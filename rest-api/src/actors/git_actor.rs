use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

use crate::path_validation::NormalisedPaths;
use git2::{Repository, Signature};

#[derive(Debug, Clone)]
pub struct CommitFile {
    // File path is relative to the git root
    pub file_paths: NormalisedPaths,
    pub commit_message: String,
    pub request_id: String,
}

const ACTOR_NAME: &str = "git-actor";
const GIT_USER_EMAIL: &str = "git-actor@rest-api.asfaload.com";

pub struct GitActor {
    repo_path: PathBuf,
}

impl GitActor {
    pub fn new(repo_path: PathBuf) -> Self {
        tracing::info!(repo_path = %repo_path.display(), "GitActor created");
        Self { repo_path }
    }
    async fn commit_file(
        &self,
        file_paths: NormalisedPaths,
        commit_message: &str,
        request_id: &str,
    ) -> Result<(), ApiError> {
        if file_paths.base_dir() != self.repo_path {
            return Err(ApiError::InvalidFilePath(format!(
                "File's base_dir ({}) != actor's git dir ({})",
                file_paths.base_dir().to_string_lossy(),
                self.repo_path.to_string_lossy()
            )));
        }
        tracing::info!(
            request_id = %request_id,
            file_path = %file_paths.absolute_path().display(),
            commit_message,
            "Attempting to commit file"
        );
        let repo_path = self.repo_path.clone();
        let file_path = file_paths.relative_path();
        let commit_message = commit_message.to_string();
        let request_id = request_id.to_string();

        tokio::task::spawn_blocking(move || {
            // Open the repository
            let repo = Repository::open(&repo_path)?;

            // Create a signature for the commit
            let signature = Signature::now(ACTOR_NAME, GIT_USER_EMAIL)?;

            // Add the file to the index
            let mut index = repo.index()?;
            index.add_path(&file_path)?;

            // Get the tree from the index
            let tree_oid = index.write_tree()?;
            let tree = repo.find_tree(tree_oid)?;

            // Try to get the current HEAD for parent commit, or use empty parents for initial commit
            let parent_commit = repo
                .head()
                .and_then(|head| head.peel_to_commit()) // Peel to commit if HEAD exists
                .ok(); // Convert Result<Commit> to Option<Commit>

            // Collect an optional reference into a Vec<&Commit> (empty if None)
            let parents: Vec<&git2::Commit> = parent_commit.as_ref().into_iter().collect();

            // Create the commit
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                &commit_message,
                &tree,
                &parents,
            )?;

            tracing::info!(request_id = %request_id, file_path = %file_path.display(), "Successfully committed file");
            Ok(())
        })
        .await?
    }
}
// GitActor implements Message<CommitFile> - the actor handles CommitFile messages
impl Message<CommitFile> for GitActor {
    type Reply = Result<(), ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: CommitFile,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            file_path = %msg.file_paths.relative_path().display(),
            commit_message = %msg.commit_message,
            "GitActor received commit request"
        );

        self.commit_file(msg.file_paths, &msg.commit_message, &msg.request_id)
            .await
    }
}

// Implement Actor trait with required associated types and methods
impl Actor for GitActor {
    type Args = PathBuf;
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(repo_path = %args.display(), "GitActor starting");
        Ok(Self::new(args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    // Helper to initialise a git repo for these tests
    fn initialise_git_actor_repo<P: AsRef<Path>>(repo_path: P) -> Result<Repository> {
        // Initialize a git repository
        let repo = Repository::init(repo_path)?;

        // Define specific scope because repo.find_tree borrows the repo. Without this scope,
        // it would be impossible to return the repo, as tree, which borrows repo, would still be
        // in scope.
        {
            // Configure git user (required for commits)
            let signature = Signature::now("Test User", "test@example.com")?;
            let tree_oid = repo.index()?.write_tree()?;
            let tree = repo.find_tree(tree_oid)?;
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "Initial commit",
                &tree,
                &[],
            )?;
        }

        Ok(repo)
    }

    #[tokio::test]
    async fn test_git_actor_mismatched_base_directory() -> Result<()> {
        let temp_dir1 = TempDir::new().expect("Failed to create first temp directory");
        let temp_dir2 = TempDir::new().expect("Failed to create second temp directory");

        // Create GitActor with first directory
        let git_actor = GitActor::new(temp_dir1.path().to_path_buf());

        // Create a test file in second directory
        let test_file_path = PathBuf::from("test_file.txt");
        let full_test_file_path = temp_dir2.path().join(&test_file_path);
        let mut test_file = File::create(&full_test_file_path).await.unwrap();
        test_file.write_all(b"Test content").await.unwrap();
        test_file.flush().await.unwrap();

        // Use second directory as base_dir (different from GitActor's repo_path)
        let normalised_paths = NormalisedPaths::new(temp_dir2.path(), test_file_path).await?;

        // Try to commit - this should fail because base_dir != repo_path
        let result = git_actor
            .commit_file(normalised_paths, "Test commit message", "test-request-id")
            .await;

        // Verify that the commit failed with InvalidFilePath
        assert!(result.is_err());
        match result {
            Err(ApiError::InvalidFilePath(e)) => {
                assert!(e.contains("File's base_dir") && e.contains("!= actor's git dir"))
            }
            Err(e) => panic!("Got unexpected error type back: {}", e),
            Ok(_) => panic!("Git operation succeeded with mismatched base directory??"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_git_actor_successful_commit() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path = temp_dir.path();

        let repo = initialise_git_actor_repo(repo_path)?;
        // Create GitActor
        let git_actor = GitActor::new(repo_path.to_path_buf());

        // Create a test file
        let test_file_path = PathBuf::from("test_file.txt");
        let full_test_file_path = repo_path.join(&test_file_path);
        let mut test_file = File::create(&full_test_file_path).await.unwrap();
        test_file.write_all(b"Test content").await.unwrap();
        test_file.flush().await.unwrap();

        let normalised_paths = NormalisedPaths::new(repo_path, test_file_path).await?;

        // Try to commit - this should succeed
        let result = git_actor
            .commit_file(normalised_paths, "Test commit message", "test-request-id")
            .await;

        // Verify that the commit succeeded
        assert!(result.is_ok(), "Commit failed: {:?}", result);

        // Verify the commit actually exists in git
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;
        let commits: Vec<git2::Oid> = revwalk.by_ref().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            commits.len(),
            2,
            "Should have 2 commits (initial + our commit)"
        );

        // Get the latest commit and verify its message
        let latest_commit = repo.find_commit(commits[0])?;
        assert_eq!(latest_commit.message().unwrap(), "Test commit message");

        Ok(())
    }

    #[tokio::test]
    async fn test_git_actor_message_handling() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path = temp_dir.path();

        let repo = initialise_git_actor_repo(repo_path)?;
        let git_actor = GitActor::new(repo_path.to_path_buf());

        // Create a test file
        let test_file_path = PathBuf::from("test_file.txt");
        let full_test_file_path = repo_path.join(&test_file_path);
        let mut test_file = File::create(&full_test_file_path).await.unwrap();
        test_file.write_all(b"Test content").await.unwrap();
        test_file.flush().await.unwrap();

        let normalised_paths = NormalisedPaths::new(repo_path, test_file_path).await?;

        // Create a CommitFile message
        let commit_msg = CommitFile {
            file_paths: normalised_paths,
            commit_message: "Test message handling".to_string(),
            request_id: "test-request-id".to_string(),
        };

        // Test message creation and that Message trait is properly implemented
        // Note: Since Context::mock() doesn't exist, we'll test the components separately
        assert_eq!(commit_msg.commit_message, "Test message handling");
        assert_eq!(
            commit_msg.file_paths.relative_path(),
            PathBuf::from("test_file.txt")
        );

        // Test that the commit_file method works (which is what the handle method calls)
        let result = git_actor
            .commit_file(
                commit_msg.file_paths,
                &commit_msg.commit_message,
                "test-request-id",
            )
            .await;

        // Verify that the commit succeeded
        assert!(result.is_ok(), "Message handling failed: {:?}", result);

        // Verify the commit actually exists in git
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;
        let commits: Vec<git2::Oid> = revwalk.by_ref().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            commits.len(),
            2,
            "Should have 2 commits (initial + our commit)"
        );

        // Get the latest commit and verify its message
        let latest_commit = repo.find_commit(commits[0])?;
        assert_eq!(latest_commit.message().unwrap(), "Test message handling");

        Ok(())
    }

    #[tokio::test]
    async fn test_git_actor_uninitialised_git_repo_gives_commit_file_failure() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        // Don't initialize git repo - this should cause the commit to fail
        // Create a GitActor
        let git_actor = GitActor::new(repo_path_buf.to_path_buf());

        // Create a test file
        let test_file_path = PathBuf::from("test_file.txt");
        let full_test_file_path = repo_path_buf.join(&test_file_path);
        let mut test_file = File::create(&full_test_file_path).await.unwrap();
        test_file.write_all(b"Test content").await.unwrap();
        test_file.flush().await.unwrap();

        let normalised_paths = NormalisedPaths::new(repo_path_buf, test_file_path).await?;
        // Try to commit the file - this should fail because there's no git repo
        let result = git_actor
            .commit_file(normalised_paths, "Test commit message", "test-request-id")
            .await;

        // Verify that the commit failed
        assert!(result.is_err());
        match result {
            Err(ApiError::GitOperationFailed(e)) => {
                assert!(e.to_string().starts_with("could not find repository at"))
            }
            Err(e) => panic!("Got unexpected error type back: {}", e),
            Ok(_) => panic!("Git operation succeeded outside a git repo??"),
        }
        Ok(())
    }
}
