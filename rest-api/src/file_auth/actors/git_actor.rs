use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use std::fs;
use std::path::{Path, PathBuf};

use crate::path_validation::NormalisedPaths;
use git2::{Repository, Signature};

#[derive(Debug, Clone)]
pub struct CommitFile {
    // File path is relative to the git root
    pub file_paths: Vec<NormalisedPaths>,
    pub commit_message: String,
    pub request_id: String,
}

const ACTOR_NAME: &str = "git-actor";
const GIT_USER_EMAIL: &str = "git-actor@rest-api.asfaload.com";

pub struct GitActor {
    repo_path: PathBuf,
}
fn add_path_recursively<P1: AsRef<Path>, P2: AsRef<Path>>(
    index: &mut git2::Index,
    repo_workdir_in: P1,
    target_path_in: P2,
) -> Result<(), git2::Error> {
    let repo_workdir = repo_workdir_in.as_ref();
    let mut paths_to_visit = vec![target_path_in.as_ref().to_path_buf()];

    while let Some(current_path) = paths_to_visit.pop() {
        let metadata = match fs::symlink_metadata(&current_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    tracing::error!(
                        file_path = %current_path.display(),
                        "Encountered symlink in git repo!"
                    );
                    return Err(git2::Error::from_str(&format!(
                        "Encountered a symlink!{}",
                        current_path.display()
                    )));
                }
                meta
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // This can happen with broken symlinks, for example. We just skip them.
                continue;
            }
            Err(e) => {
                return Err(git2::Error::from_str(&format!(
                    "Failed to read path {:?}: {}",
                    current_path, e
                )));
            }
        };

        if metadata.is_file() {
            let rel_path = current_path
                .strip_prefix(repo_workdir)
                .map_err(|_| git2::Error::from_str("Target path is outside repository"))?;
            index.add_path(rel_path)?;
        } else if metadata.is_dir() {
            if let Some(name) = current_path.file_name()
                && (name == ".git" || name == ".app_cache")
            {
                tracing::debug!("Skipping ignored directory: {}", current_path.display());
                continue;
            }
            for entry in fs::read_dir(&current_path).map_err(|e| {
                git2::Error::from_str(&format!(
                    "Failed to read directory {:?}: {}",
                    current_path, e
                ))
            })? {
                let entry =
                    entry.map_err(|e| git2::Error::from_str(&format!("Dir entry error: {}", e)))?;
                paths_to_visit.push(entry.path());
            }
        }
        // Symlinks and other file types are implicitly ignored.
    }
    Ok(())
}
impl GitActor {
    pub fn new(repo_path: PathBuf) -> Self {
        tracing::info!(repo_path = %repo_path.display(), "GitActor created");
        Self { repo_path }
    }
    async fn commit_files(
        &self,
        file_paths: Vec<NormalisedPaths>,
        commit_message: &str,
        request_id: &str,
    ) -> Result<(), ApiError> {
        for path in &file_paths {
            if path.base_dir() != self.repo_path {
                return Err(ApiError::InvalidFilePath(format!(
                    "File's base_dir ({}) != actor's git dir ({})",
                    path.base_dir().to_string_lossy(),
                    self.repo_path.to_string_lossy()
                )));
            }
        }

        tracing::info!(
            request_id = %request_id,
            file_paths = %file_paths.iter()
                .map(|p| p.relative_path().display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            commit_message,
            "Attempting to commit files"
        );

        let repo_path = self.repo_path.clone();
        let file_paths: Vec<PathBuf> = file_paths.iter().map(|p| p.absolute_path()).collect();
        let commit_message = commit_message.to_string();
        let request_id = request_id.to_string();

        tokio::task::spawn_blocking(move || {
            // Open the repository
            let repo = Repository::open(&repo_path)?;

            // Create a signature for the commit
            let signature = Signature::now(ACTOR_NAME, GIT_USER_EMAIL)?;

            // Add all files to the index
            let mut index = repo.index()?;
            for file_path in &file_paths {
                add_path_recursively(&mut index, &repo_path, file_path)?;
            }

            // Get the tree from the index
            let tree_oid = index.write_tree()?;

            // Write the index to disk so the files remain tracked
            index.write()?;

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

            tracing::info!(request_id = %request_id, file_paths = ?file_paths, "Successfully committed files");
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
            file_paths = %msg.file_paths.iter().map(|p| p.relative_path().display().to_string()).collect::<Vec<_>>().join(", "),
            commit_message = %msg.commit_message,
            "GitActor received commit request"
        );

        self.commit_files(msg.file_paths, &msg.commit_message, &msg.request_id)
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

    #[test]
    fn test_add_path_recursively_rejects_symlink() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path)?;
        let mut index = repo.index()?;

        let target_file = repo_path.join("target.txt");
        fs::write(&target_file, "target content")?;

        let symlink_path = repo_path.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target.txt", &symlink_path)?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_file("target.txt", &symlink_path)?;

        let result = add_path_recursively(&mut index, repo_path, &symlink_path);

        match result {
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("symlink"),
                    "Error message should mention symlink: {}",
                    error_msg
                );
                assert!(
                    error_msg.contains("link.txt"),
                    "Error message should mention path: {}",
                    error_msg
                );
            }
            Ok(_) => panic!("Expected error when encountering symlink but got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_add_path_recursively_skips_git_directory() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path)?;
        let mut index = repo.index()?;

        // Create some test files
        let test_file = repo_path.join("test.txt");
        fs::write(&test_file, "test content")?;

        let test_dir = repo_path.join("subdir");
        fs::create_dir(&test_dir)?;
        let test_file_in_dir = test_dir.join("nested.txt");
        fs::write(&test_file_in_dir, "nested content")?;

        // Add the repo root recursively
        let result = add_path_recursively(&mut index, repo_path, repo_path);
        assert!(result.is_ok(), "Should successfully add repo root");

        // Verify no files from .git directory were added
        for entry in index.iter() {
            let path_str = String::from_utf8_lossy(&entry.path);
            assert!(
                !path_str.starts_with(".git/"),
                "File from .git directory found in index: {}",
                path_str
            );
        }

        Ok(())
    }

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
            .commit_files(
                vec![normalised_paths],
                "Test commit message",
                "test-request-id",
            )
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
            .commit_files(
                vec![normalised_paths],
                "Test commit message",
                "test-request-id",
            )
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
            file_paths: vec![normalised_paths],
            commit_message: "Test message handling".to_string(),
            request_id: "test-request-id".to_string(),
        };

        // Test message creation and that Message trait is properly implemented
        // Note: Since Context::mock() doesn't exist, we'll test the components separately
        assert_eq!(commit_msg.commit_message, "Test message handling");
        assert_eq!(
            commit_msg.file_paths[0].relative_path(),
            PathBuf::from("test_file.txt")
        );

        // Test that the commit_file method works (which is what the handle method calls)
        let result = git_actor
            .commit_files(
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
            .commit_files(
                vec![normalised_paths],
                "Test commit message",
                "test-request-id",
            )
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

    #[tokio::test]
    async fn test_git_actor_mismatched_base_directory_multiple_files() -> Result<()> {
        let temp_dir1 = TempDir::new().expect("Failed to create first temp directory");
        let temp_dir2 = TempDir::new().expect("Failed to create second temp directory");

        let git_actor = GitActor::new(temp_dir1.path().to_path_buf());

        // Create test files in second directory
        let test_file_path1 = PathBuf::from("test_file1.txt");
        let full_test_file_path1 = temp_dir2.path().join(&test_file_path1);
        let mut test_file1 = File::create(&full_test_file_path1).await.unwrap();
        test_file1.write_all(b"Test content 1").await.unwrap();
        test_file1.flush().await.unwrap();

        let test_file_path2 = PathBuf::from("test_file2.txt");
        let full_test_file_path2 = temp_dir2.path().join(&test_file_path2);
        let mut test_file2 = File::create(&full_test_file_path2).await.unwrap();
        test_file2.write_all(b"Test content 2").await.unwrap();
        test_file2.flush().await.unwrap();

        // Create NormalisedPaths for both files
        let normalised_paths1 = NormalisedPaths::new(temp_dir2.path(), test_file_path1).await?;
        let normalised_paths2 = NormalisedPaths::new(temp_dir2.path(), test_file_path2).await?;

        // Try to commit multiple files with wrong base_dir
        let result = git_actor
            .commit_files(
                vec![normalised_paths1, normalised_paths2],
                "Test commit message",
                "test-request-id",
            )
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
    async fn test_git_actor_successful_commit_multiple_files() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path = temp_dir.path();

        let repo = initialise_git_actor_repo(repo_path)?;
        let git_actor = GitActor::new(repo_path.to_path_buf());

        // Create multiple test files
        let test_file_path1 = PathBuf::from("test_file1.txt");
        let full_test_file_path1 = repo_path.join(&test_file_path1);
        let mut test_file1 = File::create(&full_test_file_path1).await.unwrap();
        test_file1.write_all(b"Test content 1").await.unwrap();
        test_file1.flush().await.unwrap();

        let test_file_path2 = PathBuf::from("test_file2.txt");
        let full_test_file_path2 = repo_path.join(&test_file_path2);
        let mut test_file2 = File::create(&full_test_file_path2).await.unwrap();
        test_file2.write_all(b"Test content 2").await.unwrap();
        test_file2.flush().await.unwrap();

        let test_file_path3 = PathBuf::from("subdir/test_file3.txt");
        let full_test_file_path3 = repo_path.join(&test_file_path3);
        tokio::fs::create_dir_all(full_test_file_path3.parent().unwrap())
            .await
            .unwrap();
        let mut test_file3 = File::create(&full_test_file_path3).await.unwrap();
        test_file3.write_all(b"Test content 3").await.unwrap();
        test_file3.flush().await.unwrap();

        let normalised_paths1 = NormalisedPaths::new(repo_path, test_file_path1).await?;
        let normalised_paths2 = NormalisedPaths::new(repo_path, test_file_path2).await?;
        let normalised_paths3 = NormalisedPaths::new(repo_path, test_file_path3).await?;

        // Try to commit multiple files - this should succeed
        let result = git_actor
            .commit_files(
                vec![normalised_paths1, normalised_paths2, normalised_paths3],
                "Test multi-file commit",
                "test-request-id",
            )
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
            "Should have 2 commits (initial + our multi-file commit)"
        );

        // Get the latest commit and verify its message
        let latest_commit = repo.find_commit(commits[0])?;
        assert_eq!(latest_commit.message().unwrap(), "Test multi-file commit");

        // Verify all files are tracked by git
        let tree = latest_commit.tree()?;
        assert!(tree.get_name("test_file1.txt").is_some());
        assert!(tree.get_name("test_file2.txt").is_some());
        // Check if subdir exists and contains test_file3.txt
        let subdir_entry = tree.get_name("subdir");
        assert!(subdir_entry.is_some(), "subdir not found in tree");
        if let Some(subdir_entry) = subdir_entry {
            let subdir_tree = repo.find_tree(subdir_entry.id())?;
            assert!(
                subdir_tree.get_name("test_file3.txt").is_some(),
                "test_file3.txt not found in subdir"
            );
        }

        Ok(())
    }
}
