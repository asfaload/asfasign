use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use log::info;
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

use crate::path_validation::NormalisedPaths;
use git2::{Repository, Signature};

#[derive(Debug, Clone)]
pub struct CommitFile {
    // File path is relative to the git root
    pub file_paths: NormalisedPaths,
    pub commit_message: String,
}

pub struct GitActor {
    repo_path: PathBuf,
}

impl GitActor {
    pub fn new(repo_path: PathBuf) -> Self {
        info!("GitActor created with repo path: {:?}", repo_path);
        Self { repo_path }
    }
    async fn commit_file(
        &self,
        file_paths: NormalisedPaths,
        commit_message: &str,
    ) -> Result<(), ApiError> {
        if file_paths.base_dir() != self.repo_path {
            return Err(ApiError::InvalidFilePath(format!(
                "File's base_dir ({}) != actor's git dir ({})",
                file_paths.base_dir().to_string_lossy(),
                self.repo_path.to_string_lossy()
            )));
        }
        info!(
            "Attempting to commit file: {:?} with message: {}",
            file_paths.absolute_path(),
            commit_message
        );
        let repo_path = self.repo_path.clone();
        let file_path = file_paths.relative_path();
        let commit_message = commit_message.to_string();

        tokio::task::spawn_blocking(move || {
            // Open the repository
            let repo = Repository::open(&repo_path)?;

            // Create a signature for the commit
            let signature = Signature::now("git-actor", "git-actor@rest-api.asfaload.com")?;

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

            info!("Successfully committed file: {:?}", file_path);
            Ok(())
        })
        .await?
    }
}
// GitActor implements Message<CommitFile> - the actor handles CommitFile messages
impl Message<CommitFile> for GitActor {
    type Reply = Result<(), ApiError>;

    async fn handle(
        &mut self,
        msg: CommitFile,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        info!(
            "GitActor received commit request for file: {:?}",
            msg.file_paths.relative_path()
        );
        info!("Commit message: {}", msg.commit_message);

        self.commit_file(msg.file_paths, &msg.commit_message).await
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
        info!("GitActor starting with repo path: {:?}", args);
        Ok(Self::new(args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

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
            .commit_file(normalised_paths, "Test commit message")
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
