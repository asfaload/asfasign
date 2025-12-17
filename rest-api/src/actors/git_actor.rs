use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use log::{error, info};
use rest_api_types::errors::ApiError;
use std::path::PathBuf;
use std::process::Command;

use crate::path_validation::NormalisedPaths;

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
            return Err(ApiError::GitOperationFailed(format!(
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
            // Add the file
            let output = Command::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("add")
                .arg("--")
                .arg(&file_path)
                .output()
                .map_err(|e| {
                    ApiError::ActorOperationFailed(format!("Failed to execute git add: {}", e))
                })?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Git add failed: {}", error_msg);
                return Err(ApiError::GitOperationFailed(format!(
                    "Git add failed: {}",
                    error_msg
                )));
            }

            // Commit the changes
            let output = Command::new("git")
                .arg("-C")
                .arg(&repo_path)
                .arg("commit")
                .arg("-m")
                .arg(commit_message)
                .output()
                .map_err(|e| {
                    ApiError::ActorOperationFailed(format!("Failed to execute git commit: {}", e))
                })?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Git commit failed: {}", error_msg);
                return Err(ApiError::ActorOperationFailed(format!(
                    "Git commit failed: {}",
                    error_msg
                )));
            }

            info!("Successfully committed file: {:?}", file_path);
            Ok(())
        })
        .await
        .map_err(|e| ApiError::ActorOperationFailed(format!("Task join error: {}", e)))?
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
    use rest_api_test_helpers::{init_git_repo, make_git_commit_fail};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_git_actor_commit_file_failure() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        // Create a pre-commit hook that will fail
        make_git_commit_fail(repo_path_buf.clone()).await?;

        // Create a GitActor
        let git_actor = GitActor::new(repo_path_buf.to_path_buf());

        // Create a test file
        let test_file_path = PathBuf::from("test_file.txt");
        let full_test_file_path = repo_path_buf.join(&test_file_path);
        let mut test_file = File::create(&full_test_file_path).await.unwrap();
        test_file.write_all(b"Test content").await.unwrap();
        test_file.flush().await.unwrap();

        let normalised_paths = NormalisedPaths::new(repo_path_buf, test_file_path)?;
        // Try to commit the file - this should fail due to our hook
        let result = git_actor
            .commit_file(normalised_paths, "Test commit message")
            .await;

        // Verify that the commit failed
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Git commit failed")
        );
        Ok(())
    }
}
