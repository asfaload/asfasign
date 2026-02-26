use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

use crate::path_validation::NormalisedPaths;

use super::git_backend::GitBackendKind;

#[derive(Debug, Clone)]
pub struct CommitFile {
    // File path is relative to the git root
    pub file_paths: Vec<NormalisedPaths>,
    pub commit_message: String,
    pub request_id: String,
}

const ACTOR_NAME: &str = "git-actor";

pub struct GitActor {
    repo_path: PathBuf,
    backend: GitBackendKind,
}

impl GitActor {
    pub fn new(repo_path: PathBuf) -> Self {
        tracing::info!(repo_path = %repo_path.display(), "GitActor created");
        Self {
            repo_path,
            backend: GitBackendKind::Sha1,
        }
    }

    /// Create a GitActor with a specific backend kind.
    pub fn with_backend(repo_path: PathBuf, backend: GitBackendKind) -> Self {
        tracing::info!(repo_path = %repo_path.display(), backend = ?backend, "GitActor created");
        Self { repo_path, backend }
    }

    async fn commit_files(
        &self,
        file_paths: Vec<NormalisedPaths>,
        commit_message: &str,
        request_id: &str,
    ) -> Result<(), ApiError> {
        for path in &file_paths {
            if path.base_dir() != self.repo_path {
                tracing::error!(
                    actor = ACTOR_NAME,
                    path = %path,
                    path_base_dir = %path.base_dir().display(),
                    repo_path = %self.repo_path.display(),
                    "Invalid file path: base dir of path is not repo_path"
                );
                return Err(ApiError::InvalidFilePath(format!(
                    "File's base_dir ({}) != actor's git dir ({})",
                    path.base_dir().to_string_lossy(),
                    self.repo_path.to_string_lossy()
                )));
            }
        }

        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %request_id,
            file_paths = %file_paths.iter()
                .map(|p| p.relative_path().display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            commit_message,
            "Attempting to commit files"
        );

        let commit_message = commit_message.to_string();
        let request_id = request_id.to_string();
        let backend = self.backend; // Copy! No Arc needed.

        tokio::task::spawn_blocking(move || backend.commit_files(&file_paths, &commit_message))
            .await??;

        tracing::info!(request_id = %request_id, "Successfully committed files");
        Ok(())
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
    type Args = (PathBuf, GitBackendKind);
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(repo_path = %args.0.display(), backend = ?args.1, "GitActor starting");
        Ok(Self::with_backend(args.0, args.1))
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;
    use crate::file_auth::actors::git_backend::backend_kind_from_env;
    use anyhow::Result;
    use rest_api_test_helpers::{file_is_tracked_in_git, get_latest_commit, init_git_repo};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    fn run_git(repo_path: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(["-C", &repo_path.to_string_lossy()])
            .args(args)
            .output()?;
        if !output.status.success() {
            anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    // Helper to initialise a git repo with an initial empty commit
    fn initialise_git_actor_repo<P: AsRef<Path>>(repo_path: P) -> Result<()> {
        let repo_path = repo_path.as_ref();
        init_git_repo(repo_path)?;
        run_git(
            repo_path,
            &["commit", "--allow-empty", "-m", "Initial commit"],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_git_actor_mismatched_base_directory() -> Result<()> {
        let temp_dir1 = TempDir::new().expect("Failed to create first temp directory");
        let temp_dir2 = TempDir::new().expect("Failed to create second temp directory");

        // Create GitActor with first directory
        let git_actor =
            GitActor::with_backend(temp_dir1.path().to_path_buf(), backend_kind_from_env());

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

        initialise_git_actor_repo(repo_path)?;
        // Create GitActor
        let git_actor = GitActor::with_backend(repo_path.to_path_buf(), backend_kind_from_env());

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

        let latest_commit = get_latest_commit(repo_path)?;
        assert!(latest_commit.contains("Test commit message"));

        Ok(())
    }

    #[tokio::test]
    async fn test_git_actor_message_handling() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path = temp_dir.path();

        initialise_git_actor_repo(repo_path)?;
        let git_actor = GitActor::with_backend(repo_path.to_path_buf(), backend_kind_from_env());

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

        let latest_commit = get_latest_commit(repo_path)?;
        assert!(latest_commit.contains("Test message handling"));

        Ok(())
    }

    #[tokio::test]
    async fn test_git_actor_uninitialised_git_repo_gives_commit_file_failure() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        // Don't initialize git repo - this should cause the commit to fail
        // Create a GitActor
        let git_actor =
            GitActor::with_backend(repo_path_buf.to_path_buf(), backend_kind_from_env());

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
                let message = e.to_string();
                assert!(
                    message.starts_with("could not find repository at")
                        || message.contains("not a git repository")
                );
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

        let git_actor =
            GitActor::with_backend(temp_dir1.path().to_path_buf(), backend_kind_from_env());

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

        initialise_git_actor_repo(repo_path)?;
        let git_actor = GitActor::with_backend(repo_path.to_path_buf(), backend_kind_from_env());

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

        let latest_commit = get_latest_commit(repo_path)?;
        assert!(latest_commit.contains("Test multi-file commit"));
        assert!(file_is_tracked_in_git(repo_path, "test_file1.txt")?);
        assert!(file_is_tracked_in_git(repo_path, "test_file2.txt")?);
        assert!(file_is_tracked_in_git(repo_path, "subdir/test_file3.txt")?);

        Ok(())
    }
}
