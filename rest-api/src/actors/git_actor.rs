use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use log::info;
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

use crate::path_validation::NormalisedPaths;
use git2::{Repository, Signature};

pub mod logic {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct CommitPlan {
        pub repo_path: PathBuf,
        pub relative_path: PathBuf,
        pub commit_message: String,
    }

    pub fn plan_commit(msg: CommitFile) -> Result<CommitPlan, ApiError> {
        // Pure validation logic - no I/O
        if msg.commit_message.trim().is_empty() {
            return Err(ApiError::ActorOperationFailed(
                "Commit message cannot be empty".to_string(),
            ));
        }

        // Validate file paths
        if msg.file_paths.relative_path().as_os_str().is_empty() {
            return Err(ApiError::InvalidFilePath(
                "File path cannot be empty".to_string(),
            ));
        }

        Ok(CommitPlan {
            repo_path: msg.file_paths.base_dir().clone(),
            relative_path: msg.file_paths.relative_path().clone(),
            commit_message: msg.commit_message,
        })
    }
}

pub mod effects {
    use super::logic::CommitPlan;
    use super::*;

    pub async fn execute_commit(plan: CommitPlan) -> Result<(), ApiError> {
        // All git operations here - no business logic
        let repo_path = plan.repo_path;
        let relative_path = plan.relative_path;
        let commit_message = plan.commit_message;

        tokio::task::spawn_blocking(move || {
            // Move existing git code here
            let repo = Repository::open(&repo_path)?;
            let signature = Signature::now(ACTOR_NAME, GIT_USER_EMAIL)?;
            let mut index = repo.index()?;
            index.add_path(&relative_path)?;
            let tree_oid = index.write_tree()?;
            let tree = repo.find_tree(tree_oid)?;
            let parent_commit = repo.head().and_then(|head| head.peel_to_commit()).ok();
            let parents: Vec<&git2::Commit> = parent_commit.as_ref().into_iter().collect();
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                &commit_message,
                &tree,
                &parents,
            )?;
            Ok(())
        })
        .await?
    }
}

#[derive(Debug, Clone)]
pub struct CommitFile {
    // File path is relative to the git root
    pub file_paths: NormalisedPaths,
    pub commit_message: String,
}

const ACTOR_NAME: &str = "git-actor";
const GIT_USER_EMAIL: &str = "git-actor@rest-api.asfaload.com";

pub struct GitActor {
    repo_path: PathBuf,
}

impl GitActor {
    pub fn new(repo_path: PathBuf) -> Self {
        info!("GitActor created with repo path: {:?}", repo_path);
        Self { repo_path }
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

        // Validate repo path matches actor's configured repo
        if msg.file_paths.base_dir() != self.repo_path {
            return Err(ApiError::InvalidFilePath(format!(
                "File's base_dir ({}) != actor's git dir ({})",
                msg.file_paths.base_dir().to_string_lossy(),
                self.repo_path.to_string_lossy()
            )));
        }

        // 1. Plan the operation (pure logic)
        let plan = logic::plan_commit(msg)?;

        // 2. Execute the plan (side effects)
        effects::execute_commit(plan).await
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

        // Create a test file
        let test_file_path = PathBuf::from("test_file.txt");
        let full_test_file_path = repo_path_buf.join(&test_file_path);
        let mut test_file = File::create(&full_test_file_path).await.unwrap();
        test_file.write_all(b"Test content").await.unwrap();
        test_file.flush().await.unwrap();

        let normalised_paths = NormalisedPaths::new(repo_path_buf, test_file_path).await?;

        // Create a CommitFile message
        let commit_msg = CommitFile {
            file_paths: normalised_paths,
            commit_message: "Test commit message".to_string(),
        };

        // Test the logic planning - should succeed
        let plan = logic::plan_commit(commit_msg).unwrap();

        // Test the effects execution - should fail because there's no git repo
        let result = effects::execute_commit(plan).await;

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
