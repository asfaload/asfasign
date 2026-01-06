use crate::actors::git_actor::{CommitFile, GitActor};
use crate::path_validation::NormalisedPaths;
use kameo::message::Context;
use kameo::prelude::{Actor, ActorRef, Message};
use rest_api_types::errors::ApiError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WriteAndCommitFilesRequest {
    pub signers_file_path: PathBuf,
    pub history_file_path: PathBuf,
    pub git_repo_path: PathBuf,
    pub request_id: String,
}

pub struct RepoHandler {
    git_repo_path: PathBuf,
    git_actor: ActorRef<GitActor>,
}

impl RepoHandler {
    pub fn new(git_repo_path: PathBuf, git_actor: ActorRef<GitActor>) -> Self {
        tracing::info!(repo_path = %git_repo_path.display(), "RepoHandler created");
        Self {
            git_repo_path,
            git_actor,
        }
    }

    fn validate_paths_within_repo(
        &self,
        signers_file_path: &Path,
        history_file_path: &Path,
    ) -> Result<(), ApiError> {
        if !signers_file_path.starts_with(&self.git_repo_path)
            || !history_file_path.starts_with(&self.git_repo_path)
        {
            return Err(ApiError::InvalidFilePath(
                "Files must be within the git repository".to_string(),
            ));
        }
        Ok(())
    }
}

impl Actor for RepoHandler {
    type Args = (PathBuf, ActorRef<GitActor>);
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self::new(args.0, args.1))
    }
}

impl Message<WriteAndCommitFilesRequest> for RepoHandler {
    type Reply = Result<(), ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: WriteAndCommitFilesRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            signers_file_path = %msg.signers_file_path.display(),
            history_file_path = %msg.history_file_path.display(),
            "RepoHandler received write and commit request"
        );

        // Validate paths are within the git repository
        if let Err(e) =
            self.validate_paths_within_repo(&msg.signers_file_path, &msg.history_file_path)
        {
            tracing::error!(
                request_id = %msg.request_id,
                signers_file_path = %msg.signers_file_path.display(),
                history_file_path = %msg.history_file_path.display(),
                git_repo_path = %self.git_repo_path.display(),
                "Files are outside git repository"
            );
            return Err(e);
        }

        let signers_normalised =
            NormalisedPaths::new(self.git_repo_path.clone(), msg.signers_file_path.clone())
                .await
                .map_err(|e| {
                    tracing::error!(
                        request_id = %msg.request_id,
                        error = %e,
                        "Failed to normalise signers file path"
                    );
                    ApiError::InvalidFilePath("Invalid file path".to_string())
                })?;

        let history_normalised =
            NormalisedPaths::new(self.git_repo_path.clone(), msg.history_file_path.clone())
                .await
                .map_err(|e| {
                    tracing::error!(
                        request_id = %msg.request_id,
                        error = %e,
                        "Failed to normalise history file path"
                    );
                    ApiError::InvalidFilePath("Invalid file path".to_string())
                })?;

        let signers_commit_msg = CommitFile {
            file_paths: signers_normalised.clone(),
            commit_message: format!(
                "added initial signers file for {}",
                signers_normalised.relative_path().display()
            ),
            request_id: msg.request_id.clone(),
        };

        let history_commit_msg = CommitFile {
            file_paths: history_normalised.clone(),
            commit_message: format!(
                "added history file for {}",
                history_normalised.relative_path().display()
            ),
            request_id: msg.request_id.clone(),
        };

        self.git_actor.ask(signers_commit_msg).await.map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                error = %e,
                "Failed to commit signers file"
            );
            ApiError::ActorMessageFailed(e.to_string())
        })?;

        self.git_actor.ask(history_commit_msg).await.map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                error = %e,
                "Failed to commit history file"
            );
            ApiError::ActorMessageFailed(e.to_string())
        })?;

        tracing::info!(
            request_id = %msg.request_id,
            "Files committed successfully"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;

    async fn create_test_handler(repo_path: PathBuf) -> RepoHandler {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let git_actor_ref = GitActor::spawn(temp_dir.path().to_path_buf());
        RepoHandler::new(repo_path, git_actor_ref)
    }

    #[tokio::test]
    async fn test_repo_handler_validates_path_within_repo() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_path = temp.path().to_path_buf();

        let handler = create_test_handler(repo_path.clone()).await;

        // Valid path (within repo)
        let valid_path = repo_path.join("test/file.txt");
        let history_path = repo_path.join("test/history.json");

        // This should not return InvalidFilePath error
        let result = handler.validate_paths_within_repo(&valid_path, &history_path);
        assert!(result.is_ok(), "Path validation failed for valid paths");
    }

    #[tokio::test]
    async fn test_repo_handler_rejects_path_outside_repo() {
        let temp1 = tempfile::TempDir::new().unwrap();
        let temp2 = tempfile::TempDir::new().unwrap();
        let repo_path = temp1.path().to_path_buf();
        let outside_path = temp2.path().join("malicious.txt");

        let handler = create_test_handler(repo_path.clone()).await;

        let result =
            handler.validate_paths_within_repo(&outside_path, &repo_path.join("test/history.json"));

        // Should fail with InvalidFilePath
        assert!(result.is_err());
        match result.unwrap_err() {
            rest_api_types::errors::ApiError::InvalidFilePath(msg) => {
                assert!(
                    msg.contains("within the git repository") || msg.contains("must be within")
                );
            }
            _ => panic!("Expected InvalidFilePath error"),
        }
    }
}
