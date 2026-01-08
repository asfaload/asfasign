use crate::actors::git_actor::{CommitFile, GitActor};
use crate::path_validation::NormalisedPaths;
use kameo::message::Context;
use kameo::prelude::{Actor, ActorRef, Message};
use rest_api_types::errors::ApiError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WriteAndCommitFilesRequest {
    pub signers_file_path: NormalisedPaths,
    pub history_file_path: NormalisedPaths,
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
            signers_file_path = %msg.signers_file_path.absolute_path().display(),
            history_file_path = %msg.history_file_path.absolute_path().display(),
            "RepoHandler received write and commit request"
        );

        let signers_normalised = msg.signers_file_path;
        let history_normalised = msg.history_file_path;

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

        tracing::debug!(
            request_id = %msg.request_id,
            "Sent commit request for signers file"
        );

        self.git_actor.ask(history_commit_msg).await.map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                error = %e,
                "Failed to commit history file"
            );
            ApiError::ActorMessageFailed(e.to_string())
        })?;

        tracing::debug!(
            request_id = %msg.request_id,
            "Sent commit request for history file"
        );

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
}
