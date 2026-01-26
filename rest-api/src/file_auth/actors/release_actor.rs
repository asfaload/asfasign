use super::git_actor::{CommitFile, GitActor};
use crate::file_auth::release_types::ReleaseAdder;
use crate::file_auth::releasers::ReleaseAdders;
use crate::path_validation::NormalisedPaths;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use tracing::info;
use uuid::Uuid;

const ACTOR_NAME: &str = "release_actor";
pub struct ReleaseActor {
    git_actor: kameo::actor::ActorRef<GitActor>,
    git_repo_path: std::path::PathBuf,
}

pub struct ProcessRelease {
    pub release_url: url::Url,
    pub request_id: String,
}

pub struct RegisterResult {
    pub index_file_path: NormalisedPaths,
}

impl Actor for ReleaseActor {
    type Args = (
        kameo::actor::ActorRef<GitActor>,
        Option<String>,
        std::path::PathBuf,
    );
    type Error = ApiError;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(actor = ACTOR_NAME, "Release actor starting");

        Ok(Self {
            git_actor: args.0,
            git_repo_path: args.2,
        })
    }
}

impl Message<ProcessRelease> for ReleaseActor {
    type Reply = Result<RegisterResult, ApiError>;

    async fn handle(
        &mut self,
        msg: ProcessRelease,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.process_release(msg, ctx).await
    }
}

impl ReleaseActor {
    async fn process_release(
        &self,
        msg: ProcessRelease,
        _ctx: &mut Context<Self, Result<RegisterResult, ApiError>>,
    ) -> Result<RegisterResult, ApiError> {
        info!(
            request_id = %msg.request_id,
            url = %msg.release_url,
            "Processing release"
        );

        let adder: crate::file_auth::releasers::ReleaseAdders =
            ReleaseAdders::new(&msg.release_url, self.git_repo_path.clone())
                .await
                .map_err(|e| {
                    tracing::error!(
                        actor = %ACTOR_NAME,
                        error = %e,
                        "Failed to initialise ReleaseAdders"
                    );
                    match e {
                        crate::file_auth::release_types::ReleaseUrlError::UnsupportedPlatform(
                            platform,
                        ) => ApiError::UnsupportedReleasePlatform(platform),
                        crate::file_auth::release_types::ReleaseUrlError::InvalidFormat(msg) => {
                            ApiError::InvalidReleaseUrl(msg)
                        }
                        crate::file_auth::release_types::ReleaseUrlError::MissingTag => {
                            ApiError::InvalidReleaseUrl("Missing tag in release URL".to_string())
                        }
                        crate::file_auth::release_types::ReleaseUrlError::MissingComponent(msg) => {
                            ApiError::InvalidReleaseUrl(msg)
                        }
                    }
                })?;

        let release_info: &dyn crate::file_auth::release_types::ReleaseInfo = adder.release_info();

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            owner = %release_info.owner(),
            repo = %release_info.repo(),
            tag = %release_info.tag(),
            release_path = %release_info.release_path().relative_path().display(),
            "Extracted release info"
        );

        let index_file_path = adder.write_index().await.map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                actor = %ACTOR_NAME,
                error = %e,
                "Could not write index file"
            );
            e
        })?;
        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            index_path = %index_file_path,
            "Index file written",
        );

        let commit_msg = CommitFile {
            file_paths: vec![index_file_path.clone()],
            commit_message: format!(
                "Add index for {}/{}/{}",
                release_info.owner(),
                release_info.repo(),
                release_info.tag()
            ),
            request_id: Uuid::new_v4().to_string(),
        };

        self.git_actor
            .ask(commit_msg)
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Failed to commit file: {}", e)))?;

        Ok(RegisterResult { index_file_path })
    }
}
