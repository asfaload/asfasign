use super::git_actor::{CommitFile, GitActor};
use crate::file_auth::github_release::GithubReleaseAdder;
use crate::file_auth::releases::ReleaseAdder;
use crate::path_validation::NormalisedPaths;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use tracing::info;
use uuid::Uuid;

const ACTOR_NAME: &str = "github_release_actor";
pub struct GitHubReleaseActor {
    git_actor: kameo::actor::ActorRef<GitActor>,
    octocrab: octocrab::Octocrab,
    git_repo_path: std::path::PathBuf,
}

pub struct ProcessGitHubRelease {
    pub release_url: url::Url,
    pub request_id: String,
}

pub struct RegisterResult {
    pub index_file_path: NormalisedPaths,
}

impl Actor for GitHubReleaseActor {
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
        info!(actor = ACTOR_NAME, "starting");

        let octocrab: octocrab::Octocrab = match &args.1 {
            Some(token) => octocrab::Octocrab::builder()
                .personal_token(token.clone())
                .build()?,
            None => octocrab::Octocrab::default(),
        };

        Ok(Self {
            git_actor: args.0,
            octocrab,
            git_repo_path: args.2,
        })
    }
}

impl Message<ProcessGitHubRelease> for GitHubReleaseActor {
    type Reply = Result<RegisterResult, ApiError>;

    async fn handle(
        &mut self,
        msg: ProcessGitHubRelease,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.process_release(msg, ctx).await
    }
}

impl GitHubReleaseActor {
    async fn process_release(
        &self,
        msg: ProcessGitHubRelease,
        _ctx: &mut Context<Self, Result<RegisterResult, ApiError>>,
    ) -> Result<RegisterResult, ApiError> {
        info!(
            request_id = %msg.request_id,
            url = %msg.release_url,
            "Processing GitHub release"
        );

        let adder = GithubReleaseAdder::new(
            msg.release_url,
            self.octocrab.clone(),
            self.git_repo_path.clone(),
        )
        .await?;

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            owner = %adder.release_info().owner,
            repo = %adder.release_info().repo,
            tag = %adder.release_info().tag,
            release_path = %adder.release_info().release_path.relative_path().display(),
            "Extracted release info"
        );

        let index_file_path = adder.write_index().await?;

        let commit_msg = CommitFile {
            file_paths: vec![index_file_path.clone()],
            commit_message: format!(
                "Add index for {}/{}/{}",
                adder.release_info().owner,
                adder.release_info().repo,
                adder.release_info().tag
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
