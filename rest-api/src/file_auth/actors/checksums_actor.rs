use super::git_actor::{CommitFile, GitActor};
use crate::file_auth::checksum_file_registrar::ChecksumFileRegistrar;
use crate::helpers::create_empty_aggregate_signature;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use tracing::info;
use uuid::Uuid;

const ACTOR_NAME: &str = "checksums_actor";

pub struct ChecksumsActor {
    git_actor: kameo::actor::ActorRef<GitActor>,
    config: crate::config::AppConfig,
}

pub struct ProcessChecksums {
    pub request_id: String,
    pub urls: Vec<url::Url>,
}

pub struct ChecksumsResult {
    pub index_file_path: NormalisedPaths,
}

impl Actor for ChecksumsActor {
    type Args = (kameo::actor::ActorRef<GitActor>, crate::config::AppConfig);
    type Error = ApiError;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(actor = ACTOR_NAME, "Checksums actor starting");

        Ok(Self {
            git_actor: args.0,
            config: args.1,
        })
    }
}

impl Message<ProcessChecksums> for ChecksumsActor {
    type Reply = Result<ChecksumsResult, ApiError>;

    async fn handle(
        &mut self,
        msg: ProcessChecksums,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.process_checksums(msg, ctx).await
    }
}

impl ChecksumsActor {
    async fn process_checksums(
        &self,
        msg: ProcessChecksums,
        _ctx: &mut Context<Self, Result<ChecksumsResult, ApiError>>,
    ) -> Result<ChecksumsResult, ApiError> {
        info!(
            request_id = %msg.request_id,
            url_count = %msg.urls.len(),
            "Processing checksums files"
        );

        let registrar =
            ChecksumFileRegistrar::new(self.config.git_repo_path.clone(), msg.urls).await?;

        let index_file_path = registrar.create_index().await.inspect_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                actor = %ACTOR_NAME,
                error = %e,
                "Failed to create index file from checksums"
            );
        })?;

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            index_path = %index_file_path,
            "Index file written from checksums",
        );

        // Create empty aggregate signature for the index file
        let signature_file_path = create_empty_aggregate_signature(&index_file_path)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    actor = %ACTOR_NAME,
                    error = %e,
                    "Could not create empty aggregate signature for index file"
                );
                e
            })?;

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            signature_path = %signature_file_path,
            "Empty aggregate signature file created",
        );

        let commit_msg = CommitFile {
            file_paths: vec![index_file_path.clone(), signature_file_path],
            commit_message: format!(
                "Add index and signature for {}",
                index_file_path
                    .relative_path()
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ),
            request_id: Uuid::new_v4().to_string(),
        };

        self.git_actor
            .ask(commit_msg)
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Failed to commit file: {}", e)))?;

        Ok(ChecksumsResult { index_file_path })
    }
}
