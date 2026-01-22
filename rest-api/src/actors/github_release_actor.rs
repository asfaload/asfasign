use std::path::PathBuf;

use crate::actors::git_actor::{CommitFile, GitActor};
use crate::constants::INDEX_FILE;
use crate::path_validation::NormalisedPaths;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use octocrab::models::repos::Release;
use rest_api_types::errors::ApiError;
use serde_json::json;
use tokio::fs;
use tracing::info;
use uuid::Uuid;

const ACTOR_NAME: &str = "github_release_actor";
pub struct GitHubReleaseActor {
    git_actor: kameo::actor::ActorRef<GitActor>,
    octocrab: octocrab::Octocrab,
    git_repo_path: std::path::PathBuf,
}

pub struct ProcessGitHubRelease {
    pub release_url: String,
}

pub struct RegisterResult {
    pub index_file_path: String,
}

impl Actor for GitHubReleaseActor {
    type Args = (
        kameo::actor::ActorRef<GitActor>,
        Option<String>,
        std::path::PathBuf,
    );
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        info!(actor = ACTOR_NAME, "starting");

        let octocrab: octocrab::Octocrab = match &args.1 {
            Some(token) => octocrab::Octocrab::builder()
                .personal_token(token.clone())
                .build()
                .unwrap_or_else(|_| octocrab::Octocrab::default()),
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
            url = %msg.release_url,
            "Processing GitHub release"
        );

        let (owner, repo, tag) = parse_release_url(&msg.release_url)?;

        let project_path = NormalisedPaths::new(
            self.git_repo_path.clone(),
            PathBuf::from(format!("{}/{}", owner, repo)),
        )
        .await?;

        let signers_file_path = project_path
            .absolute_path()
            .join("asfaload.signers")
            .join("index.json");

        if !signers_file_path.exists() {
            return Err(ApiError::NoActiveSignersFile);
        }

        info!(
            actor = %ACTOR_NAME,
            owner = %owner,
            repo = %repo,
            tag = %tag,
            "Extracted release info"
        );

        let release: Release = self
            .octocrab
            .repos(&owner, &repo)
            .releases()
            .get_by_tag(&tag)
            .await
            .map_err(|e| ApiError::GitHubApiError(format!("Failed to fetch release: {}", e)))?;

        let assets: Vec<ReleaseAssetInfo> = release
            .assets
            .into_iter()
            .map(|asset| ReleaseAssetInfo {
                name: asset.name,
                download_url: asset.browser_download_url.to_string(),
                size: asset.size,
            })
            .collect();

        if assets.is_empty() {
            return Err(ApiError::GitHubApiError(
                "No assets found in release".to_string(),
            ));
        }

        let index_content = self.generate_index_json(&assets)?;

        let full_index_path = project_path.absolute_path().join(INDEX_FILE);

        fs::write(&full_index_path, index_content)
            .await
            .map_err(|e| ApiError::FileWriteFailed(format!("Failed to write index file: {}", e)))?;

        let normalized_paths =
            NormalisedPaths::new(self.git_repo_path.clone(), full_index_path.clone())
                .await
                .map_err(|e| {
                    ApiError::InvalidFilePath(format!("Failed to normalize path: {}", e))
                })?;

        let commit_msg = CommitFile {
            file_paths: vec![normalized_paths],
            commit_message: format!("Add index for {}/{}/{}", owner, repo, tag),
            request_id: Uuid::new_v4().to_string(),
        };

        self.git_actor
            .ask(commit_msg)
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Failed to commit file: {}", e)))?;

        info!(
            actor = %ACTOR_NAME,
            index_path = %full_index_path.display(),
            "Successfully created index file"
        );
        Ok(RegisterResult {
            index_file_path: full_index_path.to_string_lossy().to_string(),
        })
    }

    fn generate_index_json(&self, assets: &[ReleaseAssetInfo]) -> Result<String, ApiError> {
        let mut entries = json!({});

        for asset in assets {
            entries[&asset.name] = json!({
                "url": asset.download_url,
                "size": asset.size,
            });
        }

        let index = json!({
            "version": 1,
            "files": entries
        });

        serde_json::to_string_pretty(&index)
            .map_err(|e| ApiError::InternalServerError(format!("Failed to serialize index: {}", e)))
    }
}

struct ReleaseAssetInfo {
    name: String,
    download_url: String,
    size: i64,
}

fn parse_release_url(url: &str) -> Result<(String, String, String), ApiError> {
    let parts: Vec<&str> = url.split('/').collect();

    if parts.len() < 3 {
        return Err(ApiError::InvalidGitHubUrl(
            "Invalid GitHub release URL format. Expected format: owner/repo/tag".to_string(),
        ));
    }

    let owner = parts[parts.len() - 3].to_string();
    let repo = parts[parts.len() - 2].to_string();
    let tag = parts[parts.len() - 1].to_string();

    if owner.is_empty() || repo.is_empty() || tag.is_empty() {
        return Err(ApiError::InvalidGitHubUrl(
            "Invalid GitHub release URL format. Owner, repo, and tag cannot be empty".to_string(),
        ));
    }

    Ok((owner, repo, tag))
}
