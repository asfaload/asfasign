use std::path::PathBuf;

use crate::actors::git_actor::{CommitFile, GitActor};
use crate::constants::INDEX_FILE;
use crate::path_validation::NormalisedPaths;
use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE};
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
    pub release_url: url::Url,
    pub request_id: String,
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
            request_id = %msg.request_id,
            url = %msg.release_url,
            "Processing GitHub release"
        );

        let release_info = parse_release_url(&msg.release_url, self.git_repo_path.clone()).await?;

        let owner = release_info.owner.clone();
        let repo = release_info.repo.clone();
        let tag = release_info.tag.clone();
        let index_repo_path = release_info.release_path.absolute_path();

        let project_path = NormalisedPaths::new(
            self.git_repo_path.clone(),
            PathBuf::from(format!(
                "{}/{}/{}",
                &msg.release_url
                    .host_str()
                    .ok_or(ApiError::InvalidGitHubUrl(format!(
                        "Could not extract host from {}",
                        &msg.release_url
                    )))?,
                owner,
                repo
            )),
        )
        .await?;

        let signers_file_path = project_path
            .absolute_path()
            .join(SIGNERS_DIR)
            .join(SIGNERS_FILE);

        if !signers_file_path.exists() {
            return Err(ApiError::NoActiveSignersFile);
        }

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            owner = %owner,
            repo = %repo,
            tag = %tag,
            release_path = %release_info.release_path.relative_path().display(),
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

        let full_index_path = index_repo_path.join(INDEX_FILE);

        if let Some(parent) = full_index_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to create directory: {}", e))
            })?;
        }

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
            request_id = %msg.request_id,
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

struct GithubReleaseInfo {
    owner: String,
    repo: String,
    tag: String,
    release_path: NormalisedPaths,
}

fn validate_github_url(url: &url::Url) -> Result<(String, String, String, String), ApiError> {
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::InvalidGitHubUrl("Missing host".to_string()))?;

    if !host.ends_with("github.com") {
        return Err(ApiError::InvalidGitHubUrl(
            "Only github.com URLs are supported".to_string(),
        ));
    }

    let path_segments: Vec<_> = url
        .path_segments()
        .ok_or_else(|| ApiError::InvalidGitHubUrl("Invalid path".to_string()))?
        .collect();

    let releases_idx = path_segments
        .iter()
        .position(|&s| s == "releases")
        .ok_or_else(|| ApiError::InvalidGitHubUrl("Missing /releases/ in path".to_string()))?;

    if releases_idx < 2
        || releases_idx + 2 >= path_segments.len()
        || path_segments[releases_idx + 1] != "tag"
    {
        return Err(ApiError::InvalidGitHubUrl(
            "Invalid GitHub release URL structure".to_string(),
        ));
    }

    let owner = path_segments[releases_idx - 2].to_string();
    let repo = path_segments[releases_idx - 1].to_string();
    let tag = path_segments[releases_idx + 2].to_string();

    Ok((host.to_string(), owner, repo, tag))
}
async fn parse_release_url(
    url: &url::Url,
    git_repo: PathBuf,
) -> Result<GithubReleaseInfo, ApiError> {
    let (host, owner, repo, tag) = validate_github_url(url)?;
    if owner.is_empty() || repo.is_empty() || tag.is_empty() {
        return Err(ApiError::InvalidGitHubUrl(
            "Owner, repo, and tag cannot be empty".to_string(),
        ));
    }

    let url_path = format!("{}/{}", host, url.path());
    let release_path = NormalisedPaths::new(git_repo, PathBuf::from(&url_path)).await?;

    Ok(GithubReleaseInfo {
        owner,
        repo,
        tag,
        release_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_parse_release_url_full_url() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url =
            url::Url::parse("https://github.com/asfaload/asfald/releases/tag/v0.9.0").unwrap();
        let result = parse_release_url(&url, git_repo).await.unwrap();

        assert_eq!(result.owner, "asfaload");
        assert_eq!(result.repo, "asfald");
        assert_eq!(result.tag, "v0.9.0");
        assert_eq!(
            result.release_path.relative_path(),
            PathBuf::from("github.com/asfaload/asfald/releases/tag/v0.9.0")
        );
    }

    #[tokio::test]
    async fn test_parse_release_url_invalid_too_short() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/owner/repo").unwrap();
        let result = parse_release_url(&url, git_repo).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_release_url_empty_values() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/asfaload/releases/tag/").unwrap();
        let result = parse_release_url(&url, git_repo).await;

        assert!(result.is_err());
    }
}
