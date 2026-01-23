use std::path::PathBuf;

use crate::actors::git_actor::{CommitFile, GitActor};
use crate::constants::INDEX_FILE;
use crate::path_validation::NormalisedPaths;
use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE};
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use octocrab::models::repos::Release;
use rest_api_types::errors::ApiError;
use rest_api_types::github_helpers::validate_github_url;
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
    pub index_file_path: NormalisedPaths,
}

pub trait ReleaseAdder: std::fmt::Debug {
    fn signers_file_path(&self) -> PathBuf;
    async fn index_content(&self) -> Result<String, ApiError>;
    async fn write_index(&self) -> Result<NormalisedPaths, ApiError>;
}

struct GithubReleaseAdder {
    release_url: url::Url,
    git_repo_path: PathBuf,
    client: octocrab::Octocrab,
    release_info: GithubReleaseInfo,
}

impl GithubReleaseAdder {
    async fn new(
        release_url: url::Url,
        client: octocrab::Octocrab,
        git_repo_path: PathBuf,
    ) -> Result<Self, ApiError> {
        let release_info = parse_release_url(&release_url, git_repo_path.clone()).await?;

        Ok(Self {
            release_url,
            git_repo_path,
            client,
            release_info,
        })
    }

    fn extract_assets(&self, release: &Release) -> Vec<ReleaseAssetInfo> {
        release
            .assets
            .iter()
            .map(|asset| ReleaseAssetInfo {
                name: asset.name.clone(),
                download_url: asset.browser_download_url.to_string(),
                size: asset.size,
            })
            .collect()
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

impl ReleaseAdder for GithubReleaseAdder {
    fn signers_file_path(&self) -> PathBuf {
        self.git_repo_path
            .join(&self.release_info.host)
            .join(&self.release_info.owner)
            .join(&self.release_info.repo)
            .join(SIGNERS_DIR)
            .join(SIGNERS_FILE)
    }

    async fn index_content(&self) -> Result<String, ApiError> {
        let release: Release = self
            .client
            .repos(&self.release_info.owner, &self.release_info.repo)
            .releases()
            .get_by_tag(&self.release_info.tag)
            .await
            .map_err(|e| ApiError::GitHubApiError(format!("Failed to fetch release: {}", e)))?;

        let assets = self.extract_assets(&release);

        if assets.is_empty() {
            return Err(ApiError::GitHubApiError(
                "No assets found in release".to_string(),
            ));
        }

        self.generate_index_json(&assets)
    }

    async fn write_index(&self) -> Result<NormalisedPaths, ApiError> {
        let signers_file_path = self.signers_file_path();
        if !signers_file_path.exists() {
            return Err(ApiError::NoActiveSignersFile);
        }

        let index_content = self.index_content().await?;

        let full_index_path = self.release_info.release_path.join(INDEX_FILE).await?;
        if let Some(parent) = full_index_path.absolute_path().parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to create directory: {}", e))
            })?;
        }

        fs::write(&full_index_path, index_content)
            .await
            .map_err(|e| ApiError::FileWriteFailed(format!("Failed to write index file: {}", e)))?;

        info!(
            actor = %ACTOR_NAME,
            index_path = %full_index_path.relative_path().display(),
            "Successfully created index file"
        );

        Ok(full_index_path)
    }
}

impl std::fmt::Debug for GithubReleaseAdder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubReleaseAdder")
            .field("release_url", &self.release_url)
            .field("git_repo_path", &self.git_repo_path)
            .field("release_info", &self.release_info)
            .finish()
    }
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
            owner = %adder.release_info.owner,
            repo = %adder.release_info.repo,
            tag = %adder.release_info.tag,
            release_path = %adder.release_info.release_path.relative_path().display(),
            "Extracted release info"
        );

        let index_file_path = adder.write_index().await?;

        let commit_msg = CommitFile {
            file_paths: vec![index_file_path.clone()],
            commit_message: format!(
                "Add index for {}/{}/{}",
                adder.release_info.owner, adder.release_info.repo, adder.release_info.tag
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

struct ReleaseAssetInfo {
    name: String,
    download_url: String,
    size: i64,
}

#[derive(Debug)]
struct GithubReleaseInfo {
    host: String,
    owner: String,
    repo: String,
    tag: String,
    release_path: NormalisedPaths,
}

async fn parse_release_url(
    url: &url::Url,
    git_repo: PathBuf,
) -> Result<GithubReleaseInfo, ApiError> {
    let (host, owner, repo, tag) = validate_github_url(url)?;
    let url_path = format!("{}/{}", host, url.path());
    let release_path = NormalisedPaths::new(git_repo, PathBuf::from(&url_path)).await?;

    Ok(GithubReleaseInfo {
        host,
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
