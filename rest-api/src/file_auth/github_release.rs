use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{ReleaseAdder, ReleaseInfo};
use crate::path_validation::NormalisedPaths;
use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE};
use octocrab::models::repos::Release;
use rest_api_types::errors::ApiError;
use rest_api_types::github_helpers::validate_github_url;
use serde_json::json;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::info;

pub struct GithubReleaseAdder {
    release_url: url::Url,
    git_repo_path: PathBuf,
    client: octocrab::Octocrab,
    release_info: GithubReleaseInfo,
}

#[derive(Debug)]
pub struct GithubReleaseInfo {
    pub host: String,
    pub owner: String,
    pub repo: String,
    pub tag: String,
    pub release_path: NormalisedPaths,
}

impl ReleaseInfo for GithubReleaseInfo {
    fn host(&self) -> &str {
        &self.host
    }

    fn owner(&self) -> &str {
        &self.owner
    }

    fn repo(&self) -> &str {
        &self.repo
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn release_path(&self) -> &NormalisedPaths {
        &self.release_path
    }
}

struct ReleaseAssetInfo {
    name: String,
    download_url: String,
    size: i64,
}

impl ReleaseAdder for GithubReleaseAdder {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
    ) -> Result<Self, crate::file_auth::release_types::ReleaseUrlError>
    where
        Self: Sized,
    {
        let client = octocrab::Octocrab::default();
        let release_info = parse_release_url(release_url, &git_repo_path)
            .await
            .map_err(|e| {
                crate::file_auth::release_types::ReleaseUrlError::InvalidFormat(e.to_string())
            })?;

        Ok(Self {
            release_url: release_url.clone(),
            git_repo_path,
            client,
            release_info,
        })
    }

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
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    format!("Failed to fetch release: {}", e),
                )
            })?;

        let assets = self.extract_assets(&release);

        if assets.is_empty() {
            return Err(ApiError::ReleaseApiError(
                "GitHub".to_string(),
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
            "Successfully created index file at {}",
            full_index_path.relative_path().display()
        );

        Ok(full_index_path)
    }

    fn release_info(&self) -> &dyn ReleaseInfo {
        &self.release_info
    }
}

impl GithubReleaseAdder {
    pub fn release_info_concrete(&self) -> &GithubReleaseInfo {
        &self.release_info
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

impl std::fmt::Debug for GithubReleaseAdder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubReleaseAdder")
            .field("release_url", &self.release_url)
            .field("git_repo_path", &self.git_repo_path)
            .field("release_info", &self.release_info)
            .finish()
    }
}

pub async fn parse_release_url(
    url: &url::Url,
    git_repo: &Path,
) -> Result<GithubReleaseInfo, ApiError> {
    let (host, owner, repo, tag) = validate_github_url(url)?;
    let url_path = format!("{}/{}", host, url.path());
    let release_path =
        NormalisedPaths::new(git_repo.to_path_buf(), PathBuf::from(&url_path)).await?;

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
        let result = parse_release_url(&url, &git_repo).await.unwrap();

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
        let result = parse_release_url(&url, &git_repo).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_release_url_empty_values() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = temp_dir.path().to_path_buf();
        let url = url::Url::parse("https://github.com/asfaload/releases/tag/").unwrap();
        let result = parse_release_url(&url, &git_repo).await;

        assert!(result.is_err());
    }
}
