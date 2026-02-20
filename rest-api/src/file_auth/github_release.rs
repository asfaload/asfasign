use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{ReleaseAdder, ReleaseError, ReleaseInfo, ReleaseUrlError};
use crate::file_auth::releasers::ReleaseInfos;
use crate::path_validation::NormalisedPaths;
use constants::{SIGNERS_DIR, SIGNERS_FILE};
use features_lib::{AsfaloadIndex, FileChecksum, HashAlgorithm};
use octocrab::models::repos::Release;
use rest_api_types::errors::ApiError;
use rest_api_types::github_helpers::validate_github_url;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::info;

#[cfg(not(feature = "test-utils"))]
pub type GithubClient = ProductionGithubClient;
#[cfg(feature = "test-utils")]
pub type GithubClient = test_utils::MockGithubClient;

#[async_trait::async_trait]
pub trait GithubClientTrait: Send + Sync {
    async fn get_release_by_tag(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<Release, ApiError>;
}

pub struct ProductionGithubClient {
    client: octocrab::Octocrab,
}

impl ProductionGithubClient {
    pub fn new(client: octocrab::Octocrab) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl GithubClientTrait for ProductionGithubClient {
    async fn get_release_by_tag(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<Release, ApiError> {
        self.client
            .repos(owner, repo)
            .releases()
            .get_by_tag(tag)
            .await
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    format!("Failed to fetch release: {}", e),
                )
            })
    }
}

#[cfg(not(feature = "test-utils"))]
fn create_github_client(
    config: &crate::config::AppConfig,
) -> Result<ProductionGithubClient, ApiError> {
    let client = if let Some(api_key) = &config.github_api_key {
        octocrab::Octocrab::builder()
            .personal_token(api_key.clone())
            .build()
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    format!("Failed to create client with API key: {}", e),
                )
            })?
    } else {
        tracing::warn!("No GitHub API key provided, using anonymous client (rate limited)");
        octocrab::Octocrab::default()
    };
    Ok(ProductionGithubClient::new(client))
}

#[cfg(feature = "test-utils")]
fn create_github_client(
    _config: &crate::config::AppConfig,
) -> Result<test_utils::MockGithubClient, ApiError> {
    Ok(test_utils::MockGithubClient::new())
}

pub struct GithubReleaseAdder<C: GithubClientTrait> {
    release_url: url::Url,
    git_repo_path: PathBuf,
    pub client: C,
    release_info: GithubReleaseInfo,
}

#[derive(Debug, Clone)]
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
    hash: Option<FileChecksum>,
}

impl ReleaseAdder for GithubReleaseAdder<GithubClient> {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, crate::file_auth::release_types::ReleaseError>
    where
        Self: Sized,
    {
        let release_info = parse_release_url(release_url, &git_repo_path)
            .await
            .map_err(|e| ReleaseUrlError::InvalidFormat(e.to_string()))?;

        let client = create_github_client(config).map_err(|e| {
            ReleaseError::ClientError(format!("Failed to create GitHub client: {}", e))
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

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        let full_index_path = self.release_info.release_path.join(INDEX_FILE).await?;
        Ok(full_index_path)
    }
    async fn index_content(&self) -> Result<String, ApiError> {
        let release: Release = self
            .client
            .get_release_by_tag(
                &self.release_info.owner,
                &self.release_info.repo,
                &self.release_info.tag,
            )
            .await?;

        let assets = self.extract_assets(&release);

        if assets.is_empty() {
            return Err(ApiError::ReleaseApiError(
                "GitHub".to_string(),
                "No assets found in release".to_string(),
            ));
        }

        self.generate_index_json(&assets, &release)
    }

    async fn write_index(&self) -> Result<NormalisedPaths, ApiError> {
        let signers_file_path = self.signers_file_path();
        if !signers_file_path.exists() {
            return Err(ApiError::NoActiveSignersFile);
        }

        let index_content = self.index_content().await?;

        let full_index_path = self.index_path().await?;
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

    fn release_info(&self) -> ReleaseInfos {
        ReleaseInfos::Github(self.release_info.clone())
    }
}

impl<C: GithubClientTrait> GithubReleaseAdder<C> {
    pub fn release_info_concrete(&self) -> &GithubReleaseInfo {
        &self.release_info
    }

    fn extract_assets(&self, release: &Release) -> Vec<ReleaseAssetInfo> {
        release
            .assets
            .iter()
            .map(|asset| {
                let download_url = asset.browser_download_url.to_string();
                let hash = asset.digest.as_ref().and_then(|d| {
                    d.strip_prefix("sha256:").map(|hash| FileChecksum {
                        file_name: asset.name.clone(),
                        algo: HashAlgorithm::Sha256,
                        source: download_url,
                        hash: hash.to_string(),
                    })
                });
                ReleaseAssetInfo { hash }
            })
            .collect()
    }

    fn generate_index_json(
        &self,
        assets: &[ReleaseAssetInfo],
        release: &Release,
    ) -> Result<String, ApiError> {
        let published_files: Vec<FileChecksum> = assets
            .iter()
            .filter_map(|asset| asset.hash.clone())
            .collect();

        let published_on = release.published_at.or(release.created_at).ok_or_else(|| {
            ApiError::ReleaseApiError(
                "GitHub".to_string(),
                "No publication timestamp found in release".to_string(),
            )
        })?;
        let mirrored_on = chrono::Utc::now();

        let index = AsfaloadIndex {
            mirrored_on,
            published_on: published_on.to_utc(),
            version: 1,
            published_files,
        };

        serde_json::to_string_pretty(&index)
            .map_err(|e| ApiError::InternalServerError(format!("Failed to serialize index: {}", e)))
    }
}

impl<C: GithubClientTrait> std::fmt::Debug for GithubReleaseAdder<C> {
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

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    pub struct MockGithubClient {
        release_response: Option<Release>,
    }

    impl MockGithubClient {
        pub fn new() -> Self {
            let release = create_mock_release();
            Self {
                release_response: Some(release),
            }
        }

        pub fn mock_release(&mut self, release: Release) {
            self.release_response = Some(release);
        }
    }

    impl Default for MockGithubClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl GithubClientTrait for MockGithubClient {
        async fn get_release_by_tag(
            &self,
            _owner: &str,
            _repo: &str,
            _tag: &str,
        ) -> Result<Release, ApiError> {
            self.release_response.clone().ok_or_else(|| {
                ApiError::ReleaseApiError(
                    "GitHub".to_string(),
                    "No mock release configured".to_string(),
                )
            })
        }
    }

    pub fn create_mock_release() -> Release {
        let json_str = r#"{
            "id": 123,
            "node_id": "test_node_id",
            "tag_name": "v1.0.0",
            "name": "Test Release",
            "html_url": "https://github.com/testowner/testrepo/releases/tag/v1.0.0",
            "url": "https://api.github.com/repos/testowner/testrepo/releases/123",
            "assets_url": "https://api.github.com/repos/testowner/testrepo/releases/123/assets",
            "upload_url": "https://uploads.github.com/repos/testowner/testrepo/releases/123/assets{?name,label}",
            "tarball_url": "https://api.github.com/repos/testowner/testrepo/tarball/v1.0.0",
            "zipball_url": "https://api.github.com/repos/testowner/testrepo/zipball/v1.0.0",
            "author": {
                "login": "testowner",
                "id": 1,
                "node_id": "test_node_id",
                "avatar_url": "https://github.com/images/error/testowner_happy.gif",
                "gravatar_id": "",
                "url": "https://api.github.com/users/testowner",
                "html_url": "https://github.com/testowner",
                "type": "User",
                "site_admin": false,
                "name": "Test Owner",
                "email": "test@example.com",
                "patch_url": "https://github.com/testowner/testrepo/patch/v1.0.0",
                "events_url": "https://api.github.com/users/testowner/events{/privacy}",
                "followers_url": "https://api.github.com/users/testowner/followers",
                "following_url": "https://api.github.com/users/testowner/following{/other_user}",
                "gists_url": "https://api.github.com/users/testowner/gists{/gist_id}",
                "starred_url": "https://api.github.com/users/testowner/starred{/owner}{/repo}",
                "subscriptions_url": "https://api.github.com/users/testowner/subscriptions",
                "organizations_url": "https://api.github.com/users/testowner/orgs",
                "repos_url": "https://api.github.com/users/testowner/repos",
                "received_events_url": "https://api.github.com/users/testowner/received_events"
            },
            "assets": [{
                "id": 456,
                "node_id": "asset_node_id",
                "name": "test.tar.gz",
                "label": "Test Asset",
                "state": "uploaded",
                "content_type": "application/gzip",
                "size": 1024,
                "download_count": 10,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "browser_download_url": "https://github.com/testowner/testrepo/releases/download/v1.0.0/test.tar.gz",
                "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "url": "https://api.github.com/repos/testowner/testrepo/releases/assets/456",
                "uploader": {
                    "login": "testowner",
                    "id": 1,
                    "node_id": "test_node_id",
                    "avatar_url": "https://github.com/images/error/testowner_happy.gif",
                    "gravatar_id": "",
                    "url": "https://api.github.com/users/testowner",
                    "html_url": "https://github.com/testowner",
                    "type": "User",
                    "site_admin": false,
                    "name": "Test Owner",
                    "email": "test@example.com",
                    "patch_url": "https://github.com/testowner/testrepo/patch/v1.0.0",
                    "events_url": "https://api.github.com/users/testowner/events{/privacy}",
                    "followers_url": "https://api.github.com/users/testowner/followers",
                    "following_url": "https://api.github.com/users/testowner/following{/other_user}",
                    "gists_url": "https://api.github.com/users/testowner/gists{/gist_id}",
                    "starred_url": "https://api.github.com/users/testowner/starred{/owner}{/repo}",
                    "subscriptions_url": "https://api.github.com/users/testowner/subscriptions",
                    "organizations_url": "https://api.github.com/users/testowner/orgs",
                    "repos_url": "https://api.github.com/users/testowner/repos",
                    "received_events_url": "https://api.github.com/users/testowner/received_events"
                }
            }],
            "published_at": "2024-01-01T00:00:00Z",
            "created_at": "2024-01-01T00:00:00Z",
            "draft": false,
            "prerelease": false,
            "target_commitish": "main"
        }"#;
        serde_json::from_str(json_str).unwrap()
    }
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
