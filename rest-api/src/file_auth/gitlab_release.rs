use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{ReleaseAdder, ReleaseError, ReleaseInfo, ReleaseUrlError};
use crate::file_auth::releasers::ReleaseInfos;
use crate::path_validation::NormalisedPaths;
use constants::{SIGNERS_DIR, SIGNERS_FILE};
use features_lib::{AsfaloadIndex, FileChecksum, HashAlgorithm};
use futures_util::StreamExt;
use gitlab::GitlabBuilder;
use gitlab::api::{AsyncQuery, projects};
use rest_api_types::errors::ApiError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

#[cfg(not(feature = "test-utils"))]
pub type GitLabClient = ProductionGitLabClient;
#[cfg(not(feature = "test-utils"))]
async fn get_client(host: String, token: String) -> Result<GitLabClient, ApiError> {
    ProductionGitLabClient::new(host.as_str(), token.as_str()).await
}
#[cfg(feature = "test-utils")]
pub type GitLabClient = MockGitLabClient;

#[cfg(feature = "test-utils")]
async fn get_client(_host: String, _token: String) -> Result<GitLabClient, ApiError> {
    Ok(GitLabClient::new())
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitlabReleaseLink {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "direct_asset_url")]
    pub direct_asset_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitlabRelease {
    #[serde(default)]
    pub assets: Option<Vec<GitlabReleaseLink>>,
}

#[async_trait::async_trait]
pub trait GitLabClientTrait: Send + Sync {
    async fn query_release(
        &self,
        namespace: &str,
        project: &str,
        tag: &str,
    ) -> Result<GitlabRelease, ApiError>;
}

pub struct ProductionGitLabClient {
    inner: gitlab::AsyncGitlab,
}

impl ProductionGitLabClient {
    pub async fn new(host: &str, token: &str) -> Result<Self, ApiError> {
        let builder = GitlabBuilder::new(host, token);
        let inner = builder.build_async().await.map_err(|e| {
            ApiError::ReleaseApiError(
                "GitLab".to_string(),
                format!("Failed to create client: {}", e),
            )
        })?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl GitLabClientTrait for ProductionGitLabClient {
    async fn query_release(
        &self,
        namespace: &str,
        project: &str,
        tag: &str,
    ) -> Result<GitlabRelease, ApiError> {
        let project_id = format!("{}/{}", namespace, project);
        let endpoint = projects::releases::ProjectReleaseByTag::builder()
            .project(&project_id)
            .tag(tag)
            .build()
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitLab".to_string(),
                    format!("Failed to build query: {}", e),
                )
            })?;

        endpoint.query_async(&self.inner).await.map_err(|e| {
            ApiError::ReleaseApiError(
                "GitLab".to_string(),
                format!("Failed to fetch release: {}", e),
            )
        })
    }
}

const MAX_FILE_SIZE_FOR_HASHING: u64 = 500 * 1024 * 1024; // 500MB

pub struct GitlabReleaseAdder {
    release_url: url::Url,
    git_repo_path: PathBuf,
    client: GitLabClient,
    release_info: GitlabReleaseInfo,
    reqwest_client: reqwest::Client,
}

impl std::fmt::Debug for GitlabReleaseAdder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitlabReleaseAdder")
            .field("release_url", &self.release_url)
            .field("git_repo_path", &self.git_repo_path)
            .field("release_info", &self.release_info)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct GitlabReleaseInfo {
    pub host: String,
    pub namespace: String,
    pub project: String,
    pub tag: String,
    pub release_path: NormalisedPaths,
}

impl ReleaseInfo for GitlabReleaseInfo {
    fn host(&self) -> &str {
        &self.host
    }

    fn owner(&self) -> &str {
        &self.namespace
    }

    fn repo(&self) -> &str {
        &self.project
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
    hash: Option<FileChecksum>,
}

impl ReleaseAdder for GitlabReleaseAdder {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError>
    where
        Self: Sized,
    {
        let (host, namespace, project, tag) = Self::validate_and_parse_url(release_url)?;

        let token = config.gitlab_api_key.clone().ok_or_else(|| {
            tracing::error!("GitLab API key required but not configured");
            ReleaseError::ClientError("GitLab API key required but not configured".to_string())
        })?;

        let client = get_client(host.clone(), token).await.map_err(|e| {
            tracing::error!(
            error = %e,
            "could not get gitlab client");
            ReleaseError::ClientError(e.to_string())
        })?;

        let url_path = path_on_disk(&host, release_url.path());
        let release_path = NormalisedPaths::new(git_repo_path.clone(), PathBuf::from(&url_path))
            .await
            .map_err(|e| {
                ReleaseUrlError::InvalidFormat(format!("Failed to create release path: {}", e))
            })?;

        let release_info = GitlabReleaseInfo {
            host,
            namespace,
            project,
            tag,
            release_path,
        };

        let reqwest_client = reqwest::Client::new();

        Ok(GitlabReleaseAdder {
            release_url: release_url.clone(),
            git_repo_path,
            client,
            release_info,
            reqwest_client,
        })
    }

    fn signers_file_path(&self) -> PathBuf {
        self.git_repo_path
            .join(&self.release_info.host)
            .join(&self.release_info.namespace)
            .join(&self.release_info.project)
            .join(SIGNERS_DIR)
            .join(SIGNERS_FILE)
    }

    async fn index_content(&self) -> Result<String, ApiError> {
        let release = self
            .client
            .query_release(
                &self.release_info.namespace,
                &self.release_info.project,
                &self.release_info.tag,
            )
            .await?;

        let mut assets = self.extract_assets(&release)?;

        if assets.is_empty() {
            return Err(ApiError::ReleaseApiError(
                "GitLab".to_string(),
                "No assets found in release".to_string(),
            ));
        }

        for asset in &mut assets {
            let hash = self
                .download_and_hash_file(&asset.download_url, MAX_FILE_SIZE_FOR_HASHING)
                .await?;
            asset.hash = Some(FileChecksum {
                file_name: asset.name.clone(),
                algo: HashAlgorithm::Sha256,
                source: asset.download_url.clone(),
                hash,
            });
        }

        self.generate_index_json(&assets)
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
        ReleaseInfos::Gitlab(self.release_info.clone())
    }

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        let full_index_path = self.release_info.release_path.join(INDEX_FILE).await?;
        Ok(full_index_path)
    }
}

fn path_on_disk(host: impl Into<String>, path: impl Into<String>) -> String {
    let path = path.into();
    // Ensure we handle both absolute and relative path correctly
    let fixed_path = path.strip_prefix('/').unwrap_or(&path);
    format!("{}/{}", host.into(), fixed_path)
}

impl GitlabReleaseAdder {
    pub async fn new_with_client(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        client: GitLabClient,
    ) -> Result<Self, ReleaseUrlError> {
        let (host, namespace, project, tag) = Self::validate_and_parse_url(release_url)?;

        let url_path = path_on_disk(&host, release_url.path());
        let release_path = NormalisedPaths::new(git_repo_path.clone(), PathBuf::from(&url_path))
            .await
            .map_err(|e| {
                ReleaseUrlError::InvalidFormat(format!("Failed to create release path: {}", e))
            })?;

        let release_info = GitlabReleaseInfo {
            host,
            namespace,
            project,
            tag,
            release_path,
        };

        Ok(Self {
            release_url: release_url.clone(),
            git_repo_path,
            client,
            release_info,
            reqwest_client: reqwest::Client::new(),
        })
    }

    fn validate_and_parse_url(
        url: &url::Url,
    ) -> Result<(String, String, String, String), ReleaseUrlError> {
        let host = url
            .host_str()
            .ok_or_else(|| ReleaseUrlError::InvalidFormat("Missing host".to_string()))?;

        let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();

        let dash_idx = segments.iter().position(|&s| s == "-").ok_or_else(|| {
            ReleaseUrlError::InvalidFormat("Invalid GitLab URL format".to_string())
        })?;

        if dash_idx < 2 {
            return Err(ReleaseUrlError::InvalidFormat(
                "GitLab URL must contain namespace and project".to_string(),
            ));
        }

        let project = segments[dash_idx - 1].to_string();
        let namespace = segments[..dash_idx - 1].join("/");

        if dash_idx + 2 >= segments.len() {
            return Err(ReleaseUrlError::MissingTag);
        }

        let action = segments[dash_idx + 1];
        if action != "releases" && action != "tags" {
            return Err(ReleaseUrlError::InvalidFormat(
                "GitLab URL must contain /-/releases/ or /-/tags/".to_string(),
            ));
        }

        let tag = segments[dash_idx + 2].to_string();

        if namespace.is_empty() || project.is_empty() || tag.is_empty() {
            return Err(ReleaseUrlError::InvalidFormat(
                "Namespace, project, and tag cannot be empty".to_string(),
            ));
        }

        Ok((host.to_string(), namespace, project, tag))
    }

    fn extract_assets(&self, release: &GitlabRelease) -> Result<Vec<ReleaseAssetInfo>, ApiError> {
        let mut assets = Vec::new();

        if let Some(release_links) = release.assets.as_ref() {
            for link in release_links {
                assets.push(ReleaseAssetInfo {
                    name: link.name.clone(),
                    download_url: link.direct_asset_url.clone(),
                    hash: None,
                });
            }
        }

        Ok(assets)
    }

    async fn download_and_hash_file(&self, url: &str, max_size: u64) -> Result<String, ApiError> {
        let response = self.reqwest_client.get(url).send().await.map_err(|e| {
            ApiError::ReleaseApiError(
                "GitLab".to_string(),
                format!("Failed to download file: {}", e),
            )
        })?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(ApiError::ReleaseApiError(
                "GitLab".to_string(),
                format!("HTTP error downloading file: {}", response.status()),
            ));
        }

        let content_length = response.content_length().ok_or_else(|| {
            ApiError::ReleaseApiError(
                "GitLab".to_string(),
                "Missing Content-Length header".to_string(),
            )
        })?;

        if content_length > max_size {
            return Err(ApiError::ReleaseApiError(
                "GitLab".to_string(),
                format!("File size {} exceeds limit {}", content_length, max_size),
            ));
        }

        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        let mut total_bytes = 0u64;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitLab".to_string(),
                    format!("Error reading download stream: {}", e),
                )
            })?;

            total_bytes += chunk.len() as u64;

            if total_bytes > max_size {
                return Err(ApiError::ReleaseApiError(
                    "GitLab".to_string(),
                    format!("File size exceeded limit during download: {}", max_size),
                ));
            }

            hasher.update(&chunk);
        }

        let hash_bytes = hasher.finalize();
        Ok(hex::encode(hash_bytes))
    }

    fn generate_index_json(&self, assets: &[ReleaseAssetInfo]) -> Result<String, ApiError> {
        let published_files: Vec<FileChecksum> = assets
            .iter()
            .map(|asset| {
                asset
                    .hash
                    .as_ref()
                    .ok_or_else(|| {
                        ApiError::InternalServerError(
                            format!("Missing hash for file: {}", asset.name).to_string(),
                        )
                    })
                    .cloned()
            })
            .collect::<Result<Vec<FileChecksum>, ApiError>>()?;

        let now = chrono::Utc::now();

        let index = AsfaloadIndex {
            mirrored_on: now,
            published_on: now,
            version: 1,
            published_files,
        };

        serde_json::to_string_pretty(&index)
            .map_err(|e| ApiError::InternalServerError(format!("Failed to serialize index: {}", e)))
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;
    use httpmock;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    pub struct MockGitLabClient {
        server: httpmock::MockServer,
        release_response: Option<GitlabRelease>,
        asset_responses: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl MockGitLabClient {
        pub fn new() -> Self {
            Self {
                server: httpmock::MockServer::start(),
                release_response: Some(create_mock_release()),
                asset_responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        pub fn mock_release(&mut self, release: GitlabRelease) {
            self.release_response = Some(release);

            let project_id = urlencoding::encode("group/project");
            let endpoint_path = format!("/api/v4/projects/{}/releases/v1.0.0", project_id);

            self.server.mock(|when, then| {
                when.method(httpmock::Method::GET)
                    .path(endpoint_path.as_str());
                then.status(200);
            });
        }

        pub fn mock_asset(&self, path: &str, content: &[u8]) {
            let content = content.to_vec();
            let asset_responses = Arc::clone(&self.asset_responses);
            asset_responses
                .lock()
                .unwrap()
                .insert(path.to_string(), content);

            self.server.mock(|when, then| {
                when.method(httpmock::Method::GET).path(path);
                then.status(200).body(
                    Arc::clone(&asset_responses)
                        .lock()
                        .unwrap()
                        .get(path)
                        .unwrap(),
                );
            });
        }

        pub fn url(&self) -> String {
            self.server.url("")
        }
    }

    pub fn create_mock_release() -> GitlabRelease {
        GitlabRelease {
            assets: Some(vec![GitlabReleaseLink {
                name: "test.tar.gz".to_string(),
                direct_asset_url: "https://gitlab.com/testnamespace/testproject/-/releases/v1.0.0/downloads/test.tar.gz".to_string(),
            }]),
        }
    }

    impl Default for MockGitLabClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl GitLabClientTrait for MockGitLabClient {
        async fn query_release(
            &self,
            _namespace: &str,
            _project: &str,
            _tag: &str,
        ) -> Result<GitlabRelease, ApiError> {
            self.release_response.clone().ok_or_else(|| {
                ApiError::ReleaseApiError(
                    "GitLab".to_string(),
                    "No mock release configured".to_string(),
                )
            })
        }
    }
}

#[cfg(feature = "test-utils")]
pub use test_utils::MockGitLabClient;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_gitlab_releases_url() {
        let url = url::Url::parse("https://gitlab.com/group/project/-/releases/v1.0.0").unwrap();
        let (host, namespace, project, tag) =
            GitlabReleaseAdder::validate_and_parse_url(&url).unwrap();

        assert_eq!(host, "gitlab.com");
        assert_eq!(namespace, "group");
        assert_eq!(project, "project");
        assert_eq!(tag, "v1.0.0");
    }

    #[test]
    fn test_parse_gitlab_tags_url() {
        let url = url::Url::parse("https://gitlab.com/group/project/-/tags/v1.0.0").unwrap();
        let (_, _, _, tag) = GitlabReleaseAdder::validate_and_parse_url(&url).unwrap();

        assert_eq!(tag, "v1.0.0");
    }

    #[test]
    fn test_parse_gitlab_nested_namespace() {
        let url =
            url::Url::parse("https://gitlab.com/group/subgroup/project/-/releases/v1.0.0").unwrap();
        let (_, namespace, _, _) = GitlabReleaseAdder::validate_and_parse_url(&url).unwrap();

        assert_eq!(namespace, "group/subgroup");
    }

    #[test]
    fn test_invalid_gitlab_url_missing_separator() {
        let url = url::Url::parse("https://gitlab.com/group/project/v1.0.0").unwrap();
        let result = GitlabReleaseAdder::validate_and_parse_url(&url);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_gitlab_url_missing_tag() {
        let url = url::Url::parse("https://gitlab.com/group/project/-/releases/").unwrap();
        let result = GitlabReleaseAdder::validate_and_parse_url(&url);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_gitlab_url_empty_namespace() {
        let url = url::Url::parse("https://gitlab.com//project/-/releases/v1.0.0").unwrap();
        let result = GitlabReleaseAdder::validate_and_parse_url(&url);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_gitlab_url_empty_project() {
        let url = url::Url::parse("https://gitlab.com/group//-/releases/v1.0.0").unwrap();
        let result = GitlabReleaseAdder::validate_and_parse_url(&url);

        assert!(result.is_err());
    }

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn test_gitlab_release_hash_computation() {
        use crate::file_auth::gitlab_release::test_utils::MockGitLabClient;
        use crate::file_auth::release_types::ReleaseAdder;
        use sha2::{Digest, Sha256};
        use url::Url;

        let mut mock_client = MockGitLabClient::new();

        let release = GitlabRelease {
            assets: Some(vec![GitlabReleaseLink {
                name: "test.tar.gz".to_string(),
                direct_asset_url: format!("{}/assets/test.tar.gz", mock_client.url()),
            }]),
        };

        mock_client.mock_release(release);

        let test_content = b"mock file content for sha256 hashing";
        mock_client.mock_asset("/assets/test.tar.gz", test_content);

        let test_url = Url::parse(&format!(
            "{}/group/project/-/releases/v1.0.0",
            mock_client.url()
        ))
        .expect("Failed to parse test URL");
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");

        let adder = GitlabReleaseAdder::new_with_client(
            &test_url,
            temp_dir.path().to_path_buf(),
            mock_client,
        )
        .await
        .expect("Failed to create GitLab release adder");

        let index_content = adder
            .index_content()
            .await
            .expect("Failed to compute index content");

        let json: serde_json::Value =
            serde_json::from_str(&index_content).expect("Failed to parse index JSON");

        assert_eq!(json["version"], 1);
        assert!(json["publishedFiles"].is_array());

        let files = json["publishedFiles"].as_array().unwrap();
        assert_eq!(files.len(), 1);

        let file = &files[0];
        assert_eq!(file["fileName"], "test.tar.gz");
        assert_eq!(file["algo"], "Sha256");
        assert!(
            file["source"]
                .as_str()
                .unwrap()
                .contains("/assets/test.tar.gz")
        );

        let hash = file["hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);

        let expected_hash = hex::encode(Sha256::digest(test_content));
        assert_eq!(hash, expected_hash);
    }

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn test_download_and_hash_file_size_limit() {
        let temp_dir = tempfile::tempdir().expect("Could not create temp dir");
        let mock_client = MockGitLabClient::new();
        let large_body = vec![0u8; 1000];
        let test_url = url::Url::parse(&format!(
            "{}/group/project/-/releases/v1.0.0/",
            mock_client.url()
        ))
        .unwrap();
        let asset_url = test_url.join("asset.tgz").unwrap();
        let test_url_string = test_url.to_string();
        dbg!(&test_url_string);
        mock_client.mock_asset(asset_url.path(), &large_body);
        let adder = GitlabReleaseAdder::new_with_client(
            &test_url,
            temp_dir.path().to_path_buf(),
            mock_client,
        )
        .await
        .expect("Failed to create GitLab release adder");
        let result = adder
            .download_and_hash_file(&asset_url.to_string(), 100)
            .await;

        assert!(result.is_err());
        let e = result.unwrap_err();
        if !e.to_string().contains("exceeds limit") {
            panic!("got unexpected {}", e)
        }
    }

    #[test]
    fn test_path_on_disk_basic() {
        let result = path_on_disk("gitlab.com", "/group/project/-/releases/v1.0.0");
        assert_eq!(result, "gitlab.com/group/project/-/releases/v1.0.0");
    }

    #[test]
    fn test_path_on_disk_empty_path() {
        let result = path_on_disk("gitlab.com", "");
        assert_eq!(result, "gitlab.com/");
    }

    #[test]
    fn test_path_on_disk_nested_namespace() {
        let result = path_on_disk(
            "gitlab.com",
            "/group/subgroup1/subgroup2/project/-/releases/v1.0.0",
        );
        assert_eq!(
            result,
            "gitlab.com/group/subgroup1/subgroup2/project/-/releases/v1.0.0"
        );
    }

    #[test]
    fn test_path_on_disk_with_port() {
        let result = path_on_disk(
            "gitlab.example.com:8080",
            "/group/project/-/releases/v1.0.0",
        );
        assert_eq!(
            result,
            "gitlab.example.com:8080/group/project/-/releases/v1.0.0"
        );
    }

    #[test]
    fn test_path_on_disk_path_without_leading_slash() {
        let result = path_on_disk("gitlab.com", "group/project/-/releases/v1.0.0");
        assert_eq!(result, "gitlab.com/group/project/-/releases/v1.0.0");
    }
}
