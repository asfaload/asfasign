use crate::constants::INDEX_FILE;
use crate::file_auth::release_types::{ReleaseAdder, ReleaseInfo, ReleaseUrlError};
use crate::path_validation::NormalisedPaths;
use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE};
use gitlab::GitlabBuilder;
use gitlab::api::{AsyncQuery, projects};
use rest_api_types::errors::ApiError;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

const MAX_FILE_SIZE_FOR_HASHING: u64 = 500 * 1024 * 1024; // 500MB

#[derive(Debug, Deserialize)]
struct GitlabReleaseLink {
    #[serde(default)]
    name: String,
    #[serde(rename = "direct_asset_url")]
    direct_asset_url: String,
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GitlabRelease {
    #[serde(default)]
    assets: Option<Vec<GitlabReleaseLink>>,
}

pub struct GitlabReleaseAdder {
    release_url: url::Url,
    git_repo_path: PathBuf,
    client: gitlab::AsyncGitlab,
    release_info: GitlabReleaseInfo,
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

#[derive(Debug)]
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
    size: u64,
    sha256_hash: Option<String>,
}

impl ReleaseAdder for GitlabReleaseAdder {
    async fn new(release_url: &url::Url, git_repo_path: PathBuf) -> Result<Self, ReleaseUrlError> {
        let (host, namespace, project, tag) = Self::validate_and_parse_url(release_url)?;

        let builder = GitlabBuilder::new(&host, "GITLAB_TOKEN");
        let client = builder.build_async().await.map_err(|e| {
            ReleaseUrlError::InvalidFormat(format!("Failed to create GitLab client: {}", e))
        })?;

        let url_path = format!("{}/-/releases/{}", host, tag);
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
        let project_id = format!(
            "{}/{}",
            self.release_info.namespace, self.release_info.project
        );

        let endpoint = projects::releases::ProjectReleaseByTag::builder()
            .project(&project_id)
            .tag(&self.release_info.tag)
            .build()
            .map_err(|e| {
                ApiError::ReleaseApiError(
                    "GitLab".to_string(),
                    format!("Failed to build query: {}", e),
                )
            })?;

        let release: GitlabRelease = endpoint.query_async(&self.client).await.map_err(|e| {
            ApiError::ReleaseApiError(
                "GitLab".to_string(),
                format!("Failed to fetch release: {}", e),
            )
        })?;

        let assets = self.extract_assets(&release)?;

        if assets.is_empty() {
            return Err(ApiError::ReleaseApiError(
                "GitLab".to_string(),
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

impl GitlabReleaseAdder {
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
                    size: link.size.unwrap_or(0),
                    sha256_hash: None,
                });
            }
        }

        Ok(assets)
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
}
