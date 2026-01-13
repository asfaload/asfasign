use rest_api_types::errors::ApiError;
use std::path::{Path, PathBuf};
use url::Url;

use crate::{
    file_auth::forges_types::{ForgeTrait, ForgeUrlError},
    path_validation::NormalisedPaths,
};

#[derive(Debug, Clone)]
pub struct GitHubRepoInfo {
    owner: String,
    repo: String,
    branch: String,
    file_path: PathBuf,
    raw_url: Url,
}

#[cfg(not(feature = "test-utils"))]
pub const GITHUB_HOSTS: &[&str] = &["github.com", "raw.githubusercontent.com"];

#[cfg(feature = "test-utils")]
pub const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "localhost",
    "127.0.0.1",
];
impl ForgeTrait for GitHubRepoInfo {
    /// Parse a GitHub URL (blob or raw format) and extract repo information
    /// Accepts both:
    /// - https://github.com/owner/repo/blob/branch/path/to/file.json
    /// - https://raw.githubusercontent.com/owner/repo/branch/path/to/file.json
    /// - http://localhost:port/owner/repo/branch/path/to/file.json (for testing)
    fn new(url: &url::Url) -> Result<GitHubRepoInfo, ForgeUrlError> {
        let host = url.host_str().unwrap_or("");

        if !GITHUB_HOSTS.contains(&host) {
            return Err(ForgeUrlError::InvalidFormat(format!(
                "URL must be one of {}",
                GITHUB_HOSTS.join(","),
            )));
        }

        let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();

        let (owner, repo, branch, file_path, raw_url) = match url.host_str() {
            Some("github.com") => {
                if segments.len() < 5 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 5 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                if segments[2] != "blob" {
                    return Err(ForgeUrlError::InvalidFormat(
                        "GitHub URL must contain /blob/".to_string(),
                    ));
                }
                let branch = segments[3].to_string();
                let file_path = segments[4..].join("/");
                let raw_url = url::Url::parse(
                    format!(
                        "https://raw.githubusercontent.com/{}/{}/{}/{}",
                        owner, repo, branch, file_path
                    )
                    .as_str(),
                )
                .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            Some("raw.githubusercontent.com") => {
                if segments.len() < 4 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 4 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                let branch = segments[2].to_string();
                let file_path = segments[3..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            #[cfg(feature = "test-utils")]
            Some("localhost") | Some("127.0.0.1") => {
                if segments.len() < 4 {
                    return Err(ForgeUrlError::InvalidFormat(
                        "URL must have at least 4 path segments".to_string(),
                    ));
                }
                let owner = segments[0].to_string();
                let repo = segments[1].to_string();
                let branch = segments[2].to_string();
                let file_path = segments[3..].join("/");
                let raw_url = url::Url::parse(url.as_str())
                    .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?;
                (owner, repo, branch, PathBuf::from(&file_path), raw_url)
            }
            _ => {
                return Err(ForgeUrlError::InvalidFormat(
                    "Unsupported GitHub URL format".to_string(),
                ));
            }
        };

        if branch.is_empty() {
            return Err(ForgeUrlError::MissingBranch);
        }

        if file_path.as_os_str().is_empty() {
            return Err(ForgeUrlError::MissingFilePath);
        }

        Ok(GitHubRepoInfo {
            owner,
            repo,
            branch,
            file_path,
            raw_url,
        })
    }

    fn project_id(&self) -> String {
        format!("github.com/{}/{}", self.owner, self.repo)
    }

    fn owner(&self) -> &str {
        &self.owner
    }

    fn repo(&self) -> &str {
        &self.repo
    }

    fn branch(&self) -> &str {
        &self.branch
    }

    fn file_path(&self) -> &Path {
        &self.file_path
    }

    fn raw_url(&self) -> &url::Url {
        &self.raw_url
    }
}

/// Get the project's normalised paths in the repo
pub async fn get_project_normalised_paths<P: AsRef<Path>>(
    git_repo_path: P,
    project_id_in: impl Into<String>,
) -> Result<NormalisedPaths, ApiError> {
    let project_id = project_id_in.into();
    if project_id.contains('\0') {
        return Err(ApiError::InvalidRequestBody(
            "Project ID must not contain null bytes".to_string(),
        ));
    }

    if project_id.contains('\\') {
        return Err(ApiError::InvalidRequestBody(
            "Project ID must not contain backslashes".to_string(),
        ));
    }

    let normalised_paths = NormalisedPaths::new(git_repo_path, project_id).await?;

    Ok(normalised_paths)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_parse_github_blob_url() {
        let url = url::Url::parse(
            "https://github.com/owner/repo/blob/main/asfaload.initial_signers.json",
        )
        .unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(
            result.file_path,
            PathBuf::from("asfaload.initial_signers.json")
        );
        assert_eq!(
            result.raw_url,
            url::Url::parse(
                "https://raw.githubusercontent.com/owner/repo/main/asfaload.initial_signers.json"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_github_raw_url() {
        let url = url::Url::parse(
            "https://raw.githubusercontent.com/owner/repo/develop/path/to/file.json",
        )
        .unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "develop");
        assert_eq!(result.file_path, PathBuf::from("path/to/file.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    fn test_parse_invalid_domain() {
        let url = url::Url::parse("https://gitlab.com/owner/repo/blob/main/file.json").unwrap();
        let result = GitHubRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_blob_segment() {
        let url = url::Url::parse("https://github.com/owner/repo/main/file.json").unwrap();
        let result = GitHubRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_branch() {
        let url =
            url::Url::parse("https://raw.githubusercontent.com/owner/repo/file.json").unwrap();
        let result = GitHubRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn test_parse_localhost_url() {
        let url = url::Url::parse("http://localhost:8080/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn test_parse_127_0_0_1_url() {
        let url = url::Url::parse("http://127.0.0.1:8080/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn test_parse_localhost_without_port() {
        let url = url::Url::parse("http://localhost/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn test_parse_127_0_0_1_without_port() {
        let url = url::Url::parse("http://127.0.0.1/owner/repo/main/signers.json").unwrap();
        let result = GitHubRepoInfo::new(&url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }
    #[tokio::test]
    async fn test_validate_project_id_with_null_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = get_project_normalised_paths(&git_repo_path, "github.com/user/repo\0").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("null bytes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }
    }

    #[tokio::test]
    async fn test_validate_project_id_with_backslashes() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = get_project_normalised_paths(&git_repo_path, "github.com\\user\\repo").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("backslashes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }
    }

    #[tokio::test]
    async fn test_validate_project_id_valid() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = get_project_normalised_paths(&git_repo_path, "github.com/user/repo").await;
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.absolute_path().starts_with(&git_repo_path));
        assert!(path.absolute_path().ends_with("github.com/user/repo"));
    }

    #[tokio::test]
    async fn test_validate_project_id_with_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let project_id = "github.com/user/repo";
        let project_path = git_repo_path.join(project_id);
        fs::create_dir_all(&project_path).unwrap();

        let result = get_project_normalised_paths(&git_repo_path, project_id).await;
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path.absolute_path(), project_path);
    }
    #[tokio::test]
    async fn test_validate_project_id_with_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let project_id = "../../../etc/passwd";

        let result = get_project_normalised_paths(&git_repo_path, project_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidFilePath(msg) => {
                assert!(msg.contains("traversal"));
            }
            e => panic!("Expected InvalidFilePath error, got {}", e),
        }
    }
}
