pub mod actors;

use rest_api_types::errors::ApiError;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::path_validation::NormalisedPaths;

#[derive(Debug, Error)]
pub enum GitHubUrlError {
    #[error("Invalid GitHub URL format: {0}")]
    InvalidFormat(String),
    #[error("Missing branch in URL")]
    MissingBranch,
    #[error("Missing file path in URL")]
    MissingFilePath,
}

#[derive(Debug, Clone)]
pub struct GitHubRepoInfo {
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub file_path: PathBuf,
    pub raw_url: String,
}

impl GitHubRepoInfo {
    pub fn project_id(&self) -> String {
        format!("github.com/{}/{}", self.owner, self.repo)
    }
}

/// Parse a GitHub URL (blob or raw format) and extract repo information
/// Accepts both:
/// - https://github.com/owner/repo/blob/branch/path/to/file.json
/// - https://raw.githubusercontent.com/owner/repo/branch/path/to/file.json
/// - http://localhost:port/owner/repo/branch/path/to/file.json (for testing)
pub fn parse_github_url(url: &str) -> Result<GitHubRepoInfo, GitHubUrlError> {
    let url = url::Url::parse(url).map_err(|e| GitHubUrlError::InvalidFormat(e.to_string()))?;

    let host = url.host_str().unwrap_or("");
    if ![
        "github.com",
        "raw.githubusercontent.com",
        "localhost",
        "127.0.0.1",
    ]
    .contains(&host)
    {
        return Err(GitHubUrlError::InvalidFormat(
            "URL must be from github.com, raw.githubusercontent.com, or localhost".to_string(),
        ));
    }

    let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();

    let (owner, repo, branch, file_path, raw_url) = match url.host_str() {
        Some("github.com") => {
            if segments.len() < 5 {
                return Err(GitHubUrlError::InvalidFormat(
                    "URL must have at least 5 path segments".to_string(),
                ));
            }
            let owner = segments[0].to_string();
            let repo = segments[1].to_string();
            if segments[2] != "blob" {
                return Err(GitHubUrlError::InvalidFormat(
                    "GitHub URL must contain /blob/".to_string(),
                ));
            }
            let branch = segments[3].to_string();
            let file_path = segments[4..].join("/");
            let raw_url = format!(
                "https://raw.githubusercontent.com/{}/{}/{}/{}",
                owner, repo, branch, file_path
            );
            (owner, repo, branch, PathBuf::from(&file_path), raw_url)
        }
        Some("raw.githubusercontent.com") => {
            if segments.len() < 4 {
                return Err(GitHubUrlError::InvalidFormat(
                    "URL must have at least 4 path segments".to_string(),
                ));
            }
            let owner = segments[0].to_string();
            let repo = segments[1].to_string();
            let branch = segments[2].to_string();
            let file_path = segments[3..].join("/");
            let raw_url = url.to_string();
            (owner, repo, branch, PathBuf::from(&file_path), raw_url)
        }
        // Note this annotation is commented out because it works for unit tests, but not for integration tests!
        //#[cfg(test)]
        Some("localhost") | Some("127.0.0.1") => {
            if segments.len() < 4 {
                return Err(GitHubUrlError::InvalidFormat(
                    "URL must have at least 4 path segments".to_string(),
                ));
            }
            let owner = segments[0].to_string();
            let repo = segments[1].to_string();
            let branch = segments[2].to_string();
            let file_path = segments[3..].join("/");
            let raw_url = url.to_string();
            (owner, repo, branch, PathBuf::from(&file_path), raw_url)
        }
        _ => {
            return Err(GitHubUrlError::InvalidFormat(
                "Unsupported GitHub URL format".to_string(),
            ));
        }
    };

    if branch.is_empty() {
        return Err(GitHubUrlError::MissingBranch);
    }

    if file_path.as_os_str().is_empty() {
        return Err(GitHubUrlError::MissingFilePath);
    }

    Ok(GitHubRepoInfo {
        owner,
        repo,
        branch,
        file_path,
        raw_url,
    })
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
        let url = "https://github.com/owner/repo/blob/main/asfaload.initial_signers.json";
        let result = parse_github_url(url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(
            result.file_path,
            PathBuf::from("asfaload.initial_signers.json")
        );
        assert_eq!(
            result.raw_url,
            "https://raw.githubusercontent.com/owner/repo/main/asfaload.initial_signers.json"
        );
    }

    #[test]
    fn test_parse_github_raw_url() {
        let url = "https://raw.githubusercontent.com/owner/repo/develop/path/to/file.json";
        let result = parse_github_url(url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "develop");
        assert_eq!(result.file_path, PathBuf::from("path/to/file.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    fn test_parse_invalid_domain() {
        let url = "https://gitlab.com/owner/repo/blob/main/file.json";
        let result = parse_github_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_blob_segment() {
        let url = "https://github.com/owner/repo/main/file.json";
        let result = parse_github_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_branch() {
        let url = "https://raw.githubusercontent.com/owner/repo/file.json";
        let result = parse_github_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_localhost_url() {
        let url = "http://localhost:8080/owner/repo/main/signers.json";
        let result = parse_github_url(url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    fn test_parse_127_0_0_1_url() {
        let url = "http://127.0.0.1:8080/owner/repo/main/signers.json";
        let result = parse_github_url(url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    fn test_parse_localhost_without_port() {
        let url = "http://localhost/owner/repo/main/signers.json";
        let result = parse_github_url(url).unwrap();
        assert_eq!(result.owner, "owner");
        assert_eq!(result.repo, "repo");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("signers.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    fn test_parse_127_0_0_1_without_port() {
        let url = "http://127.0.0.1/owner/repo/main/signers.json";
        let result = parse_github_url(url).unwrap();
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
}
