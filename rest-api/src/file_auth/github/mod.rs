pub mod actors;

use std::path::PathBuf;
use thiserror::Error;

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

#[cfg(test)]
mod tests {
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
}
