use crate::file_auth::github::GITHUB_HOSTS;
use crate::file_auth::gitlab::GITLAB_HOSTS;
use crate::file_auth::{github::GitHubRepoInfo, gitlab::GitLabRepoInfo};

pub use crate::file_auth::forges_types::ForgeTrait;
pub use crate::file_auth::forges_types::ForgeUrlError;

#[derive(Debug)]
pub enum ForgeInfo {
    Github(GitHubRepoInfo),
    Gitlab(GitLabRepoInfo),
}

impl ForgeTrait for ForgeInfo {
    fn new(url: &str) -> Result<Self, crate::file_auth::forges_types::ForgeUrlError> {
        let parsed_url = url::Url::parse(url).map_err(|e| {
            crate::file_auth::forges_types::ForgeUrlError::InvalidFormat(e.to_string())
        })?;

        let host = parsed_url.host_str().unwrap_or("");

        if GITHUB_HOSTS.contains(&host) {
            Ok(Self::Github(GitHubRepoInfo::new(url)?))
        } else if GITLAB_HOSTS.contains(&host) {
            Ok(Self::Gitlab(GitLabRepoInfo::new(url)?))
        } else {
            Err(ForgeUrlError::InvalidFormat(format!(
                "Unsupported forge host: {}. Supported hosts: GitHub ({}), GitLab ({})",
                host,
                GITHUB_HOSTS.join(","),
                GITLAB_HOSTS.join(",")
            )))
        }
    }

    fn project_id(&self) -> String {
        match self {
            Self::Github(info) => info.project_id(),
            Self::Gitlab(info) => info.project_id(),
        }
    }

    fn owner(&self) -> &str {
        match self {
            Self::Github(info) => info.owner(),
            Self::Gitlab(info) => info.owner(),
        }
    }

    fn repo(&self) -> &str {
        match self {
            Self::Github(info) => info.repo(),
            Self::Gitlab(info) => info.repo(),
        }
    }

    fn branch(&self) -> &str {
        match self {
            Self::Github(info) => info.branch(),
            Self::Gitlab(info) => info.branch(),
        }
    }

    fn file_path(&self) -> &std::path::Path {
        match self {
            Self::Github(info) => info.file_path(),
            Self::Gitlab(info) => info.file_path(),
        }
    }

    fn raw_url(&self) -> &str {
        match self {
            Self::Github(info) => info.raw_url(),
            Self::Gitlab(info) => info.raw_url(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_github_blob_url() {
        let url = "https://github.com/owner/repo/blob/main/asfaload.initial_signers.json";
        let result = ForgeInfo::new(url).unwrap();

        match result {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), "owner");
                assert_eq!(info.repo(), "repo");
                assert_eq!(info.branch(), "main");
                assert_eq!(
                    info.file_path(),
                    PathBuf::from("asfaload.initial_signers.json")
                );
                assert_eq!(
                    info.raw_url(),
                    "https://raw.githubusercontent.com/owner/repo/main/asfaload.initial_signers.json"
                );
            }
            ForgeInfo::Gitlab(_) => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    fn test_parse_github_raw_url() {
        let url = "https://raw.githubusercontent.com/owner/repo/develop/path/to/file.json";
        let result = ForgeInfo::new(url).unwrap();

        match result {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), "owner");
                assert_eq!(info.repo(), "repo");
                assert_eq!(info.branch(), "develop");
                assert_eq!(info.file_path(), PathBuf::from("path/to/file.json"));
                assert_eq!(info.raw_url(), url);
            }
            ForgeInfo::Gitlab(_) => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    fn test_parse_gitlab_blob_url() {
        let url = "https://gitlab.com/namespace/project/-/blob/main/asfaload.initial_signers.json";
        let result = ForgeInfo::new(url).unwrap();

        match result {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), "namespace");
                assert_eq!(info.repo(), "project");
                assert_eq!(info.branch(), "main");
                assert_eq!(
                    info.file_path(),
                    PathBuf::from("asfaload.initial_signers.json")
                );
                assert_eq!(
                    info.raw_url(),
                    "https://gitlab.com/namespace/project/-/raw/main/asfaload.initial_signers.json"
                );
            }
            ForgeInfo::Github(_) => panic!("Expected GitLab variant"),
        }
    }

    #[test]
    fn test_parse_gitlab_raw_url() {
        let url = "https://gitlab.com/namespace/project/-/raw/develop/path/to/file.json";
        let result = ForgeInfo::new(url).unwrap();

        match result {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), "namespace");
                assert_eq!(info.repo(), "project");
                assert_eq!(info.branch(), "develop");
                assert_eq!(info.file_path(), PathBuf::from("path/to/file.json"));
                assert_eq!(info.raw_url(), url);
            }
            ForgeInfo::Github(_) => panic!("Expected GitLab variant"),
        }
    }

    #[test]
    fn test_unsupported_domain() {
        let url = "https://bitbucket.org/owner/repo/src/main/file.json";
        let result = ForgeInfo::new(url);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::file_auth::forges_types::ForgeUrlError::InvalidFormat(msg) => {
                assert!(msg.contains("Unsupported forge host"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_invalid_github_url() {
        let url = "https://github.com/owner/repo/main/file.json";
        let result = ForgeInfo::new(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_gitlab_url() {
        let url = "https://gitlab.com/namespace/project/-/main/file.json";
        let result = ForgeInfo::new(url);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn test_localhost_github_url() {
        let url = "http://localhost:8080/owner/repo/main/file.json";
        let result = ForgeInfo::new(url).unwrap();

        match result {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), "owner");
                assert_eq!(info.repo(), "repo");
            }
            ForgeInfo::Gitlab(_) => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn test_127_0_0_1_gitlab_url() {
        let url = "http://127.0.0.1:8080/namespace/project/-/blob/main/file.json";
        let result = ForgeInfo::new(url).unwrap();

        match result {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), "namespace");
                assert_eq!(info.repo(), "project");
            }
            ForgeInfo::Github(_) => panic!("Expected GitLab variant"),
        }
    }
}
