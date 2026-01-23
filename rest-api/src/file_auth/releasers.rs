use crate::file_auth::github_release::GithubReleaseAdder;
use crate::file_auth::release_types::{ReleaseAdder, ReleaseUrlError};
use crate::path_validation::NormalisedPaths;
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

pub const GITHUB_RELEASE_HOSTS: &[&str] = &["github.com"];

#[derive(Debug)]
pub enum ReleaseAdders {
    Github(GithubReleaseAdder),
}

impl ReleaseAdder for ReleaseAdders {
    async fn new(release_url: &url::Url, git_repo_path: PathBuf) -> Result<Self, ReleaseUrlError>
    where
        Self: Sized,
    {
        let host = release_url
            .host_str()
            .ok_or_else(|| ReleaseUrlError::InvalidFormat("Missing host".to_string()))?;

        if GITHUB_RELEASE_HOSTS.contains(&host) {
            let github_adder = GithubReleaseAdder::new(release_url, git_repo_path).await?;
            Ok(Self::Github(github_adder))
        } else {
            Err(ReleaseUrlError::UnsupportedPlatform(host.to_string()))
        }
    }

    fn signers_file_path(&self) -> PathBuf {
        match self {
            Self::Github(github) => github.signers_file_path(),
        }
    }

    async fn index_content(&self) -> Result<String, ApiError> {
        match self {
            Self::Github(github) => github.index_content().await,
        }
    }

    async fn write_index(&self) -> Result<NormalisedPaths, ApiError> {
        match self {
            Self::Github(github) => github.write_index().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_release_hosts_constant() {
        assert_eq!(GITHUB_RELEASE_HOSTS, &["github.com"]);
    }

    #[test]
    fn test_github_release_host_detection() {
        let github_url =
            url::Url::parse("https://github.com/owner/repo/releases/tag/v1.0.0").unwrap();
        assert!(GITHUB_RELEASE_HOSTS.contains(&github_url.host_str().unwrap()));
    }

    #[test]
    fn test_non_github_host_not_detected() {
        let gitlab_url =
            url::Url::parse("https://gitlab.com/owner/repo/-/releases/v1.0.0").unwrap();
        assert!(!GITHUB_RELEASE_HOSTS.contains(&gitlab_url.host_str().unwrap()));
    }
}
