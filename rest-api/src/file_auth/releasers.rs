use crate::file_auth::github_release::GithubReleaseAdder;
#[cfg(not(feature = "test-utils"))]
use crate::file_auth::github_release::GithubClient;
use crate::file_auth::gitlab_release::{GitLabClient, GitlabReleaseAdder};
use crate::file_auth::release_types::{ReleaseAdder, ReleaseUrlError};
use crate::path_validation::NormalisedPaths;
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

pub const GITHUB_RELEASE_HOSTS: &[&str] = &["github.com"];
pub const GITLAB_RELEASE_HOSTS: &[&str] = &["gitlab.com"];

#[cfg(feature = "test-utils")]
use crate::file_auth::github_release::test_utils::MockGithubClient;

#[derive(Debug)]
pub enum ReleaseAdders {
    #[cfg(not(feature = "test-utils"))]
    Github(GithubReleaseAdder<GithubClient>),
    #[cfg(feature = "test-utils")]
    Github(GithubReleaseAdder<MockGithubClient>),
    Gitlab(GitlabReleaseAdder<GitLabClient>),
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
        } else if GITLAB_RELEASE_HOSTS.contains(&host) {
            let gitlab_adder = GitlabReleaseAdder::new(release_url, git_repo_path).await?;
            Ok(Self::Gitlab(gitlab_adder))
        } else {
            Err(ReleaseUrlError::UnsupportedPlatform(format!(
                "{}. Supported: GitHub ({}), GitLab ({})",
                host,
                GITHUB_RELEASE_HOSTS.join(", "),
                GITLAB_RELEASE_HOSTS.join(", ")
            )))
        }
    }

    fn signers_file_path(&self) -> PathBuf {
        match self {
            Self::Github(github) => github.signers_file_path(),
            Self::Gitlab(gitlab) => gitlab.signers_file_path(),
        }
    }

    async fn index_content(&self) -> Result<String, ApiError> {
        match self {
            Self::Github(github) => github.index_content().await,
            Self::Gitlab(gitlab) => gitlab.index_content().await,
        }
    }

    async fn write_index(&self) -> Result<NormalisedPaths, ApiError> {
        match self {
            Self::Github(github) => github.write_index().await,
            Self::Gitlab(gitlab) => gitlab.write_index().await,
        }
    }

    fn release_info(&self) -> &dyn crate::file_auth::release_types::ReleaseInfo {
        match self {
            Self::Github(github) => github.release_info(),
            Self::Gitlab(gitlab) => gitlab.release_info(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitlab_release_hosts_constant() {
        assert_eq!(GITLAB_RELEASE_HOSTS, &["gitlab.com"]);
    }

    #[test]
    fn test_github_release_host_detection() {
        let github_url =
            url::Url::parse("https://github.com/owner/repo/releases/tag/v1.0.0").unwrap();
        assert!(GITHUB_RELEASE_HOSTS.contains(&github_url.host_str().unwrap()));
        assert!(!GITLAB_RELEASE_HOSTS.contains(&github_url.host_str().unwrap()));
    }

    #[test]
    fn test_gitlab_release_host_detection() {
        let gitlab_url =
            url::Url::parse("https://gitlab.com/group/project/-/releases/v1.0.0").unwrap();
        assert!(GITLAB_RELEASE_HOSTS.contains(&gitlab_url.host_str().unwrap()));
        assert!(!GITHUB_RELEASE_HOSTS.contains(&gitlab_url.host_str().unwrap()));
    }

    #[test]
    fn test_unsupported_host() {
        let bitbucket_url = url::Url::parse("https://bitbucket.org/owner/repo/v1.0.0").unwrap();
        assert!(!GITHUB_RELEASE_HOSTS.contains(&bitbucket_url.host_str().unwrap()));
        assert!(!GITLAB_RELEASE_HOSTS.contains(&bitbucket_url.host_str().unwrap()));
    }
}
