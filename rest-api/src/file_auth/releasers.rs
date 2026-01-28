#[cfg(not(feature = "test-utils"))]
use crate::file_auth::github_release::GithubClient;
use crate::file_auth::github_release::{GithubReleaseAdder, GithubReleaseInfo};
use crate::file_auth::gitlab_release::{GitlabReleaseAdder, GitlabReleaseInfo};
use crate::file_auth::release_types::{ReleaseAdder, ReleaseInfo, ReleaseUrlError};
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
    Github(Box<GithubReleaseAdder<GithubClient>>),
    #[cfg(feature = "test-utils")]
    Github(Box<GithubReleaseAdder<MockGithubClient>>),
    Gitlab(Box<GitlabReleaseAdder>),
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
            Ok(Self::Github(Box::new(github_adder)))
        } else if GITLAB_RELEASE_HOSTS.contains(&host) {
            let gitlab_adder = GitlabReleaseAdder::new(release_url, git_repo_path).await?;
            Ok(Self::Gitlab(Box::new(gitlab_adder)))
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
            Self::Github(github) => github.as_ref().index_content().await,
            Self::Gitlab(gitlab) => gitlab.as_ref().index_content().await,
        }
    }

    async fn write_index(&self) -> Result<NormalisedPaths, ApiError> {
        match self {
            Self::Github(github) => github.as_ref().write_index().await,
            Self::Gitlab(gitlab) => gitlab.as_ref().write_index().await,
        }
    }

    fn release_info(&self) -> ReleaseInfos {
        match self {
            Self::Github(github) => github.release_info(),
            Self::Gitlab(gitlab) => gitlab.release_info(),
        }
    }
}

#[derive(Debug)]
pub enum ReleaseInfos {
    Github(GithubReleaseInfo),
    Gitlab(GitlabReleaseInfo),
}

impl ReleaseInfo for ReleaseInfos {
    fn host(&self) -> &str {
        match self {
            Self::Github(github) => github.host(),
            Self::Gitlab(gitlab) => gitlab.host(),
        }
    }

    fn owner(&self) -> &str {
        match self {
            Self::Github(github) => github.owner(),
            Self::Gitlab(gitlab) => gitlab.owner(),
        }
    }

    fn repo(&self) -> &str {
        match self {
            Self::Github(github) => github.repo(),
            Self::Gitlab(gitlab) => gitlab.repo(),
        }
    }

    fn tag(&self) -> &str {
        match self {
            Self::Github(github) => github.tag(),
            Self::Gitlab(gitlab) => gitlab.tag(),
        }
    }

    fn release_path(&self) -> &NormalisedPaths {
        match self {
            Self::Github(github) => github.release_path(),
            Self::Gitlab(gitlab) => gitlab.release_path(),
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

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn test_release_adders_github_release() {
        use crate::file_auth::release_types::ReleaseAdder;
        use constants::{SIGNERS_DIR, SIGNERS_FILE};
        use tempfile::TempDir;
        use tokio::fs;

        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let signers_dir = git_repo_path
            .join("github.com/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).await.unwrap();

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": [
                {
                    "public_key": "test_key",
                    "name": "Test Signer"
                }
            ]
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .await
            .unwrap();

        let release_url =
            url::Url::parse("https://github.com/testowner/testrepo/releases/tag/v1.0.0").unwrap();

        let adder = ReleaseAdders::new(&release_url, git_repo_path.clone())
            .await
            .unwrap();

        let index_content = adder.index_content().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&index_content).unwrap();

        assert_eq!(json["version"], 1);
        assert!(json["publishedFiles"].is_array());
        let files = json["publishedFiles"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["fileName"], "test.tar.gz");
        assert_eq!(files[0]["algo"], "Sha256");
        assert_eq!(
            files[0]["hash"],
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn test_release_adders_gitlab_release() {
        use crate::file_auth::gitlab_release::test_utils::MockGitLabClient;
        use crate::file_auth::gitlab_release::{
            GitlabRelease, GitlabReleaseAdder, GitlabReleaseLink,
        };
        use crate::file_auth::release_types::ReleaseAdder;
        use constants::{SIGNERS_DIR, SIGNERS_FILE};
        use tempfile::TempDir;
        use tokio::fs;

        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let signers_dir = git_repo_path
            .join("gitlab.com/testnamespace/testproject")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).await.unwrap();

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": [
                {
                    "public_key": "test_key",
                    "name": "Test Signer"
                }
            ]
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .await
            .unwrap();

        let mut mock_client = MockGitLabClient::new();
        let test_content = b"test file for hashing";
        mock_client.mock_asset("/downloads/test.tar.gz", test_content);

        let _release = GitlabRelease {
            assets: Some(vec![GitlabReleaseLink {
                name: "test.tar.gz".to_string(),
                direct_asset_url: format!("{}/downloads/test.tar.gz", mock_client.url()),
            }]),
        };

        mock_client.mock_release(_release);

        let release_url =
            url::Url::parse("https://gitlab.com/testnamespace/testproject/-/releases/v1.0.0")
                .unwrap();

        let adder =
            GitlabReleaseAdder::new_with_client(&release_url, git_repo_path.clone(), mock_client)
                .await
                .unwrap();

        let index_content = adder.index_content().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&index_content).unwrap();

        assert_eq!(json["version"], 1);
        assert!(json["publishedFiles"].is_array());
        let files = json["publishedFiles"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["fileName"], "test.tar.gz");
        assert_eq!(files[0]["algo"], "Sha256");
        let hash = files[0]["hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
    }
}
