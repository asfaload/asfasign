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

    fn assert_forge_trait_methods(
        forge: &ForgeInfo,
        expected_owner: &str,
        expected_repo: &str,
        expected_branch: &str,
        expected_path: &str,
        expected_raw_url: &str,
        expected_project_id: &str,
    ) {
        assert_eq!(forge.owner(), expected_owner, "owner mismatch");
        assert_eq!(forge.repo(), expected_repo, "repo mismatch");
        assert_eq!(forge.branch(), expected_branch, "branch mismatch");
        assert_eq!(
            forge.file_path(),
            PathBuf::from(expected_path),
            "file_path mismatch"
        );
        assert_eq!(forge.raw_url(), expected_raw_url, "raw_url mismatch");
        assert_eq!(
            forge.project_id(),
            expected_project_id,
            "project_id mismatch"
        );
    }

    #[test]
    fn test_github_blob_all_trait_methods() {
        let url = "https://github.com/example-org/my-repo/blob/develop/docs/config.json";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "example-org",
            "my-repo",
            "develop",
            "docs/config.json",
            "https://raw.githubusercontent.com/example-org/my-repo/develop/docs/config.json",
            "github.com/example-org/my-repo",
        );
    }

    #[test]
    fn test_github_raw_all_trait_methods() {
        let url = "https://raw.githubusercontent.com/user/repo/v1.0/data.json";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "user",
            "repo",
            "v1.0",
            "data.json",
            url,
            "github.com/user/repo",
        );
    }

    #[test]
    fn test_github_nested_path_trait_methods() {
        let url = "https://github.com/org/complex-repo/blob/main/path/to/deeply/nested/config.yml";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "org",
            "complex-repo",
            "main",
            "path/to/deeply/nested/config.yml",
            "https://raw.githubusercontent.com/org/complex-repo/main/path/to/deeply/nested/config.yml",
            "github.com/org/complex-repo",
        );
    }

    #[test]
    fn test_github_complex_branch_trait_methods() {
        let url = "https://github.com/acme/projects/blob/feature-auth-v2/src/auth/provider.ts";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "acme",
            "projects",
            "feature-auth-v2",
            "src/auth/provider.ts",
            "https://raw.githubusercontent.com/acme/projects/feature-auth-v2/src/auth/provider.ts",
            "github.com/acme/projects",
        );
    }

    #[test]
    fn test_gitlab_blob_all_trait_methods() {
        let url = "https://gitlab.com/group/subgroup/project/-/blob/dev/src/main.rs";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "group/subgroup",
            "project",
            "dev",
            "src/main.rs",
            "https://gitlab.com/group/subgroup/project/-/raw/dev/src/main.rs",
            "gitlab.com/group/subgroup/project",
        );
    }

    #[test]
    fn test_gitlab_raw_all_trait_methods() {
        let url = "https://gitlab.com/group/project/-/raw/main/file.txt";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "group",
            "project",
            "main",
            "file.txt",
            url,
            "gitlab.com/group/project",
        );
    }

    #[test]
    fn test_gitlab_nested_namespace_trait_methods() {
        let url = "https://gitlab.com/enterprise/engineering/platform/app/-/blob/production/config/settings.toml";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "enterprise/engineering/platform",
            "app",
            "production",
            "config/settings.toml",
            "https://gitlab.com/enterprise/engineering/platform/app/-/raw/production/config/settings.toml",
            "gitlab.com/enterprise/engineering/platform/app",
        );
    }

    #[test]
    fn test_gitlab_nested_path_trait_methods() {
        let url = "https://gitlab.com/group/project/-/blob/deploy/lib/utils/helpers.js";
        let forge = ForgeInfo::new(url).unwrap();

        assert_forge_trait_methods(
            &forge,
            "group",
            "project",
            "deploy",
            "lib/utils/helpers.js",
            "https://gitlab.com/group/project/-/raw/deploy/lib/utils/helpers.js",
            "gitlab.com/group/project",
        );
    }

    #[test]
    fn test_forge_trait_methods_delegation_github() {
        let github = ForgeInfo::new("https://github.com/owner/repo/blob/main/file.json").unwrap();

        assert_eq!(github.owner(), "owner");
        assert_eq!(github.repo(), "repo");
        assert_eq!(github.branch(), "main");
        assert_eq!(github.file_path(), PathBuf::from("file.json"));
        assert_eq!(
            github.raw_url(),
            "https://raw.githubusercontent.com/owner/repo/main/file.json"
        );
        assert_eq!(github.project_id(), "github.com/owner/repo");

        match &github {
            ForgeInfo::Github(info) => {
                assert_eq!(info.owner(), github.owner());
                assert_eq!(info.repo(), github.repo());
                assert_eq!(info.branch(), github.branch());
                assert_eq!(info.file_path(), github.file_path());
                assert_eq!(info.raw_url(), github.raw_url());
                assert_eq!(info.project_id(), github.project_id());
            }
            ForgeInfo::Gitlab(_) => panic!("Expected GitHub variant"),
        }
    }

    #[test]
    fn test_forge_trait_methods_delegation_gitlab() {
        let gitlab = ForgeInfo::new("https://gitlab.com/ns/proj/-/blob/main/file.json").unwrap();

        assert_eq!(gitlab.owner(), "ns");
        assert_eq!(gitlab.repo(), "proj");
        assert_eq!(gitlab.branch(), "main");
        assert_eq!(gitlab.file_path(), PathBuf::from("file.json"));
        assert_eq!(
            gitlab.raw_url(),
            "https://gitlab.com/ns/proj/-/raw/main/file.json"
        );
        assert_eq!(gitlab.project_id(), "gitlab.com/ns/proj");

        match &gitlab {
            ForgeInfo::Gitlab(info) => {
                assert_eq!(info.owner(), gitlab.owner());
                assert_eq!(info.repo(), gitlab.repo());
                assert_eq!(info.branch(), gitlab.branch());
                assert_eq!(info.file_path(), gitlab.file_path());
                assert_eq!(info.raw_url(), gitlab.raw_url());
                assert_eq!(info.project_id(), gitlab.project_id());
            }
            ForgeInfo::Github(_) => panic!("Expected GitLab variant"),
        }
    }
}
