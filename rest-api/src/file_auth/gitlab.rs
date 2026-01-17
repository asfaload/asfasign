use std::path::{Path, PathBuf};

use crate::file_auth::forges_types::{ForgeTrait, ForgeUrlError};

#[derive(Debug, Clone)]
pub struct GitLabRepoInfo {
    namespace: String,
    project: String,
    branch: String,
    file_path: PathBuf,
    raw_url: url::Url,
}

#[cfg(not(feature = "test-utils"))]
pub const GITLAB_HOSTS: &[&str] = &["gitlab.com"];

#[cfg(feature = "test-utils")]
pub const GITLAB_HOSTS: &[&str] = &["gitlab.com", "localhost", "127.0.0.1"];

impl ForgeTrait for GitLabRepoInfo {
    fn new(url: &url::Url) -> Result<GitLabRepoInfo, ForgeUrlError> {
        let host = url.host_str().unwrap_or("");

        if !GITLAB_HOSTS.contains(&host) {
            return Err(ForgeUrlError::InvalidFormat(format!(
                "URL must be one of {}",
                GITLAB_HOSTS.join(","),
            )));
        }

        let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();

        if segments.len() < 5 {
            return Err(ForgeUrlError::InvalidFormat(
                "URL must have at least 5 path segments".to_string(),
            ));
        }

        let dash_idx = segments
            .iter()
            .position(|&s| s == "-")
            .ok_or_else(|| ForgeUrlError::InvalidFormat("Invalid GitLab URL format".to_string()))?;

        if dash_idx == 0 {
            return Err(ForgeUrlError::InvalidFormat(
                "GitLab URL must contain a namespace and project".to_string(),
            ));
        }

        let project = segments[dash_idx - 1].to_string();

        let namespace = if dash_idx > 1 {
            segments[..dash_idx - 1].join("/")
        } else {
            return Err(ForgeUrlError::InvalidFormat(
                "Namespace cannot be empty".to_string(),
            ));
        };

        let action = segments.get(dash_idx + 1);
        let action = match action {
            Some(&a) if a == "blob" || a == "raw" => a,
            _ => {
                return Err(ForgeUrlError::InvalidFormat(
                    "URL must contain /blob/ or /raw/".to_string(),
                ));
            }
        };

        let branch = segments
            .get(dash_idx + 2)
            .ok_or(ForgeUrlError::MissingBranch)?
            .to_string();

        let file_path_segments = segments
            .get(dash_idx + 3..)
            .ok_or(ForgeUrlError::MissingFilePath)?;

        let file_path = file_path_segments.join("/");

        if project.is_empty() {
            return Err(ForgeUrlError::InvalidFormat(
                "Project cannot be empty".to_string(),
            ));
        }

        if branch.is_empty() {
            return Err(ForgeUrlError::MissingBranch);
        }

        if file_path.is_empty() {
            return Err(ForgeUrlError::MissingFilePath);
        }

        let raw_url = if action == "raw" {
            url.clone()
        } else {
            url::Url::parse(
                format!(
                    "https://gitlab.com/{}/{}/-/raw/{}/{}",
                    namespace, project, branch, file_path
                )
                .as_str(),
            )
            .map_err(|e| ForgeUrlError::InvalidFormat(e.to_string()))?
        };

        Ok(GitLabRepoInfo {
            namespace,
            project,
            branch,
            file_path: PathBuf::from(file_path),
            raw_url,
        })
    }

    fn project_id(&self) -> String {
        format!("gitlab.com/{}/{}", self.namespace, self.project)
    }

    fn owner(&self) -> &str {
        &self.namespace
    }

    fn repo(&self) -> &str {
        &self.project
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gitlab_blob_url() {
        let url = url::Url::parse(
            "https://gitlab.com/namespace/project/-/blob/main/asfaload.initial_signers.json",
        )
        .unwrap();
        let result = GitLabRepoInfo::new(&url).unwrap();
        assert_eq!(result.namespace, "namespace");
        assert_eq!(result.project, "project");
        assert_eq!(result.branch, "main");
        assert_eq!(
            result.file_path,
            PathBuf::from("asfaload.initial_signers.json")
        );
        assert_eq!(
            result.raw_url,
            url::Url::parse(
                "https://gitlab.com/namespace/project/-/raw/main/asfaload.initial_signers.json"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_parse_gitlab_raw_url() {
        let url =
            url::Url::parse("https://gitlab.com/namespace/project/-/raw/develop/path/to/file.json")
                .unwrap();
        let result = GitLabRepoInfo::new(&url).unwrap();
        assert_eq!(result.namespace, "namespace");
        assert_eq!(result.project, "project");
        assert_eq!(result.branch, "develop");
        assert_eq!(result.file_path, PathBuf::from("path/to/file.json"));
        assert_eq!(result.raw_url, url);
    }

    #[test]
    fn test_parse_gitlab_nested_namespace() {
        let url =
            url::Url::parse("https://gitlab.com/group/subgroup/project/-/blob/main/file.json")
                .unwrap();
        let result = GitLabRepoInfo::new(&url).unwrap();
        assert_eq!(result.namespace, "group/subgroup");
        assert_eq!(result.project, "project");
        assert_eq!(result.branch, "main");
        assert_eq!(result.file_path, PathBuf::from("file.json"));
        assert_eq!(
            result.raw_url,
            url::Url::parse("https://gitlab.com/group/subgroup/project/-/raw/main/file.json")
                .unwrap()
        );
    }

    #[test]
    fn test_parse_invalid_domain() {
        let url =
            url::Url::parse("https://github.com/namespace/project/-/blob/main/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_blob_segment() {
        let url = url::Url::parse("https://gitlab.com/namespace/project/-/main/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_branch() {
        let url = url::Url::parse("https://gitlab.com/namespace/project/-/raw/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_namespace_and_project() {
        let url = url::Url::parse("https://gitlab.com/-/project/repo/blob/main/file.json").unwrap();
        let result = GitLabRepoInfo::new(&url);
        match result {
            Err(ForgeUrlError::InvalidFormat(msg)) => {
                if !msg.contains("GitLab URL must contain a namespace and project") {
                    panic!(
                        "Expected message to contain \"GitLab URL must contain a namespace and project\" but was \"{}\"",
                        msg
                    )
                }
            }
            Err(e) => panic!("Expected InvalidFormat error, got {}", e),
            Ok(v) => panic!("Expected InvalidFormat error, got ok value {:?}", v),
        }
    }
}
