use std::path::{Path, PathBuf};

use url::Url;

use crate::{ForgeTrait, ForgeUrlError};

const ASFALOAD_SIGNERS_DIR: &str = ".asfaload_signers";

#[derive(Debug, Clone)]
pub struct FileServerRepoInfo {
    host: String,
    file_path: PathBuf,
    raw_url: Url,
}

impl ForgeTrait for FileServerRepoInfo {
    fn new(url: &Url) -> Result<Self, ForgeUrlError> {
        let host = {
            let h = url.host_str().unwrap_or("").to_string();
            match url.port() {
                Some(port) => format!("{}:{}", h, port),
                None => h,
            }
        };

        if host.is_empty() {
            return Err(ForgeUrlError::InvalidFormat(
                "URL must have a host".to_string(),
            ));
        }

        let path = url.path();
        // Reject empty or root-only paths
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Err(ForgeUrlError::MissingFilePath);
        }

        let file_path = PathBuf::from(segments.join("/"));

        Ok(FileServerRepoInfo {
            host,
            file_path,
            raw_url: url.clone(),
        })
    }

    fn project_id(&self) -> String {
        let path = &self.file_path;
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                // If the immediate parent is .asfaload_signers, go up one more level
                let parent_name = parent
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                let effective_parent = if parent_name == ASFALOAD_SIGNERS_DIR {
                    match parent.parent() {
                        Some(grandparent) if !grandparent.as_os_str().is_empty() => grandparent,
                        _ => return self.host.clone(),
                    }
                } else {
                    parent
                };

                format!("{}/{}", self.host, effective_parent.to_string_lossy())
            }
            _ => {
                // File is at root level (no parent dir)
                self.host.clone()
            }
        }
    }

    fn owner(&self) -> &str {
        &self.host
    }

    fn repo(&self) -> &str {
        let path_str = self.file_path.to_str().unwrap_or("");
        let first_segment = path_str.split('/').next().unwrap_or("");
        // If file_path has no directory component, there's no "repo"
        if !path_str.contains('/') {
            return "";
        }
        first_segment
    }

    fn branch(&self) -> &str {
        ""
    }

    fn file_path(&self) -> &Path {
        &self.file_path
    }

    fn raw_url(&self) -> &Url {
        &self.raw_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_url() {
        let url = Url::parse("http://localhost:8080/myproject/signers.json").unwrap();
        let info = FileServerRepoInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "localhost:8080/myproject");
        assert_eq!(info.owner(), "localhost:8080");
        assert_eq!(info.repo(), "myproject");
        assert_eq!(info.branch(), "");
        assert_eq!(info.file_path(), Path::new("myproject/signers.json"));
        assert_eq!(info.raw_url(), &url);
    }

    #[test]
    fn test_asfaload_signers_stripped() {
        let url =
            Url::parse("http://localhost:8080/myproject/.asfaload_signers/signers1.json").unwrap();
        let info = FileServerRepoInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "localhost:8080/myproject");
    }

    #[test]
    fn test_nested_path() {
        let url = Url::parse("http://files.example.com/org/project/deep/file.json").unwrap();
        let info = FileServerRepoInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "files.example.com/org/project/deep");
    }

    #[test]
    fn test_no_port() {
        let url = Url::parse("http://files.example.com/project/signers.json").unwrap();
        let info = FileServerRepoInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "files.example.com/project");
    }

    #[test]
    fn test_root_file() {
        let url = Url::parse("http://localhost:8080/signers.json").unwrap();
        let info = FileServerRepoInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "localhost:8080");
        assert_eq!(info.owner(), "localhost:8080");
        assert_eq!(info.repo(), "");
        assert_eq!(info.file_path(), Path::new("signers.json"));
    }

    #[test]
    fn test_empty_path_fails() {
        let url = Url::parse("http://localhost:8080/").unwrap();
        let result = FileServerRepoInfo::new(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_only_asfaload_signers_parent() {
        let url = Url::parse("http://localhost:8080/.asfaload_signers/signers.json").unwrap();
        let info = FileServerRepoInfo::new(&url).unwrap();
        assert_eq!(info.project_id(), "localhost:8080");
    }
}
