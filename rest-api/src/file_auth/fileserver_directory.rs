use crate::constants::INDEX_FILE;
use crate::file_auth::download_hash::download_and_hash;
use crate::path_validation::NormalisedPaths;
use features_lib::{AsfaloadIndex, FileChecksum, HashAlgorithm};
use rest_api_types::errors::ApiError;
use std::path::PathBuf;

const MAX_FILE_SIZE_FOR_HASHING: u64 = 500 * 1024 * 1024; // 500MB

/// Handles registration of files from a static file server directory.
///
/// Given a set of URLs that all reside in the same directory on the same host,
/// this struct downloads each file, computes its SHA-256 hash, and writes an
/// index file into the git-backed repository.
pub struct FileServerDirectoryRegistrar {
    git_repo_path: PathBuf,
    reqwest_client: reqwest::Client,
    host: String,
    /// The common parent directory path (without host), e.g. "/projects/myapp/v2.0/"
    directory_path: String,
    urls: Vec<url::Url>,
}

impl FileServerDirectoryRegistrar {
    pub fn new(git_repo_path: PathBuf, urls: Vec<url::Url>) -> Result<Self, ApiError> {
        if urls.is_empty() {
            return Err(ApiError::InvalidRequestBody(
                "At least one URL must be provided".to_string(),
            ));
        }

        // All URLs must share the same host
        let first_host = urls[0]
            .host_str()
            .ok_or_else(|| ApiError::InvalidRequestBody("URL missing host".to_string()))?
            .to_string();

        if let Some(url) = urls[1..].iter().find(|u| u.host_str() != Some(&first_host)) {
            let other = url.host_str().unwrap_or("<missing>");
            return Err(ApiError::InvalidRequestBody(format!(
                "All URLs must have the same host. Found '{}' and '{}'",
                first_host, other
            )));
        }

        // All URLs must share the same parent directory
        let first_parent = parent_path(urls[0].path());
        if let Some(url) = urls[1..]
            .iter()
            .find(|u| parent_path(u.path()) != first_parent)
        {
            return Err(ApiError::InvalidRequestBody(format!(
                "All URLs must be in the same directory. Found '{}' and '{}'",
                first_parent,
                parent_path(url.path())
            )));
        }

        Ok(Self {
            git_repo_path,
            reqwest_client: reqwest::Client::new(),
            host: first_host,
            directory_path: first_parent,
            urls,
        })
    }

    /// Returns the on-disk directory corresponding to this file server directory.
    /// Used to locate the signers file.
    pub fn signers_file_path(&self) -> PathBuf {
        let dir_path = format!("{}{}", self.host, self.directory_path);
        self.git_repo_path.join(dir_path)
    }

    /// Computes the normalised path where the index file should be written.
    pub async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        let dir_path = format!("{}{}", self.host, self.directory_path);
        let base_path =
            NormalisedPaths::new(self.git_repo_path.clone(), PathBuf::from(&dir_path)).await?;
        base_path.join(INDEX_FILE).await
    }

    /// Downloads all files, computes hashes, and writes the index file.
    /// Fails if the index file already exists.
    pub async fn create_index(&self) -> Result<NormalisedPaths, ApiError> {
        // Verify a signers file exists for this directory
        let dir_on_disk = self.signers_file_path();
        common::fs::names::find_global_signers_for(&dir_on_disk)
            .map_err(|_| ApiError::NoActiveSignersFile)?;

        let index_path = self.index_path().await?;
        let abs_path = index_path.absolute_path();

        if let Some(parent) = abs_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to create directory: {}", e))
            })?;
        }

        // Downloads are sequential to avoid overwhelming the file server.
        let mut published_files = Vec::new();
        for url in &self.urls {
            let file_name = url
                .path_segments()
                .and_then(|mut s| s.next_back())
                .unwrap_or("unknown")
                .to_string();

            let hash = self.download_and_hash_file(url.as_str()).await?;

            published_files.push(FileChecksum {
                file_name,
                algo: HashAlgorithm::Sha256,
                source: url.to_string(),
                hash,
            });
        }

        let now = chrono::Utc::now();
        let index = AsfaloadIndex {
            mirrored_on: now,
            published_on: now,
            version: 1,
            published_files,
        };

        let content = serde_json::to_string_pretty(&index).map_err(|e| {
            ApiError::InternalServerError(format!("Failed to serialize index: {}", e))
        })?;

        let mut oo = tokio::fs::OpenOptions::new();
        match oo.write(true).create_new(true).open(&abs_path).await {
            Ok(mut f) => {
                use tokio::io::AsyncWriteExt;
                f.write_all(content.as_bytes()).await.map_err(|e| {
                    ApiError::FileWriteFailed(format!("Failed to write index file: {}", e))
                })?;
                Ok(index_path)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ApiError::ReleaseAlreadyRegistered(format!(
                    "Directory already registered: {}",
                    index_path.relative_path().display()
                )))
            }
            Err(e) => Err(ApiError::FileWriteFailed(format!(
                "Failed to create index file: {}",
                e
            ))),
        }
    }

    async fn download_and_hash_file(&self, url: &str) -> Result<String, ApiError> {
        download_and_hash(
            &self.reqwest_client,
            url,
            MAX_FILE_SIZE_FOR_HASHING,
            "FileServer",
            false, // Content-Length is optional for file servers
        )
        .await
    }
}

/// Extract the parent directory path from a URL path.
/// e.g., "/projects/myapp/v2.0/file1.tar.gz" -> "/projects/myapp/v2.0/"
fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => path[..=idx].to_string(),
        None => "/".to_string(),
    }
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // parent_path tests
    // -----------------

    #[test]
    fn test_parent_path_with_file() {
        assert_eq!(
            parent_path("/projects/myapp/v2.0/file1.tar.gz"),
            "/projects/myapp/v2.0/"
        );
    }

    #[test]
    fn test_parent_path_root_file() {
        assert_eq!(parent_path("/file.txt"), "/");
    }

    #[test]
    fn test_parent_path_no_slash() {
        assert_eq!(parent_path("file.txt"), "/");
    }

    #[test]
    fn test_parent_path_trailing_slash() {
        assert_eq!(parent_path("/dir/subdir/"), "/dir/subdir/");
    }

    #[test]
    fn test_parent_path_deep_nesting() {
        assert_eq!(parent_path("/a/b/c/d/e/file.bin"), "/a/b/c/d/e/");
    }

    #[test]
    fn test_parent_path_empty_string() {
        assert_eq!(parent_path(""), "/");
    }

    // FileServerDirectoryRegistrar::new validation tests
    // ---------------------------------------------------

    #[test]
    fn test_new_empty_urls() {
        let result = FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), vec![]);
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("At least one URL"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for empty URLs"),
        }
    }

    #[test]
    fn test_new_single_url() {
        let url = url::Url::parse("https://files.example.com/releases/v1.0/app.tar.gz").unwrap();
        let result = FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), vec![url]);
        assert!(result.is_ok());
        let registrar = result.unwrap();
        assert_eq!(registrar.host, "files.example.com");
        assert_eq!(registrar.directory_path, "/releases/v1.0/");
    }

    #[test]
    fn test_new_multiple_urls_same_directory() {
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/app.tar.gz").unwrap(),
            url::Url::parse("https://files.example.com/releases/v1.0/app.zip").unwrap(),
            url::Url::parse("https://files.example.com/releases/v1.0/checksums.txt").unwrap(),
        ];
        let result = FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), urls);
        assert!(result.is_ok());
        let registrar = result.unwrap();
        assert_eq!(registrar.host, "files.example.com");
        assert_eq!(registrar.directory_path, "/releases/v1.0/");
        assert_eq!(registrar.urls.len(), 3);
    }

    #[test]
    fn test_new_different_hosts() {
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/app.tar.gz").unwrap(),
            url::Url::parse("https://other.example.com/releases/v1.0/app.zip").unwrap(),
        ];
        let result = FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), urls);
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("same host"));
                assert!(msg.contains("files.example.com"));
                assert!(msg.contains("other.example.com"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for different hosts"),
        }
    }

    #[test]
    fn test_new_different_directories() {
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/app.tar.gz").unwrap(),
            url::Url::parse("https://files.example.com/releases/v2.0/app.tar.gz").unwrap(),
        ];
        let result = FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), urls);
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("same directory"));
                assert!(msg.contains("/releases/v1.0/"));
                assert!(msg.contains("/releases/v2.0/"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for different directories"),
        }
    }

    #[test]
    fn test_new_url_without_host() {
        let url = url::Url::parse("file:///local/path/file.txt").unwrap();
        let result = FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), vec![url]);
        // file:// URLs have no host
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("missing host") || msg.contains("URL missing host"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for URL without host"),
        }
    }

    #[test]
    fn test_signers_file_path() {
        let url =
            url::Url::parse("https://files.example.com/projects/myapp/v2.0/app.tar.gz").unwrap();
        let registrar =
            FileServerDirectoryRegistrar::new(PathBuf::from("/repo"), vec![url]).unwrap();
        let expected = PathBuf::from("/repo/files.example.com/projects/myapp/v2.0/");
        assert_eq!(registrar.signers_file_path(), expected);
    }

    #[tokio::test]
    async fn test_index_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url = url::Url::parse("https://files.example.com/releases/v1.0/app.tar.gz").unwrap();
        let registrar =
            FileServerDirectoryRegistrar::new(temp_dir.path().to_path_buf(), vec![url]).unwrap();
        let index_path = registrar.index_path().await.unwrap();
        let relative = index_path.relative_path();
        assert_eq!(
            relative,
            PathBuf::from("files.example.com/releases/v1.0").join(INDEX_FILE)
        );
    }
}
