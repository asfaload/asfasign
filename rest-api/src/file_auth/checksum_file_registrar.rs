use crate::constants::{INDEX_FILE, MAX_CHECKSUM_FILE_SIZE, MAX_PARALLEL_CSUMS};
use common::checksums_parser::parse_checksums;
use features_lib::{AsfaloadIndex, FileChecksum};
use futures::stream::{self, StreamExt};
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use rest_api_types::validate_common_parent;
use std::path::PathBuf;

/// Handles registration of files from checksums files (e.g. SHA256SUMS, SHA512SUMS).
///
/// Instead of downloading each artifact and computing its hash, this registrar
/// downloads text-based checksum files, parses them to extract file names and
/// pre-computed hashes, and writes an index file into the git-backed repository.
pub struct ChecksumFileRegistrar {
    reqwest_client: reqwest::Client,
    directory_path: NormalisedPaths,
    urls: Vec<url::Url>,
}

impl ChecksumFileRegistrar {
    pub async fn new(git_repo_path: PathBuf, urls: Vec<url::Url>) -> Result<Self, ApiError> {
        let base = validate_common_parent(&urls)
            .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;

        let dir_path = format!("{}{}", base.host, base.parent_path);
        let directory_path = NormalisedPaths::new(git_repo_path, PathBuf::from(&dir_path)).await?;

        Ok(Self {
            reqwest_client: reqwest::Client::new(),
            directory_path,
            urls,
        })
    }

    /// Returns the on-disk directory corresponding to this checksums file directory.
    /// Used to locate the signers file.
    pub fn signers_file_path(&self) -> PathBuf {
        self.directory_path.absolute_path()
    }

    /// Computes the normalised path where the index file should be written.
    pub async fn index_path(&self) -> Result<NormalisedPaths, ApiError> {
        self.directory_path.join(INDEX_FILE).await
    }

    /// Downloads all checksums files in parallel, parses them, and writes the index file.
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

        // Download and parse checksums files in parallel
        let results: Vec<Result<Vec<FileChecksum>, ApiError>> = stream::iter(self.urls.clone())
            .map(|url| {
                let client = self.reqwest_client.clone();
                async move {
                    let content = download_checksum_file(&client, url.as_str()).await?;
                    let checksums = parse_checksums(&content).map_err(|e| {
                        ApiError::InvalidRequestBody(format!(
                            "Failed to parse checksums file {}: {}",
                            url, e
                        ))
                    })?;
                    Ok(checksums
                        .into_iter()
                        .map(|c| FileChecksum {
                            file_name: c.file_name,
                            algo: c.algo,
                            source: url.to_string(),
                            hash: c.hash,
                        })
                        .collect())
                }
            })
            .buffer_unordered(MAX_PARALLEL_CSUMS)
            .collect()
            .await;

        let published_files: Vec<FileChecksum> = results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();

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
}

/// Downloads the text content of a checksums file, enforcing a size limit.
async fn download_checksum_file(client: &reqwest::Client, url: &str) -> Result<String, ApiError> {
    use futures_util::StreamExt as _;

    let response = client.get(url).send().await.map_err(|e| {
        ApiError::ReleaseApiError(
            "ChecksumFile".to_string(),
            format!("Failed to download checksums file: {}", e),
        )
    })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(ApiError::ReleaseApiError(
            "ChecksumFile".to_string(),
            format!(
                "HTTP error downloading checksums file {}: {}",
                url,
                response.status()
            ),
        ));
    }

    if let Some(len) = response.content_length()
        && len > MAX_CHECKSUM_FILE_SIZE
    {
        return Err(ApiError::ReleaseApiError(
            "ChecksumFile".to_string(),
            format!(
                "Checksums file size {} exceeds limit {}",
                len, MAX_CHECKSUM_FILE_SIZE
            ),
        ));
    }

    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    let mut total_bytes = 0u64;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            ApiError::ReleaseApiError(
                "ChecksumFile".to_string(),
                format!("Error reading checksums stream: {}", e),
            )
        })?;

        total_bytes += chunk.len() as u64;
        if total_bytes > MAX_CHECKSUM_FILE_SIZE {
            return Err(ApiError::ReleaseApiError(
                "ChecksumFile".to_string(),
                format!(
                    "Checksums file size exceeded limit during download: {}",
                    MAX_CHECKSUM_FILE_SIZE
                ),
            ));
        }

        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|e| {
        ApiError::InvalidRequestBody(format!("Checksums file is not valid UTF-8: {}", e))
    })
}

#[cfg(all(test, not(feature = "test-utils")))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_new_validates_urls() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url = url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap();
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![url]).await;
        assert!(result.is_ok());
        let registrar = result.unwrap();
        assert_eq!(
            registrar.directory_path.relative_path(),
            PathBuf::from("files.example.com/releases/v1.0")
        );
        assert_eq!(registrar.urls.len(), 1);
    }

    #[tokio::test]
    async fn test_new_different_hosts_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap(),
            url::Url::parse("https://other.example.com/releases/v1.0/SHA512SUMS").unwrap(),
        ];
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), urls).await;
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("files.example.com"));
                assert!(msg.contains("other.example.com"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for different hosts"),
        }
    }

    #[tokio::test]
    async fn test_new_different_parents_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let urls = vec![
            url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap(),
            url::Url::parse("https://files.example.com/releases/v2.0/SHA256SUMS").unwrap(),
        ];
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), urls).await;
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("/releases/v1.0/"));
                assert!(msg.contains("/releases/v2.0/"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for different parents"),
        }
    }

    #[tokio::test]
    async fn test_new_empty_urls_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let result = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![]).await;
        match result {
            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("At least one URL"));
            }
            Err(e) => panic!("Expected InvalidRequestBody, got {}", e),
            Ok(_) => panic!("Expected error for empty URLs"),
        }
    }

    #[tokio::test]
    async fn test_signers_file_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url =
            url::Url::parse("https://files.example.com/projects/myapp/v2.0/SHA256SUMS").unwrap();
        let registrar = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![url])
            .await
            .unwrap();
        let expected = temp_dir
            .path()
            .join("files.example.com/projects/myapp/v2.0");
        assert_eq!(registrar.signers_file_path(), expected);
    }

    #[tokio::test]
    async fn test_index_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let url = url::Url::parse("https://files.example.com/releases/v1.0/SHA256SUMS").unwrap();
        let registrar = ChecksumFileRegistrar::new(temp_dir.path().to_path_buf(), vec![url])
            .await
            .unwrap();
        let index_path = registrar.index_path().await.unwrap();
        let relative = index_path.relative_path();
        assert_eq!(
            relative,
            PathBuf::from("files.example.com/releases/v1.0").join(INDEX_FILE)
        );
    }
}
