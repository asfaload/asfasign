use url::Url;
pub mod git_backend;
pub mod path_validation;

pub mod errors {

    use axum::{Json, http::StatusCode, response::IntoResponse};
    use thiserror::Error;

    use super::models::ErrorResponse;

    // To surface the errors of Kameo actor's on_start, the error has to be
    // Clone, which is not possible for ApiError due to some errors it wraps
    // not being Clone.
    #[derive(Error, Debug, Clone)]
    pub enum ActorError {
        #[error("Sled operation error: {0}")]
        SledError(#[from] sled::Error),
    }

    #[derive(Error, Debug)]
    pub enum ApiError {
        #[error("Actor error: {0}")]
        ActorError(#[from] ActorError),

        #[error("State error: {0}")]
        StateError(String),

        #[error("Git repository path not set in environment")]
        GitRepoPathNotSet,

        // Errors raised specifically by the use of git2-rs
        #[error("Git2 error: {0}")]
        GitOperationFailed(#[from] git2::Error),

        #[error("Git error: {0}")]
        GitError(String),

        #[error("Failed to create directories: {0}")]
        DirectoryCreationFailed(String),

        #[error("Failed to write file: {0}")]
        FileWriteFailed(String),

        #[error("TokioJoinError: {0}")]
        TokioJoinError(#[from] tokio::task::JoinError),

        #[error("Failed to send message to git actor: {0}")]
        ActorMessageFailed(String),

        #[error("Actor encountered an error: {0}")]
        ActorOperationFailed(String),

        #[error("Invalid file path: {0}")]
        InvalidFilePath(String),

        #[error("Server setup failed: {0}")]
        ServerSetupError(#[from] std::io::Error),

        #[error("Invalid port provided: {0}")]
        PortInvalid(String),

        #[error("Missing authentication headers")]
        MissingAuthenticationHeaders,

        #[error("Invalid authentication headers")]
        InvalidAuthenticationHeaders,

        #[error("Invalid request body: {0}")]
        InvalidRequestBody(String),

        #[error("Request too big: {0}")]
        RequestTooBig(String),

        #[error("Internal server error: {0}")]
        InternalServerError(String),

        #[error("Authentication failed: {0}")]
        AuthenticationFailed(String),

        #[error("Timestamp validation failed: {0}")]
        TimestampValidationFailed(String),

        #[error("Signature verification failed")]
        SignatureVerificationFailed,

        #[error("Replay attack detected: nonce already used")]
        ReplayAttackDetected,

        #[error("Server configuration error: {0}")]
        ServerConfigError(#[from] ServerConfigError),

        #[error("{0} API error: {1}")]
        ReleaseApiError(String, String),

        #[error("GitHub API error: {0}")]
        GitHubApiError(String),

        #[error("No active signers file found for repository")]
        NoActiveSignersFile,

        #[error("Invalid release URL format: {0}")]
        InvalidReleaseUrl(String),

        #[error("Unsupported release platform: {0}")]
        UnsupportedReleasePlatform(String),

        #[error("Invalid GitHub release URL format: {0}")]
        InvalidGitHubUrl(String),

        #[error("File not found: {0}")]
        FileNotFound(String),

        #[error("Signature already complete: {0}")]
        SignatureAlreadyComplete(String),

        #[error("Signers file error: {0}")]
        SignersFileError(#[from] common::errors::SignersFileError),

        #[error("Json Serialisation error: {0}")]
        SerdeJsonError(#[from] serde_json::Error),

        #[error("Revocation error: {0}")]
        RevocationError(String),

        #[error("File has not been fully signed: {0}")]
        FileNotFullySigned(String),

        #[error("Digest mismatch: {0}")]
        DigestMismatch(String),

        #[error("File is revoked: {0}")]
        FileRevoked(String),

        #[error("Release already registered: {0}")]
        ReleaseAlreadyRegistered(String),
    }

    #[derive(Error, Debug)]
    pub enum ServerConfigError {
        #[error("Configuration building error : {0}")]
        BuildError(#[from] config::ConfigError),

        #[error("Invalid configuration : {0}")]
        InvalidConfig(String),
    }

    impl From<hyper::header::ToStrError> for ApiError {
        fn from(_error: hyper::header::ToStrError) -> Self {
            ApiError::InvalidAuthenticationHeaders
        }
    }

    impl From<rest_api_auth::AuthError> for ApiError {
        fn from(error: rest_api_auth::AuthError) -> Self {
            match error {
                rest_api_auth::AuthError::AuthDataPreparationError(msg) => {
                    ApiError::AuthenticationFailed(msg)
                }
                rest_api_auth::AuthError::IoError(_) => {
                    ApiError::ServerSetupError(std::io::Error::other("Auth IO error"))
                }
                rest_api_auth::AuthError::SigningError(_) => {
                    ApiError::AuthenticationFailed("Signing error".to_string())
                }
                rest_api_auth::AuthError::KeyError(_) => {
                    ApiError::AuthenticationFailed("Key error".to_string())
                }
                rest_api_auth::AuthError::VerificationError(_) => {
                    ApiError::AuthenticationFailed("Signature verification failed".to_string())
                }
                rest_api_auth::AuthError::SignatureError(_) => {
                    ApiError::AuthenticationFailed("Signature error".to_string())
                }
                rest_api_auth::AuthError::MissingHeader(header) => {
                    ApiError::AuthenticationFailed(format!("Missing header: {}", header))
                }
                rest_api_auth::AuthError::InvalidTimestampFormat(_) => {
                    ApiError::AuthenticationFailed("Invalid timestamp format".to_string())
                }
                rest_api_auth::AuthError::InvalidNonceFormat(_) => {
                    ApiError::AuthenticationFailed("Invalid nonce format".to_string())
                }
                rest_api_auth::AuthError::TimestampInvalid(s) => {
                    ApiError::TimestampValidationFailed(s)
                }
                rest_api_auth::AuthError::Base64DecodeError(_) => {
                    ApiError::AuthenticationFailed("Base64 decode error".to_string())
                }
            }
        }
    }

    impl ApiError {
        pub fn to_http_status(&self) -> axum::http::StatusCode {
            match self {
                ApiError::GitRepoPathNotSet => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::DirectoryCreationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::FileWriteFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorMessageFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::InvalidFilePath(_) => StatusCode::BAD_REQUEST,
                ApiError::ServerSetupError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::PortInvalid(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::TokioJoinError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::GitOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::MissingAuthenticationHeaders => StatusCode::UNAUTHORIZED,
                ApiError::InvalidAuthenticationHeaders => StatusCode::UNAUTHORIZED,
                ApiError::InvalidRequestBody(_) => StatusCode::BAD_REQUEST,
                ApiError::AuthenticationFailed(_) => StatusCode::UNAUTHORIZED,
                ApiError::TimestampValidationFailed(_) => StatusCode::UNAUTHORIZED,
                ApiError::SignatureVerificationFailed => StatusCode::UNAUTHORIZED,
                ApiError::ReplayAttackDetected => StatusCode::UNAUTHORIZED,
                ApiError::StateError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ServerConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::RequestTooBig(_) => StatusCode::PAYLOAD_TOO_LARGE,
                ApiError::GitHubApiError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ReleaseApiError(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::NoActiveSignersFile => StatusCode::BAD_REQUEST,
                ApiError::InvalidReleaseUrl(_) => StatusCode::BAD_REQUEST,
                ApiError::UnsupportedReleasePlatform(_) => StatusCode::BAD_REQUEST,
                ApiError::InvalidGitHubUrl(_) => StatusCode::BAD_REQUEST,
                ApiError::FileNotFound(_) => StatusCode::NOT_FOUND,
                ApiError::SignatureAlreadyComplete(_) => StatusCode::CONFLICT,
                ApiError::SignersFileError(_) => StatusCode::BAD_REQUEST,
                ApiError::SerdeJsonError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::RevocationError(_) => StatusCode::BAD_REQUEST,
                ApiError::FileNotFullySigned(_) => StatusCode::CONFLICT,
                ApiError::DigestMismatch(_) => StatusCode::BAD_REQUEST,
                ApiError::FileRevoked(_) => StatusCode::BAD_REQUEST,
                ApiError::ReleaseAlreadyRegistered(_) => StatusCode::CONFLICT,
                ApiError::GitError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl IntoResponse for ApiError {
        fn into_response(self) -> axum::response::Response {
            let status = self.to_http_status();
            let error_message = self.to_string(); // Get the detailed error message from the #[error] macro

            // Create the JSON response body
            let body = Json(ErrorResponse {
                error: error_message,
            });

            // Return the response with the determined status and JSON body
            (status, body).into_response()
        }
    }
}

pub mod environment {
    use std::path::PathBuf;

    // Structure to hold environment in which the server runs.
    #[derive(Clone)]
    pub struct Environment {
        pub git_repo_path: PathBuf,
        pub server_port: u16,
    }
}

pub mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize)]
    pub struct ErrorResponse {
        pub error: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterRepoRequest {
        pub signers_file_url: String,
        /// Base64-encoded signature of the SHA-512 hash of the signers file content
        pub signature: String,
        /// Base64-encoded public key of the submitter
        pub public_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterRepoResponse {
        pub success: bool,
        pub project_id: String,
        pub message: String,
        pub required_signers: Vec<String>,
        pub signature_submission_url: String,
    }

    pub type UpdateRepoSignersRequest = RegisterRepoRequest;
    pub type UpdateRepoSignersResponse = RegisterRepoResponse;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    /// Request to submit a signature for a specific file.
    ///
    /// # Fields
    /// * `file_path` - Relative path to the file being signed
    /// * `public_key` - Base64-encoded public key of the signer
    /// * `signature` - Base64-encoded signature data
    pub struct SubmitSignatureRequest {
        pub file_path: String,
        pub public_key: String,
        pub signature: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    /// Response to a signature submission request.
    ///
    /// # Fields
    /// * `is_complete` - Whether the aggregate signature is now complete,
    ///   meaning all required signatures have been collected
    pub struct SubmitSignatureResponse {
        pub is_complete: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    /// Response to a signature status query.
    ///
    /// # Fields
    /// * `file_path` - Path to the file
    /// * `is_complete` - Whether the aggregate signature is complete
    /// * `collected_count` - Number of individual signatures collected so far
    pub struct GetSignatureStatusResponse {
        pub file_path: String,
        pub is_complete: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    /// Response to a pending signatures list request.
    ///
    /// # Fields
    /// * `file_paths` - List of relative paths to files that need signatures
    ///   from the requesting signer
    pub struct ListPendingResponse {
        pub file_paths: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RevokeFileRequest {
        /// Relative path to the signed file being revoked
        pub file_path: String,
        /// JSON string of the revocation document (RevocationInfo)
        pub revocation_json: String,
        /// Base64-encoded signature of the sha512 of revocation_json
        pub signature: String,
        /// Base64-encoded public key of the revoker
        pub public_key: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RevokeFileResponse {
        pub success: bool,
        pub message: String,
    }

    /// Request to register assets — either a GitHub release URL or checksums file URLs.
    /// Exactly one of `github_release_url` or `csum_files` must be provided.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterAssetsRequest {
        /// GitHub release URL (mutually exclusive with csum_files)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub github_release_url: Option<String>,
        /// Checksums file URLs (mutually exclusive with github_release_url)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub csum_files: Option<Vec<String>>,
    }

    /// Response to an assets registration request.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterAssetsResponse {
        pub success: bool,
        pub message: String,
        pub index_file_path: Option<String>,
    }

    /// Response for the get_signers_chain endpoint.
    ///
    /// Contains the signers history chain applicable to a signed artifact,
    /// filtered to entries up to and including the active config at signing time.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetSignersChainResponse {
        pub history: signers_file_types::HistoryFile,
    }
}

pub mod github_helpers {
    use crate::errors::ApiError;

    pub fn validate_github_url(
        url: &url::Url,
    ) -> Result<(String, String, String, String), ApiError> {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::InvalidGitHubUrl("Missing host".to_string()))?;

        if !host.ends_with("github.com") {
            return Err(ApiError::InvalidGitHubUrl(
                "Only github.com URLs are supported".to_string(),
            ));
        }

        let path_segments: Vec<_> = url
            .path_segments()
            .ok_or_else(|| ApiError::InvalidGitHubUrl("Invalid path".to_string()))?
            .collect();

        let releases_idx = path_segments
            .iter()
            .position(|&s| s == "releases")
            .ok_or_else(|| ApiError::InvalidGitHubUrl("Missing /releases/ in path".to_string()))?;

        if releases_idx < 2
            || releases_idx + 2 >= path_segments.len()
            || path_segments[releases_idx + 1] != "tag"
        {
            return Err(ApiError::InvalidGitHubUrl(
                "Invalid GitHub release URL structure trying to extract tag".to_string(),
            ));
        }

        let owner = path_segments[releases_idx - 2].to_string();
        let repo = path_segments[releases_idx - 1].to_string();
        let tag = path_segments[releases_idx + 2].to_string();

        if owner.is_empty() || repo.is_empty() || tag.is_empty() {
            return Err(ApiError::InvalidGitHubUrl(
                "Owner, repo, and tag cannot be empty".to_string(),
            ));
        }
        Ok((host.to_string(), owner, repo, tag))
    }
}
pub mod rustls {
    pub fn setup_crypto_provider() {
        use rustls::crypto::{CryptoProvider, ring};

        // Use the provider corresponding to the 'ring' feature you selected
        let provider = ring::default_provider();

        let _ = CryptoProvider::install_default(provider);
    }
}

// Re-export commonly used types at the module level
pub use models::{
    GetSignatureStatusResponse, GetSignersChainResponse, ListPendingResponse,
    RegisterAssetsRequest, RegisterAssetsResponse, RegisterRepoRequest, RegisterRepoResponse,
    RevokeFileRequest, RevokeFileResponse, SubmitSignatureRequest, SubmitSignatureResponse,
};

// ********************
// Assets registration
// ********************
/// Represents a validated common base path shared by a set of URLs.
pub struct CommonBasePath {
    pub host: String,
    pub parent_path: String,
}

/// Errors that can occur during URL validation.
#[derive(Debug, thiserror::Error)]
pub enum UrlValidationError {
    #[error("At least one URL must be provided")]
    EmptyUrls,
    #[error("URL missing host: {0}")]
    MissingHost(String),
    #[error("All URLs must have the same host. Found '{0}' and '{1}'")]
    DifferentHosts(String, String),
    #[error("All URLs must be in the same directory. Found '{0}' and '{1}'")]
    DifferentParents(String, String),
}

/// Extracts the parent directory from a URL path.
///
/// For example, "/releases/v1.0/SHA256SUMS" yields "/releases/v1.0/".
/// Falls back to "/" when no slash is found.
pub fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) => path[..=pos].to_string(),
        None => "/".to_string(),
    }
}

/// Validates that all URLs share the same host and parent directory.
///
/// Returns the common host and parent path on success.
pub fn validate_common_parent(urls: &[Url]) -> Result<CommonBasePath, UrlValidationError> {
    let first = urls.first().ok_or(UrlValidationError::EmptyUrls)?;

    let first_host = first
        .host_str()
        .ok_or_else(|| UrlValidationError::MissingHost(first.to_string()))?
        .to_string();

    let first_parent = parent_path(first.path());

    for url in &urls[1..] {
        let host = url
            .host_str()
            .ok_or_else(|| UrlValidationError::MissingHost(url.to_string()))?
            .to_string();

        if host != first_host {
            return Err(UrlValidationError::DifferentHosts(first_host, host));
        }

        let parent = parent_path(url.path());
        if parent != first_parent {
            return Err(UrlValidationError::DifferentParents(first_parent, parent));
        }
    }

    Ok(CommonBasePath {
        host: first_host,
        parent_path: first_parent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // parent_path tests
    // -----------------

    #[test]
    fn test_parent_path_with_file() {
        assert_eq!(parent_path("/releases/v1.0/SHA256SUMS"), "/releases/v1.0/");
    }

    #[test]
    fn test_parent_path_root_file() {
        assert_eq!(parent_path("/SHA256SUMS"), "/");
    }

    #[test]
    fn test_parent_path_no_slash() {
        assert_eq!(parent_path("SHA256SUMS"), "/");
    }

    // validate_common_parent tests
    // ----------------------------

    #[test]
    fn test_validate_single_url() -> anyhow::Result<()> {
        let urls = vec![Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?];
        let result = validate_common_parent(&urls)?;
        assert_eq!(result.host, "example.com");
        assert_eq!(result.parent_path, "/releases/v1.0/");
        Ok(())
    }

    #[test]
    fn test_validate_multiple_same_parent() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com/releases/v1.0/archive.tar.gz")?,
        ];
        let result = validate_common_parent(&urls)?;
        assert_eq!(result.host, "example.com");
        assert_eq!(result.parent_path, "/releases/v1.0/");
        Ok(())
    }

    #[test]
    fn test_validate_different_hosts() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://other.com/releases/v1.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentHosts(a, b)) => {
                assert_eq!(a, "example.com");
                assert_eq!(b, "other.com");
            }
            Err(e) => panic!("Expected DifferentHosts error, got: {e}"),
            Ok(_) => panic!("Expected DifferentHosts error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_different_parents() -> anyhow::Result<()> {
        let urls = vec![
            Url::parse("https://example.com/releases/v1.0/SHA256SUMS")?,
            Url::parse("https://example.com/releases/v2.0/archive.tar.gz")?,
        ];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::DifferentParents(a, b)) => {
                assert_eq!(a, "/releases/v1.0/");
                assert_eq!(b, "/releases/v2.0/");
            }
            Err(e) => panic!("Expected DifferentParents error, got: {e}"),
            Ok(_) => panic!("Expected DifferentParents error, got Ok"),
        }
        Ok(())
    }

    #[test]
    fn test_validate_empty_urls() {
        let urls: Vec<Url> = vec![];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::EmptyUrls) => {}
            Err(e) => panic!("Expected EmptyUrls error, got: {e}"),
            Ok(_) => panic!("Expected EmptyUrls error, got Ok"),
        }
    }

    #[test]
    fn test_validate_missing_host() -> anyhow::Result<()> {
        // file:// URLs have no host
        let urls = vec![Url::parse("file:///tmp/test.txt")?];
        match validate_common_parent(&urls) {
            Err(UrlValidationError::MissingHost(url_str)) => {
                assert!(url_str.starts_with("file:///"));
            }
            Err(e) => panic!("Expected MissingHost error, got: {e}"),
            Ok(_) => panic!("Expected MissingHost error, got Ok"),
        }
        Ok(())
    }
}
