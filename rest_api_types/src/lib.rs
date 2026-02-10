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

    use crate::github_helpers::validate_github_url;

    #[derive(Debug, Deserialize)]
    pub struct AddFileRequest {
        pub file_path: String,
        pub content: String,
    }

    #[derive(Debug, Serialize)]
    pub struct AddFileResponse {
        pub success: bool,
        pub message: String,
        pub file_path: String,
    }

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

    #[derive(Debug, Clone, Serialize)]
    pub struct RegisterReleaseRequest {
        pub release_url: url::Url,
    }

    impl<'de> serde::Deserialize<'de> for RegisterReleaseRequest {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::MapAccess;

            enum Field {
                ReleaseUrl,
            }

            impl<'de> serde::Deserialize<'de> for Field {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    struct FieldVisitor;
                    impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                        type Value = Field;

                        fn expecting(
                            &self,
                            formatter: &mut std::fmt::Formatter,
                        ) -> std::fmt::Result {
                            formatter.write_str("`release_url`")
                        }

                        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            match value {
                                "release_url" => Ok(Field::ReleaseUrl),
                                _ => Err(serde::de::Error::unknown_field(value, &["release_url"])),
                            }
                        }
                    }

                    deserializer.deserialize_identifier(FieldVisitor)
                }
            }

            struct RegisterReleaseVisitor;
            impl<'de> serde::de::Visitor<'de> for RegisterReleaseVisitor {
                type Value = RegisterReleaseRequest;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct RegisterReleaseRequest")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut url_string: Option<String> = None;

                    while let Some(field) = map.next_key()? {
                        match field {
                            Field::ReleaseUrl => {
                                if url_string.is_none() {
                                    url_string = Some(map.next_value()?);
                                } else {
                                    return Err(serde::de::Error::duplicate_field("release_url"));
                                }
                            }
                        }
                    }

                    let url_string = url_string
                        .map(|s| s.to_string())
                        .ok_or_else(|| serde::de::Error::missing_field("release_url"))?;

                    let release_url = url::Url::parse(&url_string)
                        .map_err(|e| serde::de::Error::custom(format!("Invalid URL: {}", e)))?;

                    validate_github_url(&release_url)
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?;

                    Ok(RegisterReleaseRequest { release_url })
                }
            }

            deserializer.deserialize_struct(
                "RegisterReleaseRequest",
                &["release_url"],
                RegisterReleaseVisitor,
            )
        }
    }

    impl RegisterReleaseRequest {
        pub fn new(url_string: String) -> Result<Self, crate::errors::ApiError> {
            let release_url = url::Url::parse(&url_string).map_err(|e| {
                crate::errors::ApiError::InvalidReleaseUrl(format!("Invalid URL: {}", e))
            })?;

            validate_github_url(&release_url)?;

            Ok(Self { release_url })
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterReleaseResponse {
        pub success: bool,
        pub message: String,
        pub index_file_path: Option<String>,
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
    GetSignatureStatusResponse, ListPendingResponse, RegisterReleaseRequest,
    RegisterReleaseResponse, RegisterRepoRequest, RegisterRepoResponse, SubmitSignatureRequest,
    SubmitSignatureResponse,
};
