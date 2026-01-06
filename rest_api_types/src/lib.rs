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
                ApiError::RequestTooBig(_) => StatusCode::PAYLOAD_TOO_LARGE,
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
}
