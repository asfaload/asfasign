pub mod errors {

    use axum::{Json, http::StatusCode, response::IntoResponse};
    use thiserror::Error;

    use super::models::ErrorResponse;

    #[derive(Error, Debug)]
    pub enum ApiError {
        #[error("Git repository path not set in environment")]
        GitRepoPathNotSet,

        #[error("Failed git operation: {0}")]
        GitOperationFailed(String),

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
                ApiError::GitOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::ActorOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                ApiError::TokioJoinError(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
