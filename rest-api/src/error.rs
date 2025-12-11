use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Git repository path not set in environment")]
    GitRepoPathNotSet,
    
    #[error("Failed to create directories: {0}")]
    DirectoryCreationFailed(String),
    
    #[error("Failed to write file: {0}")]
    FileWriteFailed(String),
    
    #[error("Failed to send message to git actor: {0}")]
    ActorMessageFailed(String),
    
    #[error("Invalid file path: {0}")]
    InvalidFilePath(String),
}

impl ApiError {
    pub fn to_http_status(&self) -> axum::http::StatusCode {
        match self {
            ApiError::GitRepoPathNotSet => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::DirectoryCreationFailed(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::FileWriteFailed(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ActorMessageFailed(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::InvalidFilePath(_) => axum::http::StatusCode::BAD_REQUEST,
        }
    }
}