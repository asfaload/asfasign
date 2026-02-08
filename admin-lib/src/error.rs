use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdminLibError {
    #[error("Authentication error: {0}")]
    AuthError(#[from] rest_api_auth::AuthError),

    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Error response from server: {0}")]
    RequestFailed(String),

    #[error("Failed to parse server response: {0}")]
    ResponseParseError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type AdminLibResult<T> = std::result::Result<T, AdminLibError>;
