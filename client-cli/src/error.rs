use features_lib::errors::AggregateSignatureError;
use features_lib::errors::keys::{KeyError, SignError, SignatureError, VerifyError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientCliError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),

    #[error("Sign error: {0}")]
    SignError(#[from] SignError),

    #[error("Verify error: {0}")]
    VerifyError(#[from] VerifyError),

    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("AggregateSignature error: {0}")]
    AggregateSignatureError(#[from] AggregateSignatureError),

    #[error("AggregateSignatureIncomplete")]
    AggregateSignatureIncompleteError,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Password is too week")]
    PasswordStrengthError(String),

    #[error("Password confirmation does not match")]
    PasswordConfirmationError,

    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signers file error: {0}")]
    SignersFile(String),

    #[error("Authentication error: {0}")]
    AuthError(#[from] rest_api_auth::AuthError),

    #[error("Reqwest header error: {0}")]
    ReqwestHeaderError(#[from] reqwest::header::InvalidHeaderValue),
}

// FIXME: remove this, creates more confusion than necessary
pub type Result<T> = std::result::Result<T, ClientCliError>;
