use features_lib::errors::{AggregateSignatureError, SignersFileError};
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientLibError {
    #[error("HTTP {status}: {url}")]
    HttpError { status: u16, url: String },

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Signers config parse error: {0}")]
    SignersConfigParse(String),

    #[error("Unsupported forge: {0}")]
    UnsupportedForge(String),

    #[error("No artifact_signers group defined in signers config")]
    MissingArtifactSigners,

    #[error("Signature parse error: {0}")]
    SignaturesParseError(String),

    #[error("Signature threshold not met: required {required}, found {found}")]
    SignatureThresholdNotMet { required: usize, found: usize },

    #[error("File '{0}' not found in index")]
    FileNotInIndex(String),

    #[error("Unsupported hash algorithm: {:?}", .0)]
    UnsupportedHashAlgorithm(features_lib::HashAlgorithm),

    #[error("Hash mismatch: expected '{expected}', got '{computed}'")]
    HashMismatch { expected: String, computed: String },

    #[error("Hash algorithm mismatch: expected {expected:?}, got {computed:?}")]
    HashAlgorithmMismatch {
        expected: features_lib::HashAlgorithm,
        computed: features_lib::HashAlgorithm,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to persist file: {0}")]
    PersistError(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] Utf8Error),

    #[error("Aggregate signature error: {0}")]
    AggregateSignature(#[from] AggregateSignatureError),

    #[error("Signers file error: {0}")]
    SignersFile(#[from] SignersFileError),
}

pub type AsfaloadLibResult<T> = std::result::Result<T, ClientLibError>;
