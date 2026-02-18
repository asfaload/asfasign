use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignedFileError {
    #[error("AggregateSignatureError: {0}")]
    AggregateSignatureError(#[from] AggregateSignatureError),
    #[error("SignersFileError: {0}")]
    SignersFileError(#[from] SignersFileError),
    #[error("Authorised signers retrieval failure: {0}")]
    AuthorisedSignersRetrievalFailure(AggregateSignatureError),
    #[error("stdio error: {0}")]
    StdIoError(#[from] std::io::Error),
    #[error("File is revoked")]
    Revoked(),
}

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Signature error: {0}")]
    Signature(String),
}

#[derive(Debug, Error)]
pub enum AggregateSignatureError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Signature error: {0}")]
    Signature(String),
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("UTF8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Public key error: {0}")]
    PublicKey(String),
    #[error("Threshold not met for group")]
    ThresholdNotMet,
    #[error("Cannot transition incomplete signature to complete")]
    IsIncomplete,
    #[error("Complete signature file according to name is not complete according to signatures")]
    MissingSignaturesInCompleteSignature,
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Signature is already complete, cannot compute missing signers")]
    SignatureAlreadyComplete,
    // Use when an agg signature does not have the status is should logically have.
    // Should not happen, but is used to avoid an unwrap() when we are sure that
    // we would get a Some with SignatureWithState::get_pending because we tested it before.
    #[error("Logic error: {0}")]
    LogicError(String),
    #[error("File is revoked")]
    FileRevoked,
}

#[derive(Debug, Error)]
pub enum SignersFileError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid signer: {0}")]
    InvalidSigner(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Signature operation failed: {0}")]
    SignatureOperationFailed(String),
    #[error("Signers file initialisation failed: {0}")]
    InitialisationError(String),
    #[error("Aggregate signature error: {0}")]
    AggregateSignatureError(#[from] AggregateSignatureError),
    #[error("Signers file not in a pending signers directory: {0}")]
    NotInPendingDir(String),
    #[error("Pending signers file filesystem hierarchy error: {0}")]
    FileSystemHierarchyError(String),
}

impl From<SignatureError> for SignersFileError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::IoError(io_err) => SignersFileError::IoError(io_err),
            SignatureError::JsonError(json_err) => SignersFileError::JsonError(json_err),
            other => SignersFileError::SignatureOperationFailed(other.to_string()),
        }
    }
}

pub mod keys {
    use std::path::PathBuf;

    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum KeyError {
        #[error("Key creation failed: {0}")]
        CreationFailed(String),
        #[error("Keypair fs io error")]
        IOError(#[from] std::io::Error),
        #[error("Refusing to overwrite existing files")]
        NotOverwriting(String),
    }

    #[derive(Error, Debug)]
    pub enum SignError {
        #[error("Signature failed: {0}")]
        SignatureFailed(String),
    }

    #[derive(Error, Debug)]
    pub enum VerifyError {
        #[error("Verification failed: {0}")]
        VerificationFailed(String),
    }

    #[derive(Error, Debug)]
    pub enum SignatureError {
        #[error("Error reading signature: {0}")]
        FormatError(String),
        #[error("base64 decoding of signature failed")]
        Base64DecodeFailed(#[from] base64::DecodeError),
        #[error("Invalid Utf8 string")]
        Utf8DecodeFailed(#[from] std::str::Utf8Error),
        #[error("IO error: {0}")]
        IoError(#[from] std::io::Error),
        #[error("JSON error: {0}")]
        JsonError(#[from] serde_json::Error),
        #[error("Attempting to add wrong signature to aggregate for file: {0}")]
        InvalidSignatureForAggregate(PathBuf),
    }

    impl From<minisign::PError> for KeyError {
        fn from(e: minisign::PError) -> Self {
            match e.kind() {
                minisign::ErrorKind::Io => KeyError::IOError(std::io::Error::other(e)),
                _ => KeyError::CreationFailed(e.to_string()),
            }
        }
    }

    impl From<minisign::PError> for SignError {
        fn from(e: minisign::PError) -> Self {
            SignError::SignatureFailed(e.to_string())
        }
    }

    impl From<minisign::PError> for VerifyError {
        fn from(e: minisign::PError) -> Self {
            VerifyError::VerificationFailed(e.to_string())
        }
    }

    impl From<minisign::PError> for SignatureError {
        fn from(e: minisign::PError) -> Self {
            match e.kind() {
                minisign::ErrorKind::Io => SignatureError::IoError(std::io::Error::other(e)),
                _ => SignatureError::FormatError(e.to_string()),
            }
        }
    }
}
use keys::*;
