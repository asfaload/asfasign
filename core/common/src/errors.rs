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
    #[error("File not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Signature error: {0}")]
    Signature(String),
    #[error("File error: {0}")]
    FileError(String),
    #[error("Signers config error: {0}")]
    SignersConfigError(#[from] SignersConfigError),
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
    #[error("Duplicate signature: this key has already signed")]
    DuplicateSignature,
    #[error("Revocation error: {0}")]
    RevocationError(#[from] RevocationError),
    #[error("Signers config error: {0}")]
    SignersConfigError(#[from] SignersConfigError),
}

#[derive(Debug, Error)]
pub enum SignersConfigError {
    #[error("Key error: {0}")]
    KeyError(#[from] keys::KeyError),
    #[error("Invalid Signer group: {0}")]
    GroupError(String),
    #[error("Master key {key} also appears in another group")]
    MasterKeyInOtherGroup { key: String },
    #[error("Serialisation error: {0}")]
    SerialisationError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
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
    #[error("Signers chain validation failed: {0}")]
    ChainValidationFailed(String),
    #[error("Signers config error: {0}")]
    SignersConfigError(#[from] SignersConfigError),
}

#[derive(Debug, Error)]
pub enum SignersChainError {
    #[error("Current Signers not found")]
    CurrentNotFound,
    #[error("Initial signers file validation failed: {0}")]
    GenesisEntryError(String),
    #[error("Chain ordering error: {0}")]
    ChainOrderingError(String),
    #[error("Signers Chain error: {0}")]
    GenericError(String),
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
        #[error("Error: {0}")]
        GenericError(String),
        #[error("asfaload format error: {0}")]
        AsfaloadFormat(String),
        #[error("Cannot create a key of this format: {0}")]
        ImportOnlyFormat(String),
        #[error("Does not recognise this key format: {0}")]
        FormatError(String),
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
        #[error("Duplicate signature: this key has already signed")]
        DuplicateSignature,
        #[error("File has been revoked: {0}")]
        FileRevoked(PathBuf),
    }

    impl From<ed25519_dalek::SignatureError> for KeyError {
        fn from(e: ed25519_dalek::SignatureError) -> Self {
            KeyError::CreationFailed(e.to_string())
        }
    }

    impl From<ed25519_dalek::SignatureError> for SignError {
        fn from(e: ed25519_dalek::SignatureError) -> Self {
            SignError::SignatureFailed(e.to_string())
        }
    }

    impl From<ed25519_dalek::SignatureError> for VerifyError {
        fn from(e: ed25519_dalek::SignatureError) -> Self {
            VerifyError::VerificationFailed(e.to_string())
        }
    }

    impl From<ed25519_dalek::SignatureError> for SignatureError {
        fn from(e: ed25519_dalek::SignatureError) -> Self {
            SignatureError::FormatError(e.to_string())
        }
    }
}
use keys::*;
