use chrono::{DateTime, Utc};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    AsfaloadSignatureTrait, AsfaloadSignatures,
    errors::keys::{KeyError, SignError, SignatureError, VerifyError},
    sha512_for_content,
};
use thiserror::Error;
use uuid::Uuid;

// we accept timestamps that are at most this far in the furture to account for
// client clock skews
pub const CLIENT_CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 10;
pub const AUTH_SIGNATURE_VALIDITY_MINUTES: i64 = 5;
pub const HEADER_TIMESTAMP: &str = "X-asfld-timestamp";
pub const HEADER_NONCE: &str = "X-asfld-nonce";
pub const HEADER_SIGNATURE: &str = "X-asfld-sig";
pub const HEADER_PUBLIC_KEY: &str = "X-asfld-pk";

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Auth data preparation error: {0}")]
    AuthDataPreparationError(String),

    #[error("Auth io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Auth signing error: {0}")]
    SigningError(#[from] SignError),

    #[error("Auth key error: {0}")]
    KeyError(#[from] KeyError),

    #[error("Auth verification error: {0}")]
    VerificationError(#[from] VerifyError),

    #[error("Auth signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("Missing required header: {0}")]
    MissingHeader(String),

    #[error("Invalid timestamp format: {0}")]
    InvalidTimestampFormat(#[from] chrono::ParseError),

    #[error("Invalid nonce format: {0}")]
    InvalidNonceFormat(#[from] uuid::Error),

    #[error("Timestamp too old")]
    TimestampTooOld,

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),
}

// Struct holding information that will be used in authentication
// by rest clients and servers
#[derive(Clone)]
pub struct AuthInfo {
    // Will be set by client as X-asfld-timestamp
    timestamp: DateTime<Utc>,
    // Will be set by client as X-asfld-nonce
    nonce: Uuid,
    // Is the payload sent by the client to the server
    payload: String,
}

pub struct AuthSignature {
    auth_info: AuthInfo,
    // Will be set by client as X-asfld-sig
    signature: AsfaloadSignatures,
    // Will be set by client as X-asfld-pk
    public_key: AsfaloadPublicKeys,
}

impl AuthInfo {
    pub fn new(payload: String) -> Self {
        let nonce = Uuid::new_v4();
        let timestamp = chrono::Utc::now();
        AuthInfo {
            timestamp,
            nonce,
            payload,
        }
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    pub fn nonce(&self) -> String {
        self.nonce.to_string()
    }
}

impl AuthSignature {
    pub fn new(auth_info: AuthInfo, secret_key: AsfaloadSecretKeys) -> Result<Self, AuthError> {
        let hash = sha512_for_content(auth_info.to_string().as_bytes().to_vec())?;
        let signature = secret_key.sign(&hash)?;
        let public_key = AsfaloadPublicKeys::from_secret_key(secret_key)?;
        Ok(AuthSignature {
            auth_info,
            signature,
            public_key,
        })
    }

    /// Validate authentication headers and signature
    pub fn validate_from_headers(
        timestamp: &str,
        nonce: &str,
        signature: &str,
        public_key: &str,
        payload: &str,
    ) -> Result<(), AuthError> {
        // Parse timestamp
        let timestamp = DateTime::parse_from_rfc3339(timestamp)?.with_timezone(&Utc);
        // Validate timestamp (e.g., not older than 5 minutes)
        let now = Utc::now();
        if now.signed_duration_since(timestamp).num_minutes() > AUTH_SIGNATURE_VALIDITY_MINUTES
            || timestamp > (now + chrono::Duration::seconds(CLIENT_CLOCK_SKEW_TOLERANCE_SECONDS))
        {
            return Err(AuthError::TimestampTooOld);
        }

        // Parse nonce
        let nonce = Uuid::parse_str(nonce)?;

        // Recreate AuthInfo
        let auth_info = AuthInfo {
            timestamp,
            nonce,
            payload: payload.to_string(),
        };

        // Parse public key and signature
        let public_key = AsfaloadPublicKeys::from_base64(public_key.to_string())?;
        let signature = AsfaloadSignatures::from_base64(signature)?;

        // Verify signature
        let hash = sha512_for_content(auth_info.to_string().as_bytes().to_vec())?;
        public_key.verify(&signature, &hash)?;

        Ok(())
    }

    pub fn auth_info(&self) -> AuthInfo {
        self.auth_info.clone()
    }
    pub fn signature(&self) -> AsfaloadSignatures {
        self.signature.clone()
    }
    pub fn public_key(&self) -> String {
        self.public_key.to_base64()
    }
}

impl std::fmt::Display for AuthInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}##{}##{}",
            self.timestamp.to_rfc3339(),
            self.nonce,
            self.payload
        )
    }
}
