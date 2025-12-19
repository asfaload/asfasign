use chrono::{DateTime, Utc};
use features_lib::{
    AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatures,
    errors::keys::{KeyError, SignError},
    sha512_for_content,
};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait};
use thiserror::Error;
use uuid::Uuid;

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
