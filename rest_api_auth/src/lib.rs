use chrono::{DateTime, Utc};
use common::errors::keys::{KeyError, SignError, SignatureError, VerifyError};
use common::sha512_for_content;
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};
use signatures::types::{AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatures};
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

    #[error("Timestamp invalid: {0}")]
    TimestampInvalid(String),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),
}

// Struct holding information that will be used in authentication
// by rest clients and servers
#[derive(Clone)]
pub struct AuthInfo {
    // Will be set by client as HEADER_TIMESTAMP
    timestamp: DateTime<Utc>,
    // Will be set by client as HEADER_NONCE
    nonce: Uuid,
    // Is the payload sent by the client to the server
    payload: String,
}

pub struct AuthSignature {
    auth_info: AuthInfo,
    // Will be set by client as HEADER_SIGNATURE
    signature: AsfaloadSignatures,
    // Will be set by client as HEADER_PUBLIC_KEY
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
    pub fn new(auth_info: &AuthInfo, secret_key: &AsfaloadSecretKeys) -> Result<Self, AuthError> {
        let hash = sha512_for_content(auth_info.to_string().as_bytes().to_vec())?;
        let signature = secret_key.sign(&hash)?;
        let public_key = AsfaloadPublicKeys::from_secret_key(secret_key)?;
        Ok(AuthSignature {
            auth_info: auth_info.clone(),
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
            return Err(AuthError::TimestampInvalid(timestamp.to_string()));
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
        let public_key = AsfaloadPublicKeys::from_base64(public_key)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use lazy_static::lazy_static;
    use signatures::keys::AsfaloadKeyPairTrait;
    use signatures::types::AsfaloadKeyPairs;

    // Shared test password
    const TEST_PASSWORD: &str = "test_password";

    // Create a single keypair that will be reused across all tests
    lazy_static! {
        static ref TEST_KEY_PAIR: AsfaloadKeyPairs = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    }

    lazy_static! {
        static ref TEST_KEY: AsfaloadSecretKeys = TEST_KEY_PAIR.secret_key(TEST_PASSWORD).unwrap();
    }
    fn setup_test_data() -> (AuthInfo, AuthSignature, String) {
        let payload = r#"{"file_path": "test.txt", "content": "Hello World"}"#;
        let auth_info = AuthInfo::new(payload.to_string());
        let auth_signature = AuthSignature::new(&auth_info, &TEST_KEY).unwrap();

        (auth_info, auth_signature, payload.to_string())
    }

    #[test]
    fn test_validate_from_headers_success() {
        let (auth_info, auth_signature, payload) = setup_test_data();

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            &payload,
        );

        assert!(
            result.is_ok(),
            "Validation should succeed with correct headers"
        );
    }

    #[test]
    fn test_validate_from_headers_wrong_payload() {
        let (auth_info, auth_signature, _) = setup_test_data();
        let wrong_payload = r#"{"file_path": "wrong.txt", "content": "Wrong Content"}"#;

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            wrong_payload,
        );

        assert!(result.is_err(), "Validation should fail with wrong payload");
        assert!(matches!(
            result.unwrap_err(),
            AuthError::VerificationError(_)
        ));
    }

    #[test]
    fn test_validate_from_headers_wrong_signature() {
        let (auth_info, auth_signature, payload) = setup_test_data();
        let wrong_signature = "wrong_signature_base64";

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            wrong_signature,
            &auth_signature.public_key(),
            &payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with wrong signature"
        );
    }

    #[test]
    fn test_validate_from_headers_wrong_public_key() {
        let (auth_info, auth_signature, payload) = setup_test_data();
        let wrong_public_key = "wrong_public_key_base64";

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            wrong_public_key,
            &payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with wrong public key"
        );
    }

    #[test]
    fn test_validate_from_headers_old_timestamp() {
        let payload = r#"{"file_path": "test.txt", "content": "Hello World"}"#;

        // Create a timestamp that's too old (more than 5 minutes)
        let old_timestamp = Utc::now() - Duration::minutes(AUTH_SIGNATURE_VALIDITY_MINUTES * 2);
        let nonce = uuid::Uuid::new_v4();

        // Create auth info with the old timestamp
        let auth_info = AuthInfo {
            timestamp: old_timestamp,
            nonce,
            payload: payload.to_string(),
        };

        // Create a signature for this specific old timestamp using the shared keypair
        let secret_key = TEST_KEY_PAIR.secret_key(TEST_PASSWORD).unwrap();
        let auth_signature = AuthSignature::new(&auth_info, &secret_key).unwrap();

        let result = AuthSignature::validate_from_headers(
            &old_timestamp.to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            payload,
        );

        assert!(result.is_err(), "Validation should fail with old timestamp");
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::TimestampInvalid(_)));
    }

    #[test]
    fn test_validate_from_headers_future_timestamp() {
        let payload = r#"{"file_path": "test.txt", "content": "Hello World"}"#;

        // Create a timestamp that's in the future
        let future_timestamp = Utc::now() + Duration::seconds(70);
        let nonce = uuid::Uuid::new_v4();

        // Create auth info with the old timestamp
        let auth_info = AuthInfo {
            timestamp: future_timestamp,
            nonce,
            payload: payload.to_string(),
        };

        // Create a signature for this specific old timestamp using the shared keypair
        let secret_key = TEST_KEY_PAIR.secret_key(TEST_PASSWORD).unwrap();
        let auth_signature = AuthSignature::new(&auth_info, &secret_key).unwrap();

        let result = AuthSignature::validate_from_headers(
            &future_timestamp.to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with future timestamp"
        );
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::TimestampInvalid(_)));
    }

    #[test]
    fn test_validate_from_headers_invalid_timestamp_format() {
        let (auth_info, auth_signature, payload) = setup_test_data();
        let invalid_timestamp = "invalid-timestamp-format";

        let result = AuthSignature::validate_from_headers(
            invalid_timestamp,
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            &payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with invalid timestamp format"
        );
        assert!(matches!(
            result.unwrap_err(),
            AuthError::InvalidTimestampFormat(_)
        ));
    }

    #[test]
    fn test_validate_from_headers_invalid_nonce_format() {
        let (auth_info, auth_signature, payload) = setup_test_data();
        let invalid_nonce = "invalid-nonce-format";

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            invalid_nonce,
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            &payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with invalid nonce format"
        );
        assert!(matches!(
            result.unwrap_err(),
            AuthError::InvalidNonceFormat(_)
        ));
    }

    #[test]
    fn test_validate_from_headers_invalid_base64_signature() {
        let (auth_info, auth_signature, payload) = setup_test_data();
        let invalid_signature = "invalid-base64-signature!";

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            invalid_signature,
            &auth_signature.public_key(),
            &payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with invalid base64 signature"
        );
        let err = result.unwrap_err();
        // The error should be a Base64DecodeError or SignatureError depending on the implementation
        assert!(
            matches!(err, AuthError::Base64DecodeError(_))
                || matches!(err, AuthError::SignatureError(_))
        );
    }

    #[test]
    fn test_validate_from_headers_invalid_base64_public_key() {
        let (auth_info, auth_signature, payload) = setup_test_data();
        let invalid_public_key = "invalid-base64-public-key!";

        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            invalid_public_key,
            &payload,
        );

        assert!(
            result.is_err(),
            "Validation should fail with invalid base64 public key"
        );
        let err = result.unwrap_err();
        // The error should be a Base64DecodeError or KeyError depending on the implementation
        assert!(
            matches!(err, AuthError::Base64DecodeError(_)) || matches!(err, AuthError::KeyError(_))
        );
    }

    #[test]
    fn test_validate_from_headers_recent_timestamp() {
        let (auth_info, _auth_signature, payload) = setup_test_data();

        // Create a timestamp that's recent (within 5 minutes)
        let recent_timestamp = Utc::now() - Duration::minutes(AUTH_SIGNATURE_VALIDITY_MINUTES / 2);

        // We need to recreate the auth signature with the new timestamp
        let new_auth_info = AuthInfo {
            timestamp: recent_timestamp,
            nonce: auth_info.nonce().parse().unwrap(),
            payload: payload.clone(),
        };

        // Use the shared keypair instead of creating a new one
        let secret_key = TEST_KEY_PAIR.secret_key(TEST_PASSWORD).unwrap();
        let new_auth_signature = AuthSignature::new(&new_auth_info, &secret_key).unwrap();

        let result = AuthSignature::validate_from_headers(
            &recent_timestamp.to_rfc3339(),
            &new_auth_info.nonce(),
            &new_auth_signature.signature().to_base64(),
            &new_auth_signature.public_key(),
            &payload,
        );

        assert!(
            result.is_ok(),
            "Validation should succeed with recent timestamp"
        );
    }
}
