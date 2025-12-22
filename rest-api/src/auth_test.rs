// Simple test to verify authentication functionality
#[cfg(test)]
mod tests {
    use super::*;
    use rest_api_auth::{AuthInfo, AuthSignature};
    use features_lib::{AsfaloadSecretKeys, AsfaloadKeyPairs};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_auth_validation() {
        // Create a test payload
        let payload = r#"{"file_path": "test.txt", "content": "Hello World"}"#;
        
        // Create authentication info
        let auth_info = AuthInfo::new(payload.to_string());
        
        // Create a test key (this would normally come from a file)
        let test_password = "test_password";
        let key_pair = AsfaloadKeyPairs::new(test_password).unwrap();
        let secret_key = key_pair.secret_key(test_password).unwrap();
        
        // Create authentication signature
        let auth_signature = AuthSignature::new(auth_info.clone(), secret_key).unwrap();
        
        // Test validation
        let result = AuthSignature::validate_from_headers(
            &auth_info.timestamp().to_rfc3339(),
            &auth_info.nonce(),
            &auth_signature.signature().to_base64(),
            &auth_signature.public_key(),
            payload,
        );
        
        assert!(result.is_ok(), "Authentication validation should succeed");
    }
}