use core::fmt;
use std::{fs, path::Path};

use chrono::{DateTime, Utc};
use common::{AsfaloadHashes, errors::RevocationError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use signatures::keys::AsfaloadPublicKeyTrait;

#[derive(Debug, Clone)]
pub struct RevocationFile<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    /// ISO8601 formatted UTC date and time when the revocation was created
    pub timestamp: DateTime<Utc>,
    /// digest of the file being revoked
    pub subject_digest: AsfaloadHashes,
    pub initiator: APK,
}

impl<APK> RevocationFile<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    pub fn from_json(json: &str) -> Result<Self, RevocationError> {
        Ok(serde_json::from_str(json)?)
    }
    pub fn from_file<P: AsRef<Path>>(path_in: P) -> Result<Self, RevocationError> {
        let json = fs::read_to_string(path_in.as_ref())?;
        Self::from_json(json.as_str())
    }
}
impl<APK> Serialize for RevocationFile<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RevocationFile", 3)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("subject_digest", &self.subject_digest)?;
        // Convert public key to base64 string for serialization
        state.serialize_field("initiator", &self.initiator.to_base64())?;
        state.end()
    }
}

impl<'de, APK> Deserialize<'de> for RevocationFile<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RevocationFileHelper {
            timestamp: DateTime<Utc>,
            subject_digest: AsfaloadHashes,
            initiator: String,
        }

        let helper = RevocationFileHelper::deserialize(deserializer)?;
        // Parse public key from base64 string
        let initiator = APK::from_base64(helper.initiator)
            .map_err(|e| serde::de::Error::custom(format!("Failed to parse public key: {}", e)))?;
        Ok(RevocationFile {
            timestamp: helper.timestamp,
            subject_digest: helper.subject_digest,
            initiator,
        })
    }
}

// Add a Display implementation for easier debugging
impl<APK> fmt::Display for RevocationFile<APK>
where
    APK: AsfaloadPublicKeyTrait,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RevocationFile(timestamp={}, subject_digest={}, initiator={})",
            self.timestamp,
            self.subject_digest,
            self.initiator.to_base64()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use common::AsfaloadHashes;
    use serde_json;
    use sha2::{Digest, Sha512};
    use signatures::keys::{AsfaloadPublicKey, AsfaloadPublicKeyTrait};
    use test_helpers::TestKeys;

    fn create_test_revocation_file<APK: AsfaloadPublicKeyTrait>(
        timestamp: DateTime<Utc>,
        subject_digest: AsfaloadHashes,
        initiator: APK,
    ) -> RevocationFile<APK> {
        RevocationFile {
            timestamp,
            subject_digest,
            initiator,
        }
    }

    #[test]
    fn test_serialization_and_deserialization() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let timestamp = Utc::now();
        let subject_digest = AsfaloadHashes::Sha512([1u8; 64].into());

        let revocation_file =
            create_test_revocation_file(timestamp, subject_digest.clone(), pubkey.clone());

        // Serialize to JSON
        let json = serde_json::to_string(&revocation_file).unwrap();

        // Deserialize back
        let deserialized: RevocationFile<AsfaloadPublicKey<minisign::PublicKey>> =
            serde_json::from_str(&json).unwrap();

        // Verify all fields match
        assert_eq!(&deserialized.timestamp, &timestamp);
        assert_eq!(&deserialized.subject_digest, &subject_digest);
        assert_eq!(deserialized.initiator.to_base64(), pubkey.to_base64());
    }

    #[test]
    fn test_serialization_format() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let timestamp = "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let subject_digest = AsfaloadHashes::Sha512([1u8; 64].into());

        let revocation_file = create_test_revocation_file(timestamp, subject_digest, pubkey);

        let json = serde_json::to_string_pretty(&revocation_file).unwrap();

        // Verify JSON structure
        assert!(json.contains("\"timestamp\""));
        assert!(json.contains("\"subject_digest\""));
        assert!(json.contains("\"initiator\""));

        // Verify timestamp format
        assert!(json.contains("2023-01-01T00:00:00Z"));

        // Verify subject digest format
        assert!(json.contains("\"sha512:"));

        // Verify initiator is base64
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let initiator = parsed.get("initiator").unwrap().as_str().unwrap();
        assert!(
            initiator
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        );
    }

    #[test]
    fn test_real_sha512_hash_serialization() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let timestamp = Utc::now();

        // Create a real SHA512 hash from actual data
        let test_data = b"This is test data for revocation";
        let hash = Sha512::digest(test_data);
        let subject_digest = AsfaloadHashes::Sha512(hash);

        let revocation_file = create_test_revocation_file(timestamp, subject_digest, pubkey);

        // Serialize and deserialize
        let json = serde_json::to_string(&revocation_file).unwrap();
        let deserialized: RevocationFile<AsfaloadPublicKey<minisign::PublicKey>> =
            serde_json::from_str(&json).unwrap();

        // Verify the hash is preserved correctly
        match (
            &revocation_file.subject_digest,
            &deserialized.subject_digest,
        ) {
            (AsfaloadHashes::Sha512(h1), AsfaloadHashes::Sha512(h2)) => {
                assert_eq!(h1, h2);
            }
        }
    }

    #[test]
    fn test_invalid_base64_initiator() {
        let invalid_json = r#"
        {
            "timestamp": "2023-01-01T00:00:00Z",
            "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "initiator": "This is not valid base64!"
        }
        "#;

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(invalid_json);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse public key"));
    }

    #[test]
    fn test_invalid_subject_digest_format() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let pubkey_b64 = pubkey.to_base64();

        // Invalid hash format (wrong length)
        let invalid_json = format!(
            r#"{{
                "timestamp": "2023-01-01T00:00:00Z",
                "subject_digest": "sha512:aaaa",
                "initiator": "{}"
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&invalid_json);

        assert!(result.is_err());
        let error = result.unwrap_err();
        // The error might come from AsfaloadHashes deserialization
        assert!(
            error.to_string().contains("SHA512 must be 64 bytes")
                || error.to_string().contains("Invalid format")
        );
    }

    #[test]
    fn test_invalid_timestamp_format() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let pubkey_b64 = pubkey.to_base64();

        let invalid_json = format!(
            r#"{{
                "timestamp": "Not a valid timestamp",
                "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "initiator": "{}"
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&invalid_json);

        assert!(result.is_err());
        let error = result.unwrap_err();
        dbg!(&error);
        assert!(
            error
                .to_string()
                .contains("input contains invalid characters")
        );
    }

    #[test]
    fn test_missing_fields() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let pubkey_b64 = pubkey.to_base64();

        // Missing timestamp
        let missing_timestamp = format!(
            r#"{{
                "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "initiator": "{}"
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&missing_timestamp);
        assert!(result.is_err());

        match result {
            Err(ref e) => {
                assert!(e.to_string().contains("missing field `timestamp`"))
            }
            Ok(_) => {
                panic!("Expected missing field `timestamp`")
            }
        }
        // Missing subject_digest
        let missing_digest = format!(
            r#"{{
                "timestamp": "2023-01-01T00:00:00Z",
                "initiator": "{}"
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&missing_digest);
        match result {
            Err(ref e) => {
                assert!(e.to_string().contains("missing field `subject_digest`"))
            }
            Ok(_) => {
                panic!("Expected missing field `subject_digest`")
            }
        }

        // Missing initiator
        let missing_initiator = r#"
        {
            "timestamp": "2023-01-01T00:00:00Z",
            "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
        "#;

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(missing_initiator);
        match result {
            Err(ref e) => {
                assert!(e.to_string().contains("missing field `initiator`"))
            }
            Ok(_) => {
                panic!("Expected missing field `initiator`")
            }
        }

        // Empty timestamp
        let empty_timestamp = format!(
            r#"{{
                "timestamp": "",
                "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "initiator": "{}"
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&empty_timestamp);
        assert!(result.is_err());

        match result {
            Err(ref e) => {
                dbg!(e.to_string());
                assert!(e.to_string().contains("premature end of input"))
            }
            Ok(_) => {
                panic!("premature end of input")
            }
        }
        // Empty initiator
        let empty_initiator = r#"
        {
            "timestamp": "2023-01-01T00:00:00Z",
            "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "initiator": ""
        }
        "#;

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(empty_initiator);
        match result {
            Err(ref e) => {
                dbg!(e.to_string());
                assert!(
                    e.to_string()
                        .contains("Failed to parse public key: Keypair fs io error")
                )
            }
            Ok(_) => {
                panic!("Failed to parse public key: Keypair fs io error")
            }
        }
    }

    #[test]
    fn test_round_trip_multiple_revocation_files() {
        let test_keys = TestKeys::new(3);

        let mut revocation_files = Vec::new();

        for i in 0..3 {
            let pubkey = test_keys.pub_key(i).unwrap().clone();
            let timestamp = Utc::now() + chrono::Duration::seconds(i as i64);
            let hash_data = format!("test data {}", i);
            let hash = Sha512::digest(hash_data.as_bytes());
            let subject_digest = AsfaloadHashes::Sha512(hash);

            let revocation = create_test_revocation_file(timestamp, subject_digest, pubkey);
            revocation_files.push(revocation);
        }

        // Test each revocation file independently
        for revocation in &revocation_files {
            let json = serde_json::to_string(revocation).unwrap();
            let deserialized: RevocationFile<AsfaloadPublicKey<minisign::PublicKey>> =
                serde_json::from_str(&json).unwrap();

            assert_eq!(revocation.timestamp, deserialized.timestamp);
            assert_eq!(revocation.subject_digest, deserialized.subject_digest);
            assert_eq!(
                revocation.initiator.to_base64(),
                deserialized.initiator.to_base64()
            );
        }
    }

    #[test]
    fn test_verify_serialization_structure() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();

        let timestamp = "2023-01-01T12:34:56.789Z".parse::<DateTime<Utc>>().unwrap();
        let subject_digest = AsfaloadHashes::Sha512([0xFFu8; 64].into());

        let revocation_file = create_test_revocation_file(timestamp, subject_digest, pubkey);

        let json = serde_json::to_string(&revocation_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Check the exact structure
        assert!(parsed.is_object());
        let obj = parsed.as_object().unwrap();

        assert!(obj.contains_key("timestamp"));
        assert!(obj.contains_key("subject_digest"));
        assert!(obj.contains_key("initiator"));

        assert_eq!(obj.len(), 3); // Exactly 3 fields

        // Check types
        assert!(obj["timestamp"].is_string());
        assert!(obj["subject_digest"].is_string());
        assert!(obj["initiator"].is_string());
    }

    #[test]
    fn test_deserialize_with_extra_fields() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let pubkey_b64 = pubkey.to_base64();

        let json_with_extra = format!(
            r#"{{
                "timestamp": "2023-01-01T00:00:00Z",
                "subject_digest": "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "initiator": "{}",
                "extra_field": "should be ignored",
                "another_extra": 123
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&json_with_extra);

        // Should succeed with extra fields being ignored
        assert!(result.is_ok());
    }

    #[test]
    fn test_different_hash_algorithms_error() {
        let test_keys = TestKeys::new(1);
        let pubkey = test_keys.pub_key(0).unwrap().clone();
        let pubkey_b64 = pubkey.to_base64();

        // Try to use an unsupported hash algorithm
        let json_wrong_algo = format!(
            r#"{{
                "timestamp": "2023-01-01T00:00:00Z",
                "subject_digest": "md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "initiator": "{}"
            }}"#,
            pubkey_b64
        );

        let result: Result<RevocationFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            serde_json::from_str(&json_wrong_algo);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Unsupported hash algorithm")
                || error.to_string().contains("Invalid format")
        );
    }
}
