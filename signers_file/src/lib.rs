use minisign;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use signatures::keys::{AsfaloadPublicKey, AsfaloadPublicKeyTrait};
use std::fmt; // Required for minisign::PublicKey::from_base64 and its Error type
use std::fs;
use std::io::Write;
use std::path::Path;
use thiserror::Error;
//
// We set a bound in the serde annotation. Here why, as explained by AI:
// Without this bound, we get the error `E0277` "the trait bound `P: _::_serde::Deserialize<'_>` is
// not satisfied" occurs because when `#[derive(Deserialize)]` is used on generic structs like
// `SignersConfig`, `SignerGroup`, and `Signer`, `serde` implicitly adds `P: Deserialize` and `P:
// Serialize` bounds to their generic parameter `P`.
// However, in this design, the actual deserialization and serialization of the generic `P` (which
// represents the public key) is handled manually within the `SignerData<P>`'s custom `impl
// Serialize` and `impl Deserialize` blocks, which only require `P: AsfaloadPublicKeyTrait`. `P`
// itself does not need to implement `serde::Deserialize` or `serde::Serialize` directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct SignersConfig<P: AsfaloadPublicKeyTrait> {
    pub version: u32,
    pub initial_version: InitialVersion,
    pub artifact_signers: Vec<SignerGroup<P>>,
    pub master_keys: Vec<SignerGroup<P>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_keys: Option<Vec<SignerGroup<P>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialVersion {
    pub permalink: String,
    #[serde(default)]
    pub mirrors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct SignerGroup<P: AsfaloadPublicKeyTrait> {
    pub signers: Vec<Signer<P>>,
    pub threshold: u32,
}

// Custom deserializer for SignerGroup that validates threshold <= signers.len()
impl<'de, P> Deserialize<'de> for SignerGroup<P>
where
    P: AsfaloadPublicKeyTrait,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a helper struct that mirrors SignerGroup but without the custom Deserialize
        #[derive(Deserialize)]
        #[serde(bound(deserialize = "P: AsfaloadPublicKeyTrait"))]
        struct SignerGroupHelper<P: AsfaloadPublicKeyTrait> {
            signers: Vec<Signer<P>>,
            threshold: u32,
        }

        // Deserialize into the helper struct
        let helper = SignerGroupHelper::deserialize(deserializer)?;

        // Validate that threshold > 0
        if helper.threshold == 0 {
            return Err(serde::de::Error::custom(format!(
                "Threshold ({}) must be strictly greater than 0",
                helper.threshold,
            )));
        }
        // Validate that threshold <= signers.len()
        if helper.threshold > helper.signers.len() as u32 {
            return Err(serde::de::Error::custom(format!(
                "Threshold ({}) cannot be greater than the number of signers ({})",
                helper.threshold,
                helper.signers.len()
            )));
        }

        // If validation passes, create the actual SignerGroup
        Ok(SignerGroup {
            signers: helper.signers,
            threshold: helper.threshold,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct Signer<P: AsfaloadPublicKeyTrait> {
    pub kind: SignerKind,
    pub data: SignerData<P>, // Specify the concrete type here
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignerKind {
    Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerData<P: AsfaloadPublicKeyTrait> {
    pub format: KeyFormat,
    pub pubkey: P,
}

impl<P> Serialize for SignerData<P>
where
    P: AsfaloadPublicKeyTrait,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SignerData", 2)?;
        state.serialize_field("format", &self.format)?;
        // Convert the public key to its string representation using the trait method
        state.serialize_field("pubkey", &self.pubkey.to_base64())?;
        state.end()
    }
}

impl<'de, P> Deserialize<'de> for SignerData<P>
where
    P: AsfaloadPublicKeyTrait,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SignerDataHelper {
            format: KeyFormat,
            pubkey: String,
        }

        let helper = SignerDataHelper::deserialize(deserializer)?;
        // Parse the public key from string using the trait method
        let pubkey = P::from_base64(helper.pubkey.clone()).map_err(|_e| {
            serde::de::Error::custom(format!("Problem parsing pubkey base64: {}", helper.pubkey))
        })?;
        Ok(SignerData {
            format: helper.format,
            pubkey,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyFormat {
    Minisign,
}

pub fn parse_signers_config<P: AsfaloadPublicKeyTrait>(
    json_str: &str,
) -> Result<SignersConfig<P>, serde_json::Error> {
    serde_json::from_str(json_str)
}
#[derive(Debug, Error)]
pub enum SignersFileError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Initialize a signers file in a specific directory.
///
/// This function validates the provided JSON content by deserializing it into a SignersConfig,
/// then creates a pending signers file named "asfaload.signers.json.pending" in the specified directory.
///
/// # Arguments
/// * `dir_path` - The directory where the signers file should be created
/// * `json_content` - The JSON content of the signers configuration
///
/// # Returns
/// * `Ok(())` if the pending file was successfully created
/// * `Err(SignersFileError)` if there was an error validating the JSON or writing the file
pub fn initialize_signers_file<P: AsRef<Path>>(
    dir_path: P,
    json_content: &str,
) -> Result<(), SignersFileError> {
    // First, validate the JSON by parsing it
    let _config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
        parse_signers_config(json_content)?;

    // Create the pending file path
    let pending_file_path = dir_path.as_ref().join("asfaload.signers.json.pending");

    // Write the JSON content to the pending file
    let mut file = fs::File::create(&pending_file_path)?;
    file.write_all(json_content.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parsing() {
        let json_str = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTsbRMhBdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyv"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWSNbF6ZeLYJLBOKm8a2QbbSb3U+K4ag1YJENgvRXfKEC6RqICqYF+NE"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "R4DM1NJ1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "R4DM1NL285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "R4DM1NN3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(json_str).expect("Failed to parse JSON");
        assert_eq!(config.version, 1);
        assert_eq!(
            config.initial_version.permalink,
            "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json"
        );
        assert_eq!(config.artifact_signers.len(), 1);
        assert_eq!(config.artifact_signers[0].threshold, 2);
        assert_eq!(config.artifact_signers[0].signers[0].kind, SignerKind::Key);
        assert_eq!(
            config.artifact_signers[0].signers[0].data.format,
            KeyFormat::Minisign
        );
        assert_eq!(config.master_keys.len(), 1);
        assert_eq!(config.master_keys[0].threshold, 2);
        assert_eq!(config.master_keys[0].signers[0].kind, SignerKind::Key);
        assert!(config.admin_keys.is_some());
        let admin_keys = config
            .admin_keys
            .as_ref()
            .expect("admin_keys should be present");
        assert_eq!(admin_keys[0].threshold, 2);
        assert_eq!(admin_keys[0].signers[0].kind, SignerKind::Key);

        let json_str_with_invalid_b64_keys = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTsbRMhBdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyvinvalid"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWSNbF6ZeLYJLBOKm8a2QbbSb3U+K4ag1YJENgvRXfKEC6RqICqYF+NE"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let config: Result<
            SignersConfig<AsfaloadPublicKey<minisign::PublicKey>>,
            serde_json::Error,
        > = parse_signers_config(json_str_with_invalid_b64_keys);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert_eq!(
            error.to_string(),
            "Problem parsing pubkey base64: RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyvinvalid at line 12 column 139"
        );

        // Test the threshold validation
        let json_str_with_invalid_threshold = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTsbRMhBdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyv"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWSNbF6ZeLYJLBOKm8a2QbbSb3U+K4ag1YJENgvRXfKEC6RqICqYF+NE"} }
          ],
          "threshold": 4
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let config: Result<
            SignersConfig<AsfaloadPublicKey<minisign::PublicKey>>,
            serde_json::Error,
        > = parse_signers_config(json_str_with_invalid_threshold);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error
                .to_string()
                .starts_with("Threshold (4) cannot be greater than the number of signers (3)")
        );
        let json_str_with_zero_threshold = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
          ],
          "threshold": 0
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;
        let config: Result<
            SignersConfig<AsfaloadPublicKey<minisign::PublicKey>>,
            serde_json::Error,
        > = parse_signers_config(json_str_with_zero_threshold);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error
                .to_string()
                .starts_with("Threshold (0) must be strictly greater than 0")
        );
    }
    #[test]
    fn test_initialize_signers_file() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Example JSON content (from the existing test)
        let json_content = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTsbRMhBdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;

        // Call the function
        initialize_signers_file(dir_path, json_content).unwrap();

        // Check that the pending file exists
        let pending_file_path = dir_path.join("asfaload.signers.json.pending");
        assert!(pending_file_path.exists());

        // Check the content
        let content = fs::read_to_string(pending_file_path).unwrap();
        // We don't compare exactly because of formatting, but we can parse it again to validate
        let _config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(&content).unwrap();
    }

    #[test]
    fn test_initialize_signers_file_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let invalid_json_content = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "INVALID_BASE64" } }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;

        // Call the function - should fail due to invalid base64
        let result = initialize_signers_file(dir_path, invalid_json_content);
        assert!(result.is_err());
        assert!(matches!(result, Err(SignersFileError::JsonError(_))));

        // Ensure the pending file was not created
        let pending_file_path = dir_path.join("asfaload.signers.json.pending");
        assert!(!pending_file_path.exists());

        // Test valid json but invalid destination directory
        let valid_json_content = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTsbRMhBdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;
        let result = initialize_signers_file("/tmp/inexisting_path_fsdfd", valid_json_content);
        assert!(result.is_err());
        assert!(matches!(result, Err(SignersFileError::IoError(_))));
    }
}
