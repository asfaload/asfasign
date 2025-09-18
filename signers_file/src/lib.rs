use common::fs::names::signatures_path_for;
use common::fs::names::{
    PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_FILE, pending_signatures_path_for,
};
use minisign;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512};
use signatures::keys::{AsfaloadPublicKey, AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
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
    // FIXME: make private, but causes trouble in tests of aggregate signature definitions
    pub admin_keys: Option<Vec<SignerGroup<P>>>,
}

impl<P> SignersConfig<P>
where
    P: AsfaloadPublicKeyTrait,
{
    pub fn admin_keys(&self) -> &Vec<SignerGroup<P>> {
        match &self.admin_keys {
            Some(v) if !v.is_empty() => v,
            _ => &self.artifact_signers,
        }
    }
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

        // Validate that we have at least one signer
        if helper.signers.is_empty() {
            return Err(serde::de::Error::custom("Group size must be at least 1"));
        }
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
    #[error("Invalid signer: {0}")]
    InvalidSigner(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Signature operation failed: {0}")]
    SignatureOperationFailed(String),
    #[error("Signers file initialisation failed: {0}")]
    InitialisationError(String),
}
/// Initialize a signers file in a specific directory.
///
/// This function validates the provided JSON content by deserializing it into a SignersConfig,
/// verifies that the provided signature is from a valid signer in the admin_signers group (if present)
/// or in the artifact_signers group (if admin_signers is not present), and verifies the signature
/// against the SHA-512 hash of the JSON content. If valid, it creates a pending signers file
/// named "asfaload.signers.json.pending" in the specified directory and adds the signature to
/// "asfaload.signatures.json.pending".
///
/// # Arguments
/// * `dir_path` - The directory where the pending signers file should be placed
/// * `json_content` - The JSON content of the signers configuration
/// * `signature` - The signature of the SHA-512 hash of the JSON content
/// * `pubkey` - The public key of the signer
///
/// # Returns
/// * `Ok(())` if the pending file was successfully created
/// * `Err(SignersFileError)` if there was an error validating the JSON, signature, or writing the file
pub fn initialize_signers_file<P: AsRef<Path>, S: signatures::keys::AsfaloadSignatureTrait, K>(
    dir_path_in: P,
    json_content: &str,
    signature: &S,
    pubkey: &K,
) -> Result<(), SignersFileError>
where
    K: AsfaloadPublicKeyTrait<Signature = S> + std::cmp::PartialEq,
{
    // Ensure we work in the right directory
    let dir_path = {
        let path = if dir_path_in.as_ref().ends_with(PENDING_SIGNERS_DIR) {
            dir_path_in.as_ref().to_path_buf()
        } else {
            dir_path_in.as_ref().join(PENDING_SIGNERS_DIR)
        };
        // Ensure directory exists
        std::fs::create_dir_all(&path)?;
        path
    };
    // If a signers file exists, we refuse to overwrite it
    let signers_file_path = dir_path.join(SIGNERS_FILE);
    if signers_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Signers file exists: {}",
            signers_file_path.to_string_lossy()
        )));
    }
    // If a pending signatures file already exists, we refuse to create a pending signers file.
    // We use the function not looking to disk content here, and check on disk ourselves.
    let pending_signature_file_path = pending_signatures_path_for(signers_file_path.clone())?;

    if pending_signature_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Pending signature file exists, refusing to initialise over it: {}",
            pending_signature_file_path.to_string_lossy()
        )));
    }
    // If a complete signatures file already exists, we refuse to create a pending signers file.
    // We use the function not looking to disk content here, and check on disk ourselves.
    let complete_signature_file_path = signatures_path_for(&signers_file_path)?;

    if complete_signature_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Complete signature file exists: {}",
            complete_signature_file_path.to_string_lossy()
        )));
    }
    // First, validate the JSON by parsing it
    let config: SignersConfig<K> = parse_signers_config(json_content)?;

    // Check that the signer is in the admin_signers group (equal to artifact signers of
    // admin group is not present in file)
    let is_valid_signer = config.admin_keys().iter().any(|group| {
        group
            .signers
            .iter()
            .any(|signer| signer.data.pubkey == *pubkey)
    });

    if !is_valid_signer {
        return Err(SignersFileError::InvalidSigner(
            "The provided public key is not in the admin_signers or artifact_signers groups"
                .to_string(),
        ));
    }

    // Compute the SHA-512 hash of the JSON content
    let mut hasher = Sha512::new();
    hasher.update(json_content.as_bytes());
    let hash_result = hasher.finalize();

    // Verify the signature against the hash
    pubkey.verify(signature, &hash_result).map_err(|e| {
        SignersFileError::SignatureVerificationFailed(format!(
            "Signature verification failed: {}",
            e
        ))
    })?;

    // Write the JSON content to the pending signers file
    let mut file = fs::File::create(&signers_file_path)?;
    file.write_all(json_content.as_bytes())?;

    // Add the signature to the aggregate signatures file
    signature
        .add_to_aggregate_for_file(signers_file_path, pubkey)
        .map_err(|e| {
            use signatures::keys::errs::SignatureError;
            match e {
                // As we write a new file here, no need to handle the JSonError as
                // it should not happen.
                SignatureError::IoError(io_err) => SignersFileError::IoError(io_err),
                other => SignersFileError::SignatureOperationFailed(other.to_string()),
            }
        })?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use common::fs::names::PENDING_SIGNATURES_SUFFIX;
    use common::fs::names::PENDING_SIGNERS_FILE;
    use signatures::keys::AsfaloadPublicKey;
    use signatures::keys::AsfaloadSecretKeyTrait;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

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
          "threshold": 3
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
        let admin_keys = config.admin_keys();
        assert_eq!(admin_keys[0].threshold, 3);
        assert_eq!(admin_keys[0].signers[0].kind, SignerKind::Key);

        // Check admin key are equal to artifact_signers if not set explicitly
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
          "threshold": 3
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
        let config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(json_str).expect("Failed to parse JSON");
        assert_eq!(config.version, 1);
        assert_eq!(
            config.initial_version.permalink,
            "https://raw.githubusercontent.com/asfaload/asfald/13e1a1cae656e8d4d04ec55fa33e802f560b6b5d/asfaload.initial_signers.json"
        );
        assert_eq!(config.artifact_signers.len(), 1);
        assert_eq!(config.artifact_signers[0].threshold, 3);
        assert_eq!(config.artifact_signers[0].signers[0].kind, SignerKind::Key);
        assert_eq!(
            config.artifact_signers[0].signers[0].data.format,
            KeyFormat::Minisign
        );
        let admin_keys = config.admin_keys();
        assert_eq!(admin_keys[0].threshold, 3);
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
        // Reject empty groups
        let json_str_with_empty_master_signers_group = r#"
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
          "threshold": 3
        }
      ],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R1BdOyL8hSYo/Z4nRD6O5OvrydjXWyvd8W7QOTftBOKSSn3PH3"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R3USBDoNYvpmoQFvCwzIqouUBYesr89gxK3juKxnFNa5apmB9M"} }
          ],
          "threshold": 2
        }
      ],
      "master_keys" : [ { "signers" : [] , "threshold" : 0}]
    }
    "#;
        let config: Result<
            SignersConfig<AsfaloadPublicKey<minisign::PublicKey>>,
            serde_json::Error,
        > = parse_signers_config(json_str_with_empty_master_signers_group);
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error
                .to_string()
                .starts_with("Group size must be at least 1")
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
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RM4ST3R285887D5Ag2MdVVIr0nqM7LRLBQpA3PRiYARbtIr0H96TgN63"} }
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
    fn test_initialize_signers_file1() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // Example JSON content (from the existing test)
        let json_content_template = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} },
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER"} }
      ],
      "threshold": 2
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;

        let json_content = &test_keys.substitute_keys(json_content_template.to_string());

        // Compute the SHA-512 hash of the JSON content
        let mut hasher = Sha512::new();
        hasher.update(json_content.as_bytes());
        let hash_result = hasher.finalize();

        // Get keys we work with here
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();

        // Sign the hash
        let signature = sec_key.sign(&hash_result).unwrap();

        // Call the function
        initialize_signers_file(
            dir_path,
            json_content,
            &signature,
            test_keys.pub_key(0).unwrap(),
        )
        .unwrap();

        // Check that the pending file exists
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the content
        let content = fs::read_to_string(&pending_file_path).unwrap();
        // We don't compare exactly because of formatting, but we can parse it again to validate
        let _config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(&content).unwrap();

        // Check that the signature does not exist as the aggregate
        // signature is not complete
        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!sig_file_path.exists());
        let pending_sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_file_path.exists());

        // Check the signature file content
        let sig_content = fs::read_to_string(pending_sig_file_path).unwrap();
        let sig_map: std::collections::HashMap<String, String> =
            serde_json::from_str(&sig_content).unwrap();
        assert_eq!(sig_map.len(), 1);
        assert!(sig_map.contains_key(&pub_key.to_base64()));
        assert_eq!(
            sig_map.get(&pub_key.to_base64()).unwrap(),
            &signature.to_base64()
        );
        Ok(())
    }

    #[test]
    fn test_initialize_signers_file_invalid_signer() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // JSON content with a specific signer
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
            { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyv"} }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [],
      "admin_keys": null
    }
    "#;

        // Generate a different keypair (not in the config)
        // Get keys we work with here
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();

        // Compute the SHA-512 hash of the JSON content
        let mut hasher = Sha512::new();
        hasher.update(json_content.as_bytes());
        let hash_result = hasher.finalize();

        // Sign the hash
        let signature = seckey.sign(&hash_result).unwrap();

        // Call the function - should fail due to invalid signer
        let result = initialize_signers_file(dir_path, json_content, &signature, pubkey);
        assert!(result.is_err());
        assert!(matches!(result, Err(SignersFileError::InvalidSigner(_))));

        // Ensure the pending file was not created
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());
    }

    #[test]
    fn test_initialize_signers_file_invalid_signature() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // JSON content with a specific signer
        let json_content_template = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://example.com",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [],
      "admin_keys": null
    }
    "#;
        let json_content = &test_keys.substitute_keys(json_content_template.to_string());

        // Generate a keypair (in the config)
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();

        // Sign different data (not the hash of the JSON)
        let signature = seckey.sign(b"wrong data").unwrap();

        // Call the function - should fail due to invalid signature
        let result = initialize_signers_file(dir_path, json_content, &signature, pubkey);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(SignersFileError::SignatureVerificationFailed(_))
        ));

        // Ensure the pending file was not created
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());
    }

    #[test]
    fn test_initialize_signers_file_with_admin_signers() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // JSON content with admin_signers
        let json_content_template = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://example.com",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [],
      "admin_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER"} },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER"} }
          ],
          "threshold": 2
        }
      ]
    }
    "#;

        let json_content = &test_keys.substitute_keys(json_content_template.to_string());
        // Get keys we work with here
        let non_admin_pubkey = test_keys.pub_key(0).unwrap();
        let non_admin_seckey = test_keys.sec_key(0).unwrap();
        let admin_pubkey = test_keys.pub_key(2).unwrap();
        let admin_seckey = test_keys.sec_key(2).unwrap();

        // Compute the SHA-512 hash of the JSON content
        let mut hasher = Sha512::new();
        hasher.update(json_content.as_bytes());
        let hash_result = hasher.finalize();

        // Reject new signers files signed by non admin keys
        // -------------------------------------------------
        // Sign the hash
        let non_admin_signature = non_admin_seckey.sign(&hash_result).unwrap();

        // Call the function
        let result = initialize_signers_file(
            dir_path,
            json_content,
            &non_admin_signature,
            non_admin_pubkey,
        );
        let sig_file_path = dir_path.join("asfaload.signatures.json");
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!sig_file_path.exists());
        assert!(!pending_file_path.exists());
        assert!(result.is_err());
        assert!(matches!(result, Err(SignersFileError::InvalidSigner(_))));

        // Now sign proposal with admin key which shuld be ok
        // --------------------------------------------------
        let admin_signature = admin_seckey.sign(&hash_result).unwrap();
        let result =
            initialize_signers_file(dir_path, json_content, &admin_signature, admin_pubkey);
        // Check that the pending file exists
        assert!(pending_file_path.exists());

        // Check that the signature file does not exist as not all
        // required admin signatures where collected.
        assert!(!sig_file_path.exists());
    }
    #[test]
    fn test_errors_in_initialize_signers_file() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create a valid JSON content
        let json_content_template = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;
        let json_content = &test_keys.substitute_keys(json_content_template.to_string());

        // Compute the SHA-512 hash of the JSON content
        let mut hasher = Sha512::new();
        hasher.update(json_content.as_bytes());
        let hash_result = hasher.finalize();

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();
        let signature = sec_key.sign(&hash_result).unwrap();

        // Test for IO error: Make the directory read-only
        let mut perms = fs::metadata(dir_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(dir_path, perms).unwrap();

        // Try to initialize the signers file, which should fail with an IO error
        let result = initialize_signers_file(dir_path, json_content, &signature, pub_key);

        // Check that we got an IO error
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!(
                "Expected IoError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        // Check no overwrite happens
        // first create a signers file in an empty directory
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let result = initialize_signers_file(dir_path, json_content, &signature, pub_key);
        assert!(result.is_ok());
        let pending_signers_file_path =
            dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_signers_file_path.exists());
        let result = initialize_signers_file(dir_path, json_content, &signature, pub_key);
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!(
                "Expected InitisalistionError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
    }
    #[test]
    fn test_refuse_initialize_signers_file_when_complete_signature_exists() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create a valid JSON content
        let json_content_template = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;
        let json_content = &test_keys.substitute_keys(json_content_template.to_string());

        // Compute the SHA-512 hash of the JSON content
        let mut hasher = Sha512::new();
        hasher.update(json_content.as_bytes());
        let hash_result = hasher.finalize();

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();
        let signature = sec_key.sign(&hash_result).unwrap();

        // Create complete signature file, content does not matter, only existence.
        let aggregate_signature_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        std::fs::create_dir(aggregate_signature_path.parent().unwrap())?;
        std::fs::File::create(&aggregate_signature_path)?;

        // Try to initialize the signers file, which should fail with an Initialisation error
        let result = initialize_signers_file(dir_path, json_content, &signature, pub_key);

        // Check that we got an IO error
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!(
                "Expected InitialisationError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());
        Ok(())
    }
    #[test]
    fn test_refuse_overwriting_existing_signers_file() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create a valid JSON content
        let json_content_template = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;
        let json_content = &test_keys.substitute_keys(json_content_template.to_string());

        // Compute the SHA-512 hash of the JSON content
        let mut hasher = Sha512::new();
        hasher.update(json_content.as_bytes());
        let hash_result = hasher.finalize();

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();
        let signature = sec_key.sign(&hash_result).unwrap();

        // Create complete signature file, content does not matter, only existence.
        let existing_signers_path =
            dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        std::fs::create_dir(existing_signers_path.parent().unwrap())?;
        std::fs::File::create(existing_signers_path)?;

        // Try to initialize the signers file, which should fail with an Initialisation error
        let result = initialize_signers_file(dir_path, json_content, &signature, pub_key);

        // Check that we got an IO error
        assert!(result.is_err());
        match result.as_ref().unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!(
                "Expected InitialisationError, got something else: {:?}",
                result.unwrap_err()
            ),
        }
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        // Check the file is still there
        assert!(pending_file_path.exists());
        // And check it wasn't changed, i.e. it is still and empty file
        let file_size = std::fs::metadata(pending_file_path)?.len();
        assert_eq!(file_size, 0);
        Ok(())
    }
}
