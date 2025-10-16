use aggregate_signature::{
    AggregateSignature, CompleteSignature, SignatureWithState, check_all_signers,
};
use chrono::Utc;
use common::fs::names::{
    PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE,
    pending_signatures_path_for, signatures_path_for,
};
use core::hash;
use serde_json::json;
use sha2::{Digest, Sha512};
use signatures::keys::{
    AsfaloadPublicKey, AsfaloadPublicKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
};
use signers_file_types::{SignersConfig, parse_signers_config};
use std::{collections::HashMap, ffi::OsStr, fs, io::Write, path::Path};
use thiserror::Error;
//

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
    #[error("Aggregate signature error: {0}")]
    AggregateSignatureError(#[from] aggregate_signature::AggregateSignatureError),
    #[error("Signers file not in a pending signers directory: {0}")]
    NotInPendingDir(String),
    #[error("Pending signers file filesystem hierarchy error: {0}")]
    FileSystemHierarchyError(String),
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
pub fn initialize_signers_file<P: AsRef<Path>, S, K>(
    dir_path_in: P,
    json_content: &str,
    signature: &S,
    pubkey: &K,
) -> Result<(), SignersFileError>
where
    K: AsfaloadPublicKeyTrait<Signature = S> + std::cmp::Eq + std::clone::Clone + std::hash::Hash,
    S: signatures::keys::AsfaloadSignatureTrait + std::clone::Clone,
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
    let signers_config: SignersConfig<K> = parse_signers_config(json_content)?;

    // Check that the signer is in the admin_signers group (equal to artifact signers of
    // admin group is not present in file)
    let is_valid_signer = signers_config.admin_keys().iter().any(|group| {
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
    let hash_result = common::sha512_for_content(json_content.as_bytes().to_vec())?;

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
        .add_to_aggregate_for_file(&signers_file_path, pubkey)
        .map_err(|e| {
            use signatures::keys::errs::SignatureError;
            match e {
                // As we write a new file here, no need to handle the JSonError as
                // it should not happen.
                SignatureError::IoError(io_err) => SignersFileError::IoError(io_err),
                other => SignersFileError::SignatureOperationFailed(other.to_string()),
            }
        })?;
    let mut signatures: HashMap<K, S> = HashMap::new();
    signatures.insert(pubkey.clone(), signature.clone());

    // Now everything is set up, try the transition to a complete signature.
    // This will succeed only if the signature is complete, and it is fine
    // if it returns an error reporting an incomplete signature for which the
    // transition cannot occur.
    let agg_sig: SignatureWithState<AsfaloadPublicKey<_>, AsfaloadSignature<_>> =
        aggregate_signature::load_for_file::<_, _, _>(signers_file_path)?;
    if let Some(pending_sig) = agg_sig.get_pending() {
        if let Err(e) = pending_sig.try_transition_to_complete() {
            if !matches!(
                e,
                aggregate_signature::AggregateSignatureError::IsIncomplete
            ) {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn move_current_signers_to_history<K: AsfaloadPublicKeyTrait, Pa: AsRef<Path>>(
    dir: Pa,
) -> Result<(), SignersFileError> {
    let root_dir = dir.as_ref();
    let active_signers_dir = root_dir.join(SIGNERS_DIR);
    let active_signers_file = active_signers_dir.join(SIGNERS_FILE);
    let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

    // Read existing active signers configuration
    let existing_content = fs::read_to_string(&active_signers_file)?;
    let existing_config: SignersConfig<K> = parse_signers_config(&existing_content)?;

    // Read the signatures file for the active signers
    let signatures_file_path = signatures_path_for(&active_signers_file)?;
    let signatures_content = fs::read_to_string(&signatures_file_path)?;
    let signatures_json: serde_json::Value = serde_json::from_str(&signatures_content)?;

    // Get current UTC time as ISO8601 string
    let obsoleted_at = chrono::Utc::now().to_rfc3339();

    // Create the history entry
    let mut history_entry = serde_json::Map::new();
    history_entry.insert(
        "obsoleted_at".to_string(),
        serde_json::Value::String(obsoleted_at),
    );
    history_entry.insert(
        "signers_file".to_string(),
        serde_json::to_value(existing_config)?,
    );
    history_entry.insert("signatures".to_string(), signatures_json);

    // Read or create history entries
    let mut history_entries: Vec<serde_json::Value> = if history_file_path.exists() {
        let history_content = fs::read_to_string(&history_file_path)?;
        if history_content.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&history_content)?
        }
    } else {
        Vec::new()
    };

    // Append the new entry
    history_entries.push(serde_json::Value::Object(history_entry));

    // Write updated history
    fs::write(
        &history_file_path,
        serde_json::to_string_pretty(&history_entries)?,
    )?;

    // Remove existing active signers directory
    fs::remove_dir_all(&active_signers_dir)?;
    Ok(())
}

pub fn activate_signers_file<P: AsRef<Path>, K, S>(
    signers_file: P,
    agg_sig: AggregateSignature<K, S, CompleteSignature>,
) -> Result<(), SignersFileError>
where
    K: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait + Clone,
{
    if signers_file.as_ref() != agg_sig.subject().path {
        return Err(SignersFileError::InitialisationError(
            "Signers file is not in a pending directory".to_string(),
        ));
    }
    let signers_file_path = signers_file.as_ref();

    // Verify the signers file is in a pending directory
    let pending_dir = signers_file_path.parent().ok_or_else(|| {
        SignersFileError::FileSystemHierarchyError(signers_file_path.to_string_lossy().to_string())
    })?;

    if pending_dir.file_name() != Some(OsStr::new(PENDING_SIGNERS_DIR)) {
        return Err(SignersFileError::NotInPendingDir(
            pending_dir.to_string_lossy().to_string(),
        ));
    }

    let root_dir = pending_dir.parent().ok_or_else(|| {
        SignersFileError::FileSystemHierarchyError(pending_dir.to_string_lossy().to_string())
    })?;

    // Handle existing active signers file and history
    let active_signers_dir = root_dir.join(SIGNERS_DIR);
    let active_signers_file = active_signers_dir.join(SIGNERS_FILE);

    if active_signers_file.exists() {
        move_current_signers_to_history::<K, _>(root_dir)?;
    }

    // Rename pending directory to active directory
    fs::rename(pending_dir, &active_signers_dir)?;

    Ok(())
}

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct HistoryEntry<P: AsfaloadPublicKeyTrait> {
    /// ISO8601 formatted UTC date and time
    pub obsoleted_at: String,
    /// Content of the signers file
    pub signers_file: SignersConfig<P>,
    /// Content of the signatures file (map from public key string to signature string)
    pub signatures: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "P: AsfaloadPublicKeyTrait",
    deserialize = "P: AsfaloadPublicKeyTrait"
))]
pub struct HistoryFile<P: AsfaloadPublicKeyTrait> {
    /// Array of history entries, sorted chronologically
    pub entries: Vec<HistoryEntry<P>>,
}

impl<PK> HistoryFile<PK>
where
    PK: AsfaloadPublicKeyTrait,
{
    /// Create a new empty history file
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a new entry to the history file
    pub fn add_entry(&mut self, entry: HistoryEntry<PK>) {
        self.entries.push(entry);
    }

    /// Get all entries in the history file
    pub fn entries(&self) -> &Vec<HistoryEntry<PK>> {
        &self.entries
    }

    /// Get the most recent entry in the history file
    pub fn latest_entry(&self) -> Option<&HistoryEntry<PK>> {
        self.entries.last()
    }

    /// Parse a history file from JSON string
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Convert the history file to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load a history file from the given path
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, SignersFileError> {
        let content = std::fs::read_to_string(path)?;
        let history_file = Self::from_json(&content)?;
        Ok(history_file)
    }

    /// Save the history file to the given path
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), SignersFileError> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl<P> Default for HistoryFile<P>
where
    P: AsfaloadPublicKeyTrait,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to parse a history file from JSON string
pub fn parse_history_file<P: AsfaloadPublicKeyTrait>(
    json_str: &str,
) -> Result<HistoryFile<P>, serde_json::Error> {
    HistoryFile::from_json(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use common::fs::names::PENDING_SIGNATURES_SUFFIX;
    use common::fs::names::PENDING_SIGNERS_FILE;
    use signatures::keys::AsfaloadPublicKey;
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signers_file_types::KeyFormat;
    use signers_file_types::SignerKind;
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
        assert_eq!(config.admin_keys(), &config.artifact_signers);

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

        // Test empty master
        // Empty groups are never complete, so this is the same as an absent master_keys field
        let json_str_with_empty_master_array = r#"
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
      "master_keys" : []}
    "#;
        let config: Result<
            SignersConfig<AsfaloadPublicKey<minisign::PublicKey>>,
            serde_json::Error,
        > = parse_signers_config(json_str_with_empty_master_array);
        assert!(config.is_ok());

        // Test empty admin array
        // If the json holds an empty array for admins, it returns the artifact signers just as
        // when it is not present at all
        let json_str_with_empty_admin_array = r#"
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
      ],
      "admin_keys" : []}
    "#;
        let result: Result<
            SignersConfig<AsfaloadPublicKey<minisign::PublicKey>>,
            serde_json::Error,
        > = parse_signers_config(json_str_with_empty_admin_array);
        assert!(result.is_ok());
        let config = result.unwrap();
        // Check admin_keys holds an one element array
        assert_eq!(config.admin_keys(), &config.artifact_signers);

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
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Get keys we work with here
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();

        // Sign the hash
        let signature = sec_key.sign(&hash_value).unwrap();

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
    fn test_initialize_signers_file_invalid_signer() -> Result<()> {
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
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Sign the hash
        let signature = seckey.sign(&hash_value).unwrap();

        // Call the function - should fail due to invalid signer
        let result = initialize_signers_file(dir_path, json_content, &signature, pubkey);
        assert!(result.is_err());
        assert!(matches!(result, Err(SignersFileError::InvalidSigner(_))));

        // Ensure the pending file was not created
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());
        Ok(())
    }

    #[test]
    fn test_initialize_signers_file_invalid_signature() -> Result<()> {
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
        let signature = seckey
            .sign(&common::sha512_for_content(b"wrong data".to_vec())?)
            .unwrap();

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
        Ok(())
    }

    #[test]
    fn test_initialize_signers_file_with_admin_signers() -> Result<()> {
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
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Reject new signers files signed by non admin keys
        // -------------------------------------------------
        // Sign the hash
        let non_admin_signature = non_admin_seckey.sign(&hash_value).unwrap();

        // Call the function
        let result = initialize_signers_file(
            dir_path,
            json_content,
            &non_admin_signature,
            non_admin_pubkey,
        );
        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        let pending_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(!sig_file_path.exists());
        assert!(!pending_file_path.exists());
        assert!(result.is_err());
        assert!(matches!(result, Err(SignersFileError::InvalidSigner(_))));

        // Now sign proposal with admin key which should be ok
        // --------------------------------------------------
        let admin_signature = admin_seckey.sign(&hash_value).unwrap();
        let result =
            initialize_signers_file(dir_path, json_content, &admin_signature, admin_pubkey);
        // Check that the pending file exists
        assert!(pending_file_path.exists());

        // Check that the signature file does not exist as not all
        // required admin signatures where collected.
        assert!(!sig_file_path.exists());
        Ok(())
    }
    #[test]
    fn test_initialize_signers_file_with_one_signer() -> Result<()> {
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
      "master_keys": []
    }
    "#;

        let json_content = &test_keys.substitute_keys(json_content_template.to_string());
        // Get keys we work with here
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        let pending_file_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));

        // Now sign proposal with unique artifact key which should be complete
        // ---------------------------------------------------------------
        let signature = seckey.sign(&hash_value).unwrap();
        let result = initialize_signers_file(dir_path, json_content, &signature, pubkey);
        result.expect("initialize_signers_file should have succeeded");
        // Check that the pending file does not exist, as we have the complete
        assert!(!pending_file_path.exists());

        // Check that the signature file exists as all
        // required admin signatures where collected.
        assert!(sig_file_path.exists());
        Ok(())
    }

    #[test]
    fn test_errors_in_initialize_signers_file() -> Result<()> {
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
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();
        let signature = sec_key.sign(&hash_value).unwrap();

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
        initialize_signers_file(dir_path, json_content, &signature, pub_key).unwrap();
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
        Ok(())
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
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();
        let signature = sec_key.sign(&hash_value).unwrap();

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
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();
        let signature = sec_key.sign(&hash_value).unwrap();

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

    // Test activate pending signers file
    // ----------------------------------

    // Helper function to create a test aggregate signature
    fn create_test_aggregate_signature(
        signers_file_path: &Path,
        test_keys: &TestKeys,
    ) -> Result<
        AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            CompleteSignature,
        >,
        SignersFileError,
    > {
        // Create the local signers file (required for signature verification)
        let local_signers_path = common::fs::names::local_signers_path_for(signers_file_path)?;
        fs::copy(signers_file_path, &local_signers_path)?;

        // Compute the hash of the signers file
        let hash = common::sha512_for_file(signers_file_path)?;

        // Sign with the first key
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Sign with second key
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the agregate signature's files on disk using our api.
        // Start by loading the empty signature
        let _ = aggregate_signature::load_for_file::<AsfaloadPublicKey<minisign::PublicKey>, _, _>(
            &signers_file_path,
        )?
        // As it is empty, is is pending
        .get_pending()
        .unwrap()
        // As it is pending, we can add an individual signature to it
        // After adding the signature, it is in this case complete.
        .add_individual_signature(&signature0, pubkey0)?
        // The threshold is 2 so it is pending here
        .get_pending()
        .unwrap()
        .add_individual_signature(&signature1, pubkey1)?;

        // Load the aggregate signature using the public API
        let sig_with_state = aggregate_signature::load_for_file::<_, _, _>(signers_file_path)?;
        match sig_with_state {
            SignatureWithState::Complete(sig) => Ok(sig),
            SignatureWithState::Pending(_) => Err(SignersFileError::InitialisationError(
                "Expected complete signature".to_string(),
            )),
        }
    }

    #[test]
    fn test_activate_signers_file_success() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_content = create_test_signers_config(&test_keys);
        fs::write(&signers_file_path, signers_content.to_json()?)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(&signers_file_path, agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = root_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        // Verify the content is preserved
        let active_content = fs::read_to_string(&active_signers_file)?;
        let expected_content = create_test_signers_config(&test_keys);
        assert_eq!(active_content, expected_content.to_json()?);

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_with_existing_active() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();

        // Use distinct TestKeys instances for existing and new signers
        let existing_keys = TestKeys::new(1);
        let new_keys = TestKeys::new(2);

        // Create existing active directory and signers file
        let active_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_dir)?;
        let existing_signers_file = active_dir.join(SIGNERS_FILE);

        // Create a template for the existing content
        let existing_content_template = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://old.example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER" } }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;

        // Substitute the placeholder with an actual public key from existing_keys
        let existing_content = existing_keys.substitute_keys(existing_content_template.to_string());
        fs::write(&existing_signers_file, existing_content)?;

        // Create the signatures file for the existing signers file
        let hash = common::sha512_for_file(&existing_signers_file)?;
        let pubkey0 = existing_keys.pub_key(0).unwrap();
        let seckey0 = existing_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Create signature of current signers file
        let _ = aggregate_signature::load_for_file(&existing_signers_file)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?;

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);

        // Use new_keys for the new signers config
        let new_content = create_test_signers_config(&new_keys);
        fs::write(&signers_file_path, &new_content.to_json()?)?;

        // Create aggregate signature using new_keys
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &new_keys)?;
        agg_sig.save_to_file()?;

        // Activate the signers file
        activate_signers_file(&signers_file_path, agg_sig)?;

        // Verify the history file was created
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);
        assert!(history_file_path.exists());

        // Verify the history contains the old configuration
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 1);

        // Verify the old configuration is in the history
        let old_config_in_history = history_entries[0]
            .get("signers_file")
            .and_then(|v| v.get("initial_version"))
            .and_then(|v| v.get("permalink"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(old_config_in_history, "https://old.example.com");

        // Verify the new configuration is active
        let new_active_content = fs::read_to_string(active_dir.join(SIGNERS_FILE))?;
        assert_eq!(new_active_content, new_content.to_json()?);

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_path_mismatch() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, &signers_content)?;

        // Create aggregate signature with a different path
        let different_path = root_dir.join("different_file.json");
        fs::write(&different_path, &signers_content)?;
        let agg_sig = create_test_aggregate_signature(&different_path, &test_keys)?;

        // Try to activate with mismatched paths
        let result = activate_signers_file(&signers_file_path, agg_sig);

        // Verify the error
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Signers file is not in a pending directory"));
            }
            other => panic!(
                "Expected InitialisationError for path mismatch, got {:?}",
                other
            ),
        }

        // Verify the pending directory still exists
        assert!(pending_dir.exists());

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_not_in_pending_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a directory that is not named PENDING_SIGNERS_DIR
        let wrong_dir = root_dir.join("wrong_directory");
        fs::create_dir_all(&wrong_dir)?;
        let signers_file_path = wrong_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Try to activate
        let result = activate_signers_file(&signers_file_path, agg_sig);

        // Verify the error
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::NotInPendingDir(path) => {
                assert_eq!(path, wrong_dir.to_string_lossy().to_string());
            }
            _ => panic!("Expected NotInPendingDir error"),
        }

        // Verify the directory still exists
        assert!(wrong_dir.exists());

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_no_parent_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);

        // Create a file at the root level (no parent directory)
        let signers_file_path = temp_dir.path().join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Try to activate
        let result = activate_signers_file(&signers_file_path, agg_sig);

        // Verify the error
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            SignersFileError::NotInPendingDir(path) => {
                assert_eq!(
                    path,
                    signers_file_path
                        .parent()
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                );
            }
            _ => panic!("Expected NotInPendingDir but got {}", err),
        }

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_with_signature_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(&signers_file_path, agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = root_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signature files were removed
        let pending_sig_path = common::fs::names::pending_signatures_path_for(&signers_file_path)?;
        let complete_sig_path = common::fs::names::signatures_path_for(&signers_file_path)?;
        assert!(!pending_sig_path.exists());
        assert!(!complete_sig_path.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_nested_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        fs::create_dir_all(&nested_dir)?;
        let test_keys = TestKeys::new(2);

        // Create pending directory in nested directory
        let pending_dir = nested_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(&signers_file_path, agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = nested_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        // Verify the content is preserved
        let active_content = fs::read_to_string(&active_signers_file)?;
        let expected_config = create_test_signers_config(&test_keys);
        let expected_content = expected_config.to_json()?;
        assert_eq!(active_content, expected_content);

        Ok(())
    }
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;

    // Helper function to create a test active signers setup
    fn create_test_active_signers(
        root_dir: &Path,
        test_keys: &TestKeys,
    ) -> Result<PathBuf, SignersFileError> {
        let active_signers_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;

        let signers_file_path = active_signers_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        let hash = common::sha512_for_file(&signers_file_path)?;

        // Sign with both keys
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the aggregate signature
        aggregate_signature::load_for_file::<AsfaloadPublicKey<minisign::PublicKey>, _, _>(
            &signers_file_path,
        )?
        .get_pending()
        .unwrap()
        .add_individual_signature(&signature0, pubkey0)?
        .get_pending()
        .unwrap()
        .add_individual_signature(&signature1, pubkey1)?;

        Ok(signers_file_path)
    }

    #[test]
    fn test_move_to_history_creates_new_history_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Read the original signers file content
        let original_signers_content = fs::read_to_string(&signers_file_path)?;
        let original_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Ensure history file doesn't exist initially
        assert!(!history_file_path.exists());

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<_>, _>(root_dir)?;

        // Verify history file was created
        assert!(history_file_path.exists());

        // Verify active directory was removed
        assert!(!signers_file_path.exists());
        assert!(!root_dir.join(SIGNERS_DIR).exists());

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 1);

        let entry = &history_entries[0];
        assert!(entry.get("obsoleted_at").unwrap().is_string());

        // Verify signers file content matches original
        let signers_file_in_history = entry.get("signers_file").unwrap();
        let parsed_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            serde_json::from_value(signers_file_in_history.clone())?;
        assert_eq!(parsed_signers_config, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = entry.get("signatures").unwrap();
        let parsed_signatures: HashMap<String, String> =
            serde_json::from_value(signatures_in_history.clone())?;
        assert_eq!(parsed_signatures, original_signatures);

        Ok(())
    }

    #[test]
    fn test_move_to_history_appends_to_existing_history() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create existing history file
        let existing_entry = serde_json::json!({
            "obsoleted_at": "2023-01-01T00:00:00Z",
            "signers_file": {
                "version": 1,
                "initial_version": {
                    "permalink": "https://old.example.com",
                    "mirrors": []
                },
                "artifact_signers": ["RWRaOIhiXUjDgCLx2NwuLAVboIDMJZ32WagBSN2wjxlvYvdsvjmMzGy3"],
                "master_keys": [],
                "threshold": 1
            },
            "signatures": {}
        });

        let existing_history = serde_json::json!([existing_entry]);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        // Read the existing history content before the move
        let original_history_content = fs::read_to_string(&history_file_path)?;
        let original_history_entries: Vec<serde_json::Value> =
            serde_json::from_str(&original_history_content)?;
        assert_eq!(original_history_entries.len(), 1);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_content = fs::read_to_string(&signers_file_path)?;
        let original_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir)?;

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 2);

        // Verify first entry is unchanged and matches the original
        let first_entry = &history_entries[0];
        let original_first_entry = &original_history_entries[0];
        assert_eq!(first_entry, original_first_entry);

        // Verify second entry is the new one with correct content
        let second_entry = &history_entries[1];
        assert!(second_entry.get("obsoleted_at").unwrap().is_string());

        // Verify signers file content matches original
        let signers_file_in_history = second_entry.get("signers_file").unwrap();
        let parsed_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            serde_json::from_value(signers_file_in_history.clone())?;
        assert_eq!(parsed_signers_config, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = second_entry.get("signatures").unwrap();
        let parsed_signatures: HashMap<String, String> =
            serde_json::from_value(signatures_in_history.clone())?;
        assert_eq!(parsed_signatures, original_signatures);

        // Verify entries are sorted chronologically
        let first_time: DateTime<Utc> =
            serde_json::from_value(first_entry.get("obsoleted_at").unwrap().clone())?;
        let second_time: DateTime<Utc> =
            serde_json::from_value(second_entry.get("obsoleted_at").unwrap().clone())?;
        assert!(first_time < second_time);

        Ok(())
    }

    #[test]
    fn test_move_to_history_preserves_all_existing_entries() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create multiple existing history entries
        let entry1 = serde_json::json!({
            "obsoleted_at": "2023-01-01T00:00:00Z",
            "signers_file": {
                "version": 1,
                "initial_version": {
                    "permalink": "https://old1.example.com",
                    "mirrors": []
                },
                "artifact_signers": [],
                "master_keys": []
            },
            "signatures": {"key1": "sig1"}
        });

        let entry2 = serde_json::json!({
            "obsoleted_at": "2023-02-01T00:00:00Z",
            "signers_file": {
                "version": 2,
                "initial_version": {
                    "permalink": "https://old2.example.com",
                    "mirrors": []
                },
                "artifact_signers": [],
                "master_keys": []
            },
            "signatures": {"key2": "sig2"}
        });

        let existing_history = serde_json::json!([entry1, entry2]);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        // Read the existing history content before the move
        let original_history_content = fs::read_to_string(&history_file_path)?;
        let original_history_entries: Vec<serde_json::Value> =
            serde_json::from_str(&original_history_content)?;
        assert_eq!(original_history_entries.len(), 2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_content = fs::read_to_string(&signers_file_path)?;
        let original_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir)?;

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 3);

        // Verify all existing entries are unchanged
        for i in 0..original_history_entries.len() {
            assert_eq!(&history_entries[i], &original_history_entries[i]);
        }

        // Verify the new entry is the last one with correct content
        let new_entry = &history_entries[2];
        assert!(new_entry.get("obsoleted_at").unwrap().is_string());

        // Verify signers file content matches original
        let signers_file_in_history = new_entry.get("signers_file").unwrap();
        let parsed_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            serde_json::from_value(signers_file_in_history.clone())?;
        assert_eq!(parsed_signers_config, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = new_entry.get("signatures").unwrap();
        let parsed_signatures: HashMap<String, String> =
            serde_json::from_value(signatures_in_history.clone())?;
        assert_eq!(parsed_signatures, original_signatures);

        // Verify entries are sorted chronologically
        for i in 0..history_entries.len() - 1 {
            let current_time: DateTime<Utc> =
                serde_json::from_value(history_entries[i].get("obsoleted_at").unwrap().clone())?;
            let next_time: DateTime<Utc> = serde_json::from_value(
                history_entries[i + 1].get("obsoleted_at").unwrap().clone(),
            )?;
            assert!(current_time <= next_time);
        }

        Ok(())
    }
    #[test]
    fn test_move_to_history_timestamp_format() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Record time before operation
        let before_time = Utc::now();

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir)?;

        // Record time after operation
        let after_time = Utc::now();

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 1);

        let entry = &history_entries[0];
        let timestamp_str = entry.get("obsoleted_at").unwrap().as_str().unwrap();

        // Verify timestamp format is ISO8601
        let timestamp: DateTime<Utc> = timestamp_str.parse()?;

        // Verify timestamp is recent (between before and after)
        assert!(timestamp >= before_time);
        assert!(timestamp <= after_time);

        Ok(())
    }

    #[test]
    fn test_move_to_history_preserves_signatures_content() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let signatures_path = signatures_path_for(&signers_file_path)?;

        // Read original signatures content
        let original_signatures_content = fs::read_to_string(&signatures_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir)?;

        // Verify history content
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 1);

        let entry = &history_entries[0];
        let signatures_in_history = entry.get("signatures").unwrap();
        let parsed_signatures: HashMap<String, String> =
            serde_json::from_value(signatures_in_history.clone())?;

        // Verify signatures content is preserved
        assert_eq!(parsed_signatures, original_signatures);

        Ok(())
    }

    #[test]
    fn test_move_to_history_with_multiple_entries_sorted() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create multiple existing history entries with different timestamps
        let entry1 = serde_json::json!({
            "obsoleted_at": "2023-01-01T00:00:00Z",
            "signers_file": {"version": 1},
            "signatures": {}
        });

        let entry2 = serde_json::json!({
            "obsoleted_at": "2023-02-01T00:00:00Z",
            "signers_file": {"version": 1},
            "signatures": {}
        });

        let existing_history = serde_json::json!([entry1, entry2]);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Record time before operation
        let before_time = Utc::now();

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir)?;

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 3);

        // Verify entries are sorted chronologically
        for i in 0..history_entries.len() - 1 {
            let current_time: DateTime<Utc> =
                serde_json::from_value(history_entries[i].get("obsoleted_at").unwrap().clone())?;
            let next_time: DateTime<Utc> = serde_json::from_value(
                history_entries[i + 1].get("obsoleted_at").unwrap().clone(),
            )?;
            assert!(current_time <= next_time);
        }

        // Verify the new entry is the last one
        let last_entry = &history_entries[2];
        let last_timestamp: DateTime<Utc> =
            serde_json::from_value(last_entry.get("obsoleted_at").unwrap().clone())?;
        assert!(last_timestamp >= before_time);

        Ok(())
    }

    #[test]
    fn test_move_to_history_error_when_no_active_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();

        // Don't create active signers directory
        let result =
            move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir);

        // Should fail with IO error
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }

        Ok(())
    }

    #[test]
    fn test_move_to_history_error_when_no_signatures_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers directory and file but no signatures file
        let active_signers_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;

        let signers_file_path = active_signers_dir.join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Try to move to history
        let result =
            move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir);

        // Should fail with IO error
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }

        Ok(())
    }
    #[test]
    fn test_move_to_history_with_empty_history_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create an empty history file
        fs::write(&history_file_path, "")?;

        // Verify the history file exists but is empty
        assert!(history_file_path.exists());
        let initial_content = fs::read_to_string(&history_file_path)?;
        assert!(initial_content.is_empty());

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_content = fs::read_to_string(&signers_file_path)?;
        let original_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history::<AsfaloadPublicKey<minisign::PublicKey>, _>(root_dir)?;

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_entries: Vec<serde_json::Value> = serde_json::from_str(&history_content)?;
        assert_eq!(history_entries.len(), 1);

        let entry = &history_entries[0];
        assert!(entry.get("obsoleted_at").unwrap().is_string());

        // Verify signers file content matches original
        let signers_file_in_history = entry.get("signers_file").unwrap();
        let parsed_signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            serde_json::from_value(signers_file_in_history.clone())?;
        assert_eq!(parsed_signers_config, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = entry.get("signatures").unwrap();
        let parsed_signatures: HashMap<String, String> =
            serde_json::from_value(signatures_in_history.clone())?;
        assert_eq!(parsed_signatures, original_signatures);

        // Verify active directory was removed
        assert!(!signers_file_path.exists());
        assert!(!root_dir.join(SIGNERS_DIR).exists());

        Ok(())
    }
    // History file serialisation tests
    // --------------------------------

    // Helper function to create a test signers config
    fn create_test_signers_config(
        test_keys: &TestKeys,
    ) -> SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> {
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
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER" } },
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
      ],
      "threshold": 2
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;
        let json_content = test_keys.substitute_keys(json_content_template.to_string());
        parse_signers_config(&json_content).unwrap()
    }

    // Helper function to create a test signatures map
    fn create_test_signatures(test_keys: &TestKeys) -> HashMap<String, String> {
        let mut signatures = HashMap::new();
        signatures.insert(
            test_keys.pub_key(0).unwrap().to_base64(),
            "test_signature_0".to_string(),
        );
        signatures.insert(
            test_keys.pub_key(1).unwrap().to_base64(),
            "test_signature_1".to_string(),
        );
        signatures
    }

    // Helper function to create a test history entry
    fn create_test_history_entry(
        test_keys: &TestKeys,
        timestamp: &str,
    ) -> HistoryEntry<AsfaloadPublicKey<minisign::PublicKey>> {
        HistoryEntry {
            obsoleted_at: timestamp.to_string(),
            signers_file: create_test_signers_config(test_keys),
            signatures: create_test_signatures(test_keys),
        }
    }

    #[test]
    fn test_history_entry_creation() {
        let test_keys = TestKeys::new(2);
        let timestamp = "2023-01-01T00:00:00Z";

        let entry = create_test_history_entry(&test_keys, timestamp);

        assert_eq!(entry.obsoleted_at, timestamp);
        assert_eq!(entry.signers_file.version, 1);
        assert_eq!(
            entry.signers_file.initial_version.permalink,
            "https://example.com"
        );
        assert_eq!(entry.signers_file.artifact_signers.len(), 1);
        assert_eq!(entry.signers_file.artifact_signers[0].threshold, 2);
        assert_eq!(entry.signers_file.artifact_signers[0].signers.len(), 2);
        assert_eq!(entry.signatures.len(), 2);
    }

    #[test]
    fn test_history_file_new() {
        let history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> = HistoryFile::new();

        assert!(history_file.entries().is_empty());
    }

    #[test]
    fn test_history_file_default() {
        let history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::default();

        assert!(history_file.entries().is_empty());
    }

    #[test]
    fn test_history_file_add_entry() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z");

        history_file.add_entry(entry1);
        history_file.add_entry(entry2);

        assert_eq!(history_file.entries().len(), 2);
        assert_eq!(
            history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z"
        );
        assert_eq!(
            history_file.entries()[1].obsoleted_at,
            "2023-02-01T00:00:00Z"
        );
    }

    #[test]
    fn test_history_file_latest_entry() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        // Empty history file
        assert!(history_file.latest_entry().is_none());

        // Add one entry
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        history_file.add_entry(entry1);
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-01-01T00:00:00Z"
        );

        // Add another entry
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z");
        history_file.add_entry(entry2);
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-02-01T00:00:00Z"
        );
    }

    #[test]
    fn test_history_file_to_json() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        let entry = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        history_file.add_entry(entry);

        let json = history_file.to_json().unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify structure
        assert!(parsed.is_object());
        assert_eq!(parsed.get("entries").unwrap().as_array().unwrap().len(), 1);

        let entry = &parsed.get("entries").unwrap()[0];
        assert!(entry.get("obsoleted_at").is_some());
        assert!(entry.get("signers_file").is_some());
        assert!(entry.get("signatures").is_some());
    }

    #[test]
    fn test_history_file_from_json() {
        let test_keys = TestKeys::new(2);

        // Create a JSON template with placeholders
        let json_template = r#"
{
  "entries": [
    {
      "obsoleted_at": "2023-01-01T00:00:00Z",
      "signers_file": {
        "version": 1,
        "initial_version": {
          "permalink": "https://example.com",
          "mirrors": []
        },
        "artifact_signers": [
          {
            "signers": [
              {
                "kind": "key",
                "data": {
                  "format": "minisign",
                  "pubkey": "PUBKEY0_PLACEHOLDER"
                }
              },
              {
                "kind": "key",
                "data": {
                  "format": "minisign",
                  "pubkey": "PUBKEY1_PLACEHOLDER"
                }
              }
            ],
            "threshold": 2
          }
        ],
        "master_keys": [],
        "admin_keys": null
      },
      "signatures": {
        "PUBKEY0_PLACEHOLDER": "SIGNATURE0_PLACEHOLDER",
        "PUBKEY1_PLACEHOLDER": "SIGNATURE1_PLACEHOLDER"
      }
    }
  ]
}
"#;

        // Get the actual public keys from test_keys
        let pubkey0 = test_keys.pub_key(0).unwrap().to_base64();
        let pubkey1 = test_keys.pub_key(1).unwrap().to_base64();

        // Compute actual signatures
        let test_data = b"test data for signing";
        let hash = common::sha512_for_content(test_data.to_vec()).unwrap();

        let signature0 = test_keys.sec_key(0).unwrap().sign(&hash).unwrap();
        let signature1 = test_keys.sec_key(1).unwrap().sign(&hash).unwrap();

        let signature0_b64 = signature0.to_base64();
        let signature1_b64 = signature1.to_base64();

        // Replace placeholders in the template
        let json_content = json_template
            .replace("PUBKEY0_PLACEHOLDER", &pubkey0)
            .replace("PUBKEY1_PLACEHOLDER", &pubkey1)
            .replace("SIGNATURE0_PLACEHOLDER", &signature0_b64)
            .replace("SIGNATURE1_PLACEHOLDER", &signature1_b64);

        // Parse the history file
        let history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_history_file(&json_content).unwrap();

        // Verify the content
        assert_eq!(history_file.entries().len(), 1);
        assert_eq!(
            history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z"
        );
        assert_eq!(history_file.entries()[0].signers_file.version, 1);
        assert_eq!(
            history_file.entries()[0]
                .signers_file
                .initial_version
                .permalink,
            "https://example.com"
        );
        assert_eq!(
            history_file.entries()[0]
                .signers_file
                .artifact_signers
                .len(),
            1
        );
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers[0].threshold,
            2
        );
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers[0]
                .signers
                .len(),
            2
        );

        // Verify the public keys in the signers file
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers[0].signers[0]
                .data
                .pubkey
                .to_base64(),
            pubkey0
        );
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers[0].signers[1]
                .data
                .pubkey
                .to_base64(),
            pubkey1
        );

        // Verify the signatures
        assert_eq!(history_file.entries()[0].signatures.len(), 2);
        assert_eq!(
            history_file.entries()[0].signatures.get(&pubkey0).unwrap(),
            &signature0_b64
        );
        assert_eq!(
            history_file.entries()[0].signatures.get(&pubkey1).unwrap(),
            &signature1_b64
        );

        // Verify that the signatures are valid for the test data
        assert!(
            test_keys
                .pub_key(0)
                .unwrap()
                .verify(&signature0, &hash)
                .is_ok()
        );
        assert!(
            test_keys
                .pub_key(1)
                .unwrap()
                .verify(&signature1, &hash)
                .is_ok()
        );
    }

    #[test]
    fn test_history_file_from_json_invalid() {
        let invalid_json = r#"
{ "entries" :
[
  {
    "obsoleted_at": "2023-01-01T00:00:00Z",
    "signers_file": {
      "version": "invalid",  // Should be a number
      "initial_version": {
        "permalink": "https://example.com",
        "mirrors": []
      },
      "artifact_signers": [],
      "master_keys": [],
      "admin_keys": null
    },
    "signatures": {}
  }
]
}
"#;

        let result: Result<HistoryFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            parse_history_file(invalid_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_history_file_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history.json");
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        let entry = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        history_file.add_entry(entry);

        // Save to file
        history_file.save_to_file(&file_path).unwrap();
        assert!(file_path.exists());

        // Load from file
        let loaded_history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::load_from_file(&file_path).unwrap();

        // Verify content
        assert_eq!(loaded_history_file.entries().len(), 1);
        assert_eq!(
            loaded_history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z"
        );
        assert_eq!(loaded_history_file.entries()[0].signers_file.version, 1);
        assert_eq!(loaded_history_file.entries()[0].signatures.len(), 2);
    }

    #[test]
    fn test_history_file_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.json");

        let result: Result<HistoryFile<AsfaloadPublicKey<minisign::PublicKey>>, _> =
            HistoryFile::load_from_file(&file_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_history_file_save_to_nonexistent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent_dir = temp_dir.path().join("nonexistent");
        let file_path = nonexistent_dir.join("history.json");
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        let entry = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        history_file.add_entry(entry);

        // Try to save to nonexistent directory
        let result = history_file.save_to_file(&file_path);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(_) => {} // Expected
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_history_file_multiple_entries() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        // Add multiple entries with different timestamps
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z");
        let entry3 = create_test_history_entry(&test_keys, "2023-03-01T00:00:00Z");

        history_file.add_entry(entry1);
        history_file.add_entry(entry2);
        history_file.add_entry(entry3);

        // Verify all entries are present
        assert_eq!(history_file.entries().len(), 3);

        // Verify chronological order
        for i in 0..history_file.entries().len() - 1 {
            let current_time: DateTime<Utc> =
                history_file.entries()[i].obsoleted_at.parse().unwrap();
            let next_time: DateTime<Utc> =
                history_file.entries()[i + 1].obsoleted_at.parse().unwrap();
            assert!(current_time <= next_time);
        }

        // Verify latest entry
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-03-01T00:00:00Z"
        );
    }

    #[test]
    fn test_history_file_roundtrip() {
        let test_keys = TestKeys::new(2);
        let mut original_history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        // Add multiple entries
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z");
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z");

        original_history_file.add_entry(entry1);
        original_history_file.add_entry(entry2);

        // Convert to JSON and back
        let json = original_history_file.to_json().unwrap();
        let deserialized_history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_history_file(&json).unwrap();

        // Verify they are identical
        assert_eq!(
            original_history_file.entries().len(),
            deserialized_history_file.entries().len()
        );

        for (original_entry, deserialized_entry) in original_history_file
            .entries()
            .iter()
            .zip(deserialized_history_file.entries().iter())
        {
            assert_eq!(original_entry.obsoleted_at, deserialized_entry.obsoleted_at);
            assert_eq!(original_entry.signers_file, deserialized_entry.signers_file);
            assert_eq!(original_entry.signatures, deserialized_entry.signatures);
        }
    }

    #[test]
    fn test_history_file_with_empty_signatures() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            HistoryFile::new();

        // Create an entry with empty signatures
        let entry = HistoryEntry {
            obsoleted_at: "2023-01-01T00:00:00Z".to_string(),
            signers_file: create_test_signers_config(&test_keys),
            signatures: HashMap::new(),
        };

        history_file.add_entry(entry);

        // Verify it serializes and deserializes correctly
        let json = history_file.to_json().unwrap();
        let deserialized: HistoryFile<AsfaloadPublicKey<minisign::PublicKey>> =
            parse_history_file(&json).unwrap();

        assert_eq!(deserialized.entries().len(), 1);
        assert_eq!(deserialized.entries()[0].signatures.len(), 0);
    }
}
