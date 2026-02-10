use aggregate_signature::{AggregateSignature, CompleteSignature, SignatureWithState};
use chrono::{DateTime, Utc};
use common::{
    SignedFileLoader,
    errors::{AggregateSignatureError, SignersFileError},
    fs::{
        names::{find_global_signers_for, pending_signatures_path_for, signatures_path_for},
        open_new_file,
    },
};
use constants::{
    METADATA_FILE, PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE,
};
use signatures::{
    keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait},
    types::{AsfaloadPublicKeys, AsfaloadSignatures},
};
use signers_file_types::{
    SignersConfig, SignersConfigMetadata, SignersConfigProposal, parse_signers_config,
    parse_signers_config_proposal,
};
use std::{borrow::Borrow, collections::HashMap, ffi::OsStr, fs, io::Write, path::Path};
//

// Helper function used to validate the signer of a signers file
// initialisation, i.e. when no existing signers file is active.
fn is_valid_signer_for_signer_init(
    pubkey: &AsfaloadPublicKeys,
    config: &SignersConfig,
) -> Result<(), SignersFileError> {
    let is_valid = config.admin_keys().iter().any(|group| {
        group
            .signers
            .iter()
            .any(|signer| signer.data.pubkey == *pubkey)
    });
    if is_valid {
        Ok(())
    } else {
        Err(SignersFileError::InvalidSigner(
            "The provided public key is not in the required groups for signers init".to_string(),
        ))
    }
}

// Helper function used to validate the signer of a signers file
// initialisation, i.e. when there is an existing signers file active,
// which influences the validation.
fn is_valid_signer_for_update_of(
    pubkey: &AsfaloadPublicKeys,
    active_config: &SignersConfig,
) -> Result<(), SignersFileError> {
    // Only an admin key or a master key can propose a new signers file.
    let is_valid = active_config.admin_keys().iter().any(|group| {
        group
            .signers
            .iter()
            .any(|signer| signer.data.pubkey == *pubkey)
    }) || active_config
        .master_keys()
        .unwrap_or_default()
        .iter()
        .any(|group| {
            group
                .signers
                .iter()
                .any(|signer| signer.data.pubkey == *pubkey)
        });
    if is_valid {
        Ok(())
    } else {
        Err(SignersFileError::InvalidSigner(
            "The provided public key is not in the required groups of current config for signers update".to_string(),
        ))
    }
}

pub fn sign_signers_file<P>(
    signers_file_path: P,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
) -> Result<SignatureWithState, SignersFileError>
where
    P: AsRef<Path>,
{
    let signed_file = SignedFileLoader::load(&signers_file_path);
    if !(signed_file.is_initial_signers() || signed_file.is_signers()) {
        return Err(SignersFileError::FileSystemHierarchyError(format!(
            "Trying to sign a file as signers file, which it is not: {}",
            signers_file_path.as_ref().to_string_lossy()
        )));
    }
    // Add the signature to the aggregate signatures file
    signature.add_to_aggregate_for_file(&signers_file_path, pubkey)?;

    // Now everything is set up, try the transition to a complete signature.
    // This will succeed only if the signature is complete, and it is fine
    // if it returns an error reporting an incomplete signature for which the
    // transition cannot occur.
    let agg_sig: SignatureWithState = SignatureWithState::load_for_file(&signers_file_path)?;
    match agg_sig {
        SignatureWithState::Pending(pending_sig) => {
            match pending_sig.try_transition_to_complete() {
                Ok(agg_sig) => {
                    // Success case: The signature completed successfully.
                    activate_signers_file(&agg_sig)?;
                    Ok(SignatureWithState::Complete(agg_sig))
                }
                Err(AggregateSignatureError::IsIncomplete) => {
                    // Signature is not yet complete, which is fine. We just added our part.
                    Ok(SignatureWithState::Pending(pending_sig))
                }
                Err(e) => {
                    // Any other error is fatal.
                    Err(e.into())
                }
            }
        }
        SignatureWithState::Complete(_) => Ok(agg_sig),
    }
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
/// * `dir_path` - The directory where the pending signers file should be placed. If it is not the
///   path to a directory named ${PENDING_SIGNERS_DIR}, a subdirectory with name ${PENDING_SIGNERS_DIR} is created.
/// * `json_content` - The JSON content of the signers configuration
/// * `signature` - The signature of the SHA-512 hash of the JSON content
/// * `pubkey` - The public key of the signer
///
/// # Returns
/// * `Ok(())` if the pending file was successfully created
/// * `Err(SignersFileError)` if there was an error validating the JSON, signature, or writing the file
pub fn write_valid_signers_file<P: AsRef<Path>>(
    dir_path_in: P,
    json_content: &str,
    metadata: SignersConfigMetadata,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
    validator: impl FnOnce() -> Result<(), SignersFileError>,
) -> Result<(), SignersFileError> {
    // Ensure we work in the right directory

    let dir_path = {
        if dir_path_in.as_ref().ends_with(PENDING_SIGNERS_DIR) {
            dir_path_in.as_ref().to_path_buf()
        } else {
            dir_path_in.as_ref().join(PENDING_SIGNERS_DIR)
        }
    };

    // If a signers file exists, we refuse to overwrite it
    let signers_file_path = dir_path.join(SIGNERS_FILE);
    if signers_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Signers file exists: {}",
            signers_file_path.to_string_lossy()
        )));
    }

    // If a metadata file exists, we refuse to overwrite it
    let metadata_file_path = dir_path.join(METADATA_FILE);
    if metadata_file_path.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Metadata file exists: {}",
            metadata_file_path.to_string_lossy()
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
    let _signers_config: SignersConfig = parse_signers_config(json_content)?;

    validator()?;

    // Compute the SHA-512 hash of the JSON content
    let hash_result = common::sha512_for_content(json_content.as_bytes().to_vec())?;

    // Verify the signature against the hash
    pubkey.verify(signature, &hash_result).map_err(|e| {
        SignersFileError::SignatureVerificationFailed(format!(
            "Signature verification failed: {}",
            e
        ))
    })?;

    // Now that all validation have taken place, we can ensure directory exists
    // and create it if not.
    std::fs::create_dir_all(&dir_path)?;

    let result = (|| -> Result<(), SignersFileError> {
        // Write the metadata file
        let metadata_file = open_new_file(&metadata_file_path)?;
        serde_json::to_writer_pretty(&metadata_file, &metadata)?;
        // Write the JSON content to the pending signers file
        let mut signers_file = open_new_file(&signers_file_path)?;
        signers_file.write_all(json_content.as_bytes())?;

        sign_signers_file(signers_file_path, signature, pubkey)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&dir_path);
    }

    result
}
pub fn initialize_signers_file<P: AsRef<Path>>(
    dir_path_in: P,
    json_content_in: impl AsRef<str>,
    metadata: SignersConfigMetadata,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
) -> Result<(), SignersFileError> {
    let json_content = json_content_in.as_ref();
    if dir_path_in.as_ref().join(SIGNERS_DIR).exists()
        || dir_path_in.as_ref().join(PENDING_SIGNERS_DIR).exists()
    {
        return Err(SignersFileError::InitialisationError(format!(
            "Cannot initialise a signers dir in a directory with an existing signers dir: {}",
            dir_path_in.as_ref().to_string_lossy(),
        )));
    }
    let signers_config: SignersConfig = parse_signers_config(json_content)?;
    let validator = || is_valid_signer_for_signer_init(pubkey, &signers_config);
    write_valid_signers_file(
        dir_path_in.as_ref(),
        json_content,
        metadata,
        signature,
        pubkey,
        validator,
    )
}

/// Propose an update to an existing signers file.
///
/// This function validates that the provided signature is from a signer in the admin or master
/// group of the currently active signers file, and then calls initialize_signers_file to create
/// a new pending signers file.
///
/// # Arguments
/// * `dir_path` - The directory where the pending signers file should be placed
/// * `json_content` - The JSON content of the new signers configuration
/// * `signature` - The signature of the SHA-512 hash of the JSON content
/// * `pubkey` - The public key of the signer
///
/// # Returns
/// * `Ok(())` if the pending file was successfully created
/// * `Err(SignersFileError)` if there was an error validating the signature or creating the file
pub fn propose_signers_file<P: AsRef<Path>>(
    dir_path: P,
    json_content: &str,
    metadata: SignersConfigMetadata,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
) -> Result<(), SignersFileError>
where
{
    // Determine the path to the active signers file
    let active_signers_file = find_global_signers_for(dir_path.as_ref()).map_err(|e| {
        SignersFileError::InitialisationError(format!(
            "Active signers file not found for {}: {}",
            dir_path.as_ref().to_string_lossy(),
            e
        ))
    })?;

    // Check if the active signers file exists
    if !active_signers_file.exists() {
        return Err(SignersFileError::InitialisationError(format!(
            "Active signers file does not exist: {}",
            active_signers_file.to_string_lossy()
        )));
    }

    // Parse the active signers file
    let active_content = fs::read_to_string(&active_signers_file)?;
    let active_config: SignersConfig = parse_signers_config(&active_content)?;

    let proposed_update: SignersConfigProposal = parse_signers_config_proposal(json_content)?;
    if proposed_update.timestamp <= active_config.timestamp() {
        return Err(SignersFileError::InvalidData(format!(
            "Timestamp of update is smaller than active signers file's: update:{} <= active:{}",
            proposed_update.timestamp,
            active_config.timestamp()
        )));
    }
    // Check if the provided pubkey is in the admin_keys or master_keys groups
    let validator = || is_valid_signer_for_update_of(pubkey, &active_config);

    // If the check passes, call initialize_signers_file
    write_valid_signers_file(
        dir_path,
        json_content,
        metadata,
        signature,
        pubkey,
        validator,
    )
}

fn move_current_signers_to_history<Pa: AsRef<Path>>(dir: Pa) -> Result<(), SignersFileError> {
    let root_dir = dir.as_ref();
    let active_signers_dir = root_dir.join(SIGNERS_DIR);
    let active_signers_file = active_signers_dir.join(SIGNERS_FILE);
    let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

    // Read existing active signers configuration
    let existing_content = fs::read_to_string(&active_signers_file)?;
    let existing_config: SignersConfig = parse_signers_config(&existing_content)?;

    // Read the signatures file for the active signers
    let signatures_file_path = signatures_path_for(&active_signers_file)?;
    let signatures_content = fs::read_to_string(&signatures_file_path)?;
    let signatures: HashMap<String, String> = serde_json::from_str(&signatures_content)?;

    // Get current UTC time as ISO8601 string
    let obsoleted_at = chrono::Utc::now();

    // Create the history entry using the dedicated struct
    let history_entry = HistoryEntry {
        obsoleted_at,
        signers_file: existing_config,
        signatures,
    };

    // Read or create history file
    let mut history_file: HistoryFile = if history_file_path.exists() {
        let history_content = fs::read_to_string(&history_file_path)?;
        if history_content.trim().is_empty() {
            HistoryFile::new()
        } else {
            HistoryFile::from_json(&history_content)?
        }
    } else {
        HistoryFile::new()
    };

    // Append the new entry
    history_file.add_entry(history_entry);

    // Write updated history
    history_file.save_to_file(&history_file_path)?;

    // Remove existing active signers directory
    fs::remove_dir_all(&active_signers_dir)?;
    Ok(())
}

pub fn activate_signers_file<A>(agg_sig: A) -> Result<(), SignersFileError>
where
    A: Borrow<AggregateSignature<CompleteSignature>>,
{
    let agg_sig = agg_sig.borrow();
    if agg_sig.subject().is_artifact() {
        return Err(SignersFileError::FileSystemHierarchyError(format!(
            "Cannot activate a signers file for file of type {}",
            agg_sig.subject().kind()
        )));
    }
    let location = &agg_sig.subject().location();
    let signers_file_path = Path::new(location);

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
        move_current_signers_to_history(root_dir)?;
    }

    // Rename pending directory to active directory
    fs::rename(pending_dir, &active_signers_dir)?;

    Ok(())
}

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    /// ISO8601 formatted UTC date and time
    pub obsoleted_at: DateTime<Utc>,
    /// Content of the signers file
    pub signers_file: SignersConfig,
    /// Content of the signatures file (map from public key string to signature string)
    pub signatures: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryFile {
    /// Array of history entries, sorted chronologically
    pub entries: Vec<HistoryEntry>,
}

impl HistoryFile {
    /// Create a new empty history file
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a new entry to the history file
    pub fn add_entry(&mut self, entry: HistoryEntry) {
        self.entries.push(entry);
    }

    /// Get all entries in the history file
    pub fn entries(&self) -> &Vec<HistoryEntry> {
        &self.entries
    }

    /// Get the most recent entry in the history file
    pub fn latest_entry(&self) -> Option<&HistoryEntry> {
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

impl Default for HistoryFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to parse a history file from JSON string
pub fn parse_history_file(json_str: &str) -> Result<HistoryFile, serde_json::Error> {
    HistoryFile::from_json(json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use common::fs::names::local_signers_path_for;
    use common::sha512_for_file;
    use constants::{PENDING_SIGNATURES_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
    use signatures::keys::AsfaloadPublicKey;
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signatures::keys::AsfaloadSignatureTrait;
    use signers_file_types::KeyFormat;
    use signers_file_types::SignerKind;
    use signers_file_types::{Forge, ForgeOrigin};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    fn test_metadata() -> SignersConfigMetadata {
        SignersConfigMetadata::from_forge(ForgeOrigin::new(
            Forge::Github,
            "https://example.com/test".to_string(),
            chrono::Utc::now(),
        ))
    }

    fn assert_metadata_file_valid(root_dir: &Path, is_active: bool) {
        let dir_name = if is_active {
            SIGNERS_DIR
        } else {
            PENDING_SIGNERS_DIR
        };
        let metadata_path = root_dir.join(dir_name).join(METADATA_FILE);
        assert!(
            metadata_path.exists(),
            "metadata.json should exist in {}",
            dir_name
        );
        let content = fs::read_to_string(&metadata_path)
            .unwrap_or_else(|e| panic!("Failed to read metadata.json: {}", e));
        let _: SignersConfigMetadata = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to deserialize metadata.json: {}", e));
    }

    #[test]
    fn test_parsing() {
        let json_str = r#"
    {
      "version": 1,
      "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: SignersConfig =
            parse_signers_config(json_str.as_str()).expect("Failed to parse JSON");
        assert_eq!(config.version(), 1);
        assert_eq!(config.artifact_signers().len(), 1);
        assert_eq!(config.artifact_signers()[0].threshold, 2);
        assert_eq!(
            config.artifact_signers()[0].signers[0].kind,
            SignerKind::Key
        );
        assert_eq!(
            config.artifact_signers()[0].signers[0].data.format,
            KeyFormat::Minisign
        );
        assert_eq!(config.master_keys().unwrap_or_default().len(), 1);
        assert_eq!(config.master_keys().unwrap_or_default()[0].threshold, 2);
        assert_eq!(
            config.master_keys().unwrap_or_default()[0].signers[0].kind,
            SignerKind::Key
        );
        let admin_keys = config.admin_keys();
        assert_eq!(admin_keys[0].threshold, 3);
        assert_eq!(admin_keys[0].signers[0].kind, SignerKind::Key);

        // Check admin key are equal to artifact_signers if not set explicitly
        let json_str = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: SignersConfig =
            parse_signers_config(json_str.as_str()).expect("Failed to parse JSON");
        assert_eq!(config.version(), 1);
        assert_eq!(config.artifact_signers().len(), 1);
        assert_eq!(config.artifact_signers()[0].threshold, 3);
        assert_eq!(
            config.artifact_signers()[0].signers[0].kind,
            SignerKind::Key
        );
        assert_eq!(
            config.artifact_signers()[0].signers[0].data.format,
            KeyFormat::Minisign
        );
        assert_eq!(config.admin_keys(), config.artifact_signers());

        let json_str_with_invalid_b64_keys = r#"
    {
      "version": 1,
      "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: Result<SignersConfig, serde_json::Error> =
            parse_signers_config(json_str_with_invalid_b64_keys.as_str());
        assert!(config.is_err());
        let error = config.err().unwrap();
        assert!(
            error.to_string().starts_with(
            "Problem parsing pubkey base64: RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyvinvalid at line ")
        );

        // Test the threshold validation
        let json_str_with_invalid_threshold = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: Result<SignersConfig, serde_json::Error> =
            parse_signers_config(&json_str_with_invalid_threshold);
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
          "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: Result<SignersConfig, serde_json::Error> =
            parse_signers_config(&json_str_with_empty_master_signers_group);
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
          "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: Result<SignersConfig, serde_json::Error> =
            parse_signers_config(&json_str_with_empty_master_array);
        assert!(config.is_ok());

        // Test empty admin array
        // If the json holds an empty array for admins, it returns the artifact signers just as
        // when it is not present at all
        let json_str_with_empty_admin_array = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let result: Result<SignersConfig, serde_json::Error> =
            parse_signers_config(&json_str_with_empty_admin_array);
        assert!(result.is_ok());
        let config = result.unwrap();
        // Check admin_keys holds an one element array
        assert_eq!(config.admin_keys(), config.artifact_signers());

        let json_str_with_zero_threshold = r#"
    {
      "version": 1,
          "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let config: Result<SignersConfig, serde_json::Error> =
            parse_signers_config(&json_str_with_zero_threshold);
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
  "timestamp": "TIMESTAMP",
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

        let json_content = &test_keys
            .substitute_keys(json_content_template.to_string())
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
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
            test_metadata(),
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
        let _config: SignersConfig = parse_signers_config(&content).unwrap();

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
        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_initialize_signers_with_2_signers_threshold_1() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // Extract used keys
        let pub_key0 = test_keys.pub_key(0).unwrap().clone();
        let pub_key1 = test_keys.pub_key(1).unwrap().clone();
        let sec_key0 = test_keys.sec_key(0).unwrap();

        let signers_config =
            SignersConfig::with_keys(1, (vec![pub_key0.clone(), pub_key1.clone()], 1), None, None)?;
        let json_content = serde_json::json!(signers_config).to_string();

        //let json_content = &test_keys.substitute_keys(json_content_template.to_string());
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Get keys we work with here

        // Sign the hash
        let signature = sec_key0.sign(&hash_value).unwrap();

        // Call the function
        initialize_signers_file(
            dir_path,
            json_content,
            test_metadata(),
            &signature,
            &pub_key0,
        )
        .unwrap();

        // Even though we have a threshold 1, for a signers file initialisation we need
        // to collect signatures from all signers preseng in the file. That's why we
        // end up here with a pending signers dir and a pending agg sig.
        // Check that the pending file exists
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the content
        let content = fs::read_to_string(&pending_file_path).unwrap();
        // We don't compare exactly because of formatting, but we can parse it again to validate
        let _config: SignersConfig = parse_signers_config(&content).unwrap();

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
        assert!(sig_map.contains_key(&pub_key0.to_base64()));
        assert_eq!(
            sig_map.get(&pub_key0.to_base64()).unwrap(),
            &signature.to_base64()
        );
        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_initialize_signers_file_with_1_signer() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        let test_keys = TestKeys::new(3);

        // Get keys we work with here
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();

        // Build signers config
        let signers_config = SignersConfig::with_keys(1, (vec![pub_key.clone()], 1), None, None)?;
        let json_content = serde_json::json!(signers_config).to_string();
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Sign the hash
        let signature = sec_key.sign(&hash_value).unwrap();

        // Call the function
        initialize_signers_file(
            dir_path,
            json_content,
            test_metadata(),
            &signature,
            test_keys.pub_key(0).unwrap(),
        )
        .unwrap();

        // Check that the active file exists
        let active_file_path = dir_path.join(format!("{}/{}", SIGNERS_DIR, SIGNERS_FILE));
        assert!(active_file_path.exists());

        // Check the content
        let content = fs::read_to_string(&active_file_path).unwrap();
        // We don't compare exactly because of formatting, but we can parse it again to validate
        let _config: SignersConfig = parse_signers_config(&content).unwrap();

        // Check that the signature does not exist as the aggregate
        // signature is not complete
        let sig_file_path = dir_path.join(format!(
            "{}/{}.{}",
            SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(sig_file_path.exists());
        // Check the signature file content
        let sig_content = fs::read_to_string(sig_file_path).unwrap();
        let sig_map: std::collections::HashMap<String, String> =
            serde_json::from_str(&sig_content).unwrap();
        assert_eq!(sig_map.len(), 1);
        assert!(sig_map.contains_key(&pub_key.to_base64()));
        assert_eq!(
            sig_map.get(&pub_key.to_base64()).unwrap(),
            &signature.to_base64()
        );

        // Check no pending signers dir was left
        let pending_sig_dir = dir_path.join(PENDING_SIGNERS_DIR);
        assert!(!pending_sig_dir.exists());

        assert_metadata_file_valid(dir_path, true);
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
      "timestamp": "TIMESTAMP",
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
    "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Generate a different keypair (not in the config)
        // Get keys we work with here
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Sign the hash
        let signature = seckey.sign(&hash_value).unwrap();

        // Call the function - should fail due to invalid signer
        let result =
            initialize_signers_file(dir_path, json_content, test_metadata(), &signature, pubkey);
        assert!(result.is_err());
        match result {
            Err(SignersFileError::InvalidSigner(_)) => (), //expected
            Err(e) => panic!("Expected SignersFileError::InvalidSigner(_) but got {}", e),
            Ok(_) => panic!("Expected SignersFileError::InvalidSigner(_) but got a success value!"),
        }

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

        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?.to_json()?;

        // Sign different data (not the hash of the JSON)
        let signature = seckey
            .sign(&common::sha512_for_content(b"wrong data".to_vec())?)
            .unwrap();

        // Call the function - should fail due to invalid signature
        let result =
            initialize_signers_file(dir_path, json_content, test_metadata(), &signature, pubkey);
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

        // Get keys
        let pubkey0 = test_keys.pub_key(0).unwrap().clone();
        let pubkey2 = test_keys.pub_key(2).unwrap().clone();
        let pubkey3 = test_keys.pub_key(3).unwrap().clone();

        // Generate config
        let json_content = SignersConfig::with_keys(
            1,
            (vec![pubkey0.clone()], 1),
            Some((vec![pubkey2.clone(), pubkey3.clone()], 2)),
            None,
        )?
        .to_json()?;
        //
        // Get keys we work with here
        let non_admin_pubkey = pubkey0;
        let non_admin_seckey = test_keys.sec_key(0).unwrap();
        let admin_pubkey = pubkey2;
        let admin_seckey = test_keys.sec_key(2).unwrap();
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        // Reject new signers files signed by non admin keys
        // -------------------------------------------------
        // Sign the hash
        let non_admin_signature = non_admin_seckey.sign(&hash_value).unwrap();

        // Call the function
        let result = initialize_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &non_admin_signature,
            &non_admin_pubkey,
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
        initialize_signers_file(
            dir_path,
            json_content,
            test_metadata(),
            &admin_signature,
            &admin_pubkey,
        )?;
        // Check that the pending file exists
        assert!(pending_file_path.exists());

        // Check that the signature file does not exist as not all
        // required admin signatures where collected.
        assert!(!sig_file_path.exists());
        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }
    #[test]
    fn test_initialize_signers_file_with_one_signer() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Get keys we work with here
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();

        // Generate config
        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?.to_json()?;

        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        let pending_signers_dir = dir_path.join(PENDING_SIGNERS_DIR);
        let active_signers_dir = dir_path.join(SIGNERS_DIR);
        let active_signers_file = active_signers_dir.join(SIGNERS_FILE);
        let active_signers_file_signatures =
            active_signers_dir.join(format!("{}.{}", SIGNERS_FILE, SIGNATURES_SUFFIX));

        // Now sign proposal with unique artifact key which should be complete
        // ---------------------------------------------------------------
        let signature = seckey.sign(&hash_value).unwrap();
        let result =
            initialize_signers_file(dir_path, json_content, test_metadata(), &signature, pubkey);
        result.expect("initialize_signers_file should have succeeded");

        // Check that the signature file exists as all
        // required admin signatures where collected.
        assert!(!pending_signers_dir.exists());
        assert!(active_signers_dir.exists());
        assert!(active_signers_file.exists());
        assert!(active_signers_file_signatures.exists());
        assert_metadata_file_valid(dir_path, true);
        Ok(())
    }

    #[test]
    fn test_errors_in_initialize_signers_file() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pub_key.clone()], 1))?.to_json()?;
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let signature = sec_key.sign(&hash_value).unwrap();

        // Test for IO error: Make the directory read-only
        let mut perms = fs::metadata(dir_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(dir_path, perms).unwrap();

        // Try to initialize the signers file, which should fail with an IO error
        let result = initialize_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pub_key,
        );

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
        initialize_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pub_key,
        )
        .unwrap();
        // Threshold was one, so it is activated
        let pending_signers_file_path =
            dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_signers_file_path.exists());
        let active_signers_file_path = dir_path.join(format!("{}/{}", SIGNERS_DIR, SIGNERS_FILE));
        assert!(active_signers_file_path.exists());
        let result =
            initialize_signers_file(dir_path, json_content, test_metadata(), &signature, pub_key);
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

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pub_key.clone()], 1))?.to_json()?;
        // Compute the SHA-512 hash of the JSON content
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let signature = sec_key.sign(&hash_value).unwrap();

        // Create complete signature file, content does not matter, only existence.
        let aggregate_signature_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        std::fs::create_dir(aggregate_signature_path.parent().unwrap())?;
        std::fs::File::create(&aggregate_signature_path)?;

        // Try to initialize the signers file, which should fail with an Initialisation error
        let result =
            initialize_signers_file(dir_path, json_content, test_metadata(), &signature, pub_key);

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

        // Get keys and sign the hash
        let pub_key = test_keys.pub_key(0).unwrap();
        let sec_key = test_keys.sec_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pub_key.clone()], 1))?.to_json()?;
        let hash_value = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let signature = sec_key.sign(&hash_value).unwrap();

        // Create complete signature file, content does not matter, only existence.
        let existing_signers_path =
            dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        std::fs::create_dir(existing_signers_path.parent().unwrap())?;
        std::fs::File::create(existing_signers_path)?;

        // Try to initialize the signers file, which should fail with an Initialisation error
        let result =
            initialize_signers_file(dir_path, json_content, test_metadata(), &signature, pub_key);

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
        signed_file_path: &Path,
        test_keys: &TestKeys,
    ) -> Result<AggregateSignature<CompleteSignature>, SignersFileError> {
        // Compute the hash of the signers file
        let hash = common::sha512_for_file(signed_file_path)?;

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
        let _ = SignatureWithState::load_for_file(signed_file_path)?
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
        let sig_with_state = SignatureWithState::load_for_file(signed_file_path)?;
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
        activate_signers_file(agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = root_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        // Verify the content is preserved
        let active_content = fs::read_to_string(&active_signers_file)?;
        assert_eq!(active_content, signers_content.to_json()?);

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
        // The permalink is specific
        let existing_content_template = r#"
{
  "version": 1,
  "timestamp": "TIMESTAMP",
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
        let config_timestamp = chrono::Utc::now();
        let existing_content = existing_keys
            .substitute_keys(existing_content_template.to_string())
            .replace("TIMESTAMP", config_timestamp.to_string().as_str());
        fs::write(&existing_signers_file, existing_content)?;

        // Create the signatures file for the existing signers file
        let hash = common::sha512_for_file(&existing_signers_file)?;
        let pubkey0 = existing_keys.pub_key(0).unwrap();
        let seckey0 = existing_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Create signature of current signers file
        let _ = SignatureWithState::load_for_file(&existing_signers_file)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?;

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let completed_dir = root_dir.join(SIGNERS_DIR);
        let completed_signers_file_path = completed_dir.join(SIGNERS_FILE);

        // Use new_keys for the new signers config
        let new_content = create_test_signers_config(&new_keys);
        let new_signers_file_content = new_content.to_json()?;
        fs::write(&signers_file_path, &new_signers_file_content)?;
        let new_signers_content_hash = sha512_for_file(&signers_file_path)?;

        let existing_signer_sig = existing_keys
            .sec_key(0)
            .unwrap()
            .sign(&new_signers_content_hash)?;
        let sig_with_state_1 = SignatureWithState::load_for_file(&signers_file_path)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&existing_signer_sig, existing_keys.pub_key(0).unwrap())?;

        match sig_with_state_1 {
            SignatureWithState::Pending(_) => {} // expected
            // As we do an update of the signers file, we need the signatures to complete the
            // existing signers file + complete the new one + get signatures from those new in the new file.
            SignatureWithState::Complete(_) => panic!("Signature was expected to be incomplete!"),
        }

        // Create aggregate signature using new_keys
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &new_keys)?;
        agg_sig.save_to_file()?;

        // Activate the signers file
        activate_signers_file(agg_sig)?;

        // Verify the history file was created
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);
        assert!(history_file_path.exists());

        // Verify the history contains the old configuration
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        // Verify the old configuration is in the history
        let old_config_in_history = &history.entries[0].signers_file;
        assert_eq!(old_config_in_history.timestamp(), config_timestamp);

        // Verify the new configuration is active
        let new_active_content = fs::read_to_string(active_dir.join(SIGNERS_FILE))?;
        assert_eq!(new_active_content, new_content.to_json()?);

        let local_copy_path = local_signers_path_for(completed_signers_file_path)?;
        assert!(!local_copy_path.exists());
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

        // Create aggregate signature for a file with a signers file content but
        // with a different path
        let different_path = root_dir.join("different_file.json");
        fs::write(&different_path, &signers_content)?;

        // As this is an artifact file, the helper will look for an active signers file
        // when creating the agg sig. But it is not present, hence the error.
        let result = create_test_aggregate_signature(&different_path, &test_keys);

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::AggregateSignatureError(e) => {
                assert!(
                    e.to_string()
                        .contains("No signers file found in parent directories")
                );
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
    fn test_activate_signers_file_no_parent_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);

        // Create a file at the root level (no parent directory)
        let signers_file_path = temp_dir.path().join(SIGNERS_FILE);
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&signers_file_path, signers_content)?;

        // Create aggregate signature
        // As the file signed has the name of a signers file but is not in a signers dir,
        // it is handled as an artifact, which requires the presence of an active signers
        // file when signing. As there is none, it causes the error.
        let result = create_test_aggregate_signature(&signers_file_path, &test_keys);

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::AggregateSignatureError(e) => {
                assert!(
                    e.to_string()
                        .contains("No signers file found in parent directories")
                );
            }
            other => panic!(
                "Expected InitialisationError for path mismatch, got {:?}",
                other
            ),
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
        activate_signers_file(agg_sig)?;

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
        activate_signers_file(agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = nested_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signers file is in the active directory
        let active_signers_file = active_dir.join(SIGNERS_FILE);
        assert!(active_signers_file.exists());

        // Verify the content is preserved
        let active_content = fs::read_to_string(&active_signers_file)?;
        assert_eq!(active_content, signers_config.to_json()?);

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
        SignatureWithState::load_for_file(&signers_file_path)?
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
        let original_signers_config: SignersConfig =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Ensure history file doesn't exist initially
        assert!(!history_file_path.exists());

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history file was created
        assert!(history_file_path.exists());

        // Verify active directory was removed
        assert!(!signers_file_path.exists());
        assert!(!root_dir.join(SIGNERS_DIR).exists());

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_file: HistoryFile = serde_json::from_str(&history_content)?;
        let history_entries = history_file.entries;
        assert_eq!(history_entries.len(), 1);

        let entry = history_entries[0].clone();

        // Verify signers file content matches original
        let signers_file_in_history = entry.signers_file;
        assert_eq!(signers_file_in_history, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = entry.signatures;
        assert_eq!(signatures_in_history, original_signatures);

        Ok(())
    }

    #[test]
    fn test_move_to_history_appends_to_existing_history() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create existing history file
        // Note the timestamp of the history entry is earlier than its obsoleted_at field,
        // which makes it a consistent entry
        let existing_entry: HistoryEntry = serde_json::from_str(
            r#"{
            "obsoleted_at": "2023-01-01T00:00:00Z",
            "signers_file": {
                "version": 1,
                "timestamp": "2022-12-19T16:39:57Z",
                "artifact_signers": [
                    {
                    "signers": [
                        { "kind": "key", "data": { "format": "minisign", "pubkey": "RWRaOIhiXUjDgCLx2NwuLAVboIDMJZ32WagBSN2wjxlvYvdsvjmMzGy3"} }
                    ],
                    "threshold": 1
                    }
                ],
                "master_keys": [],
                "threshold": 1
            },
            "signatures": {}
        }"#,
        )?;

        let mut existing_history: HistoryFile = HistoryFile::new();
        existing_history.add_entry(existing_entry);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        // Read the existing history content before the move
        let original_history_content = fs::read_to_string(&history_file_path)?;
        let original_history: HistoryFile = serde_json::from_str(&original_history_content)?;
        let original_history_entries = original_history.entries;
        assert_eq!(original_history_entries.len(), 1);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_content = fs::read_to_string(&signers_file_path)?;
        let original_signers_config: SignersConfig =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history_content = fs::read_to_string(&history_file_path)?;
        let history_file: HistoryFile = serde_json::from_str(&history_content)?;
        let history_entries = history_file.entries;
        assert_eq!(history_entries.len(), 2);

        // Verify first entry is unchanged and matches the original
        let first_entry = &history_entries[0];
        let original_first_entry = &original_history_entries[0];
        assert_eq!(first_entry, original_first_entry);

        // Verify second entry is the new one with correct content
        let second_entry = &history_entries[1];

        // Verify signers file content matches original
        let signers_config_in_history = second_entry.clone().signers_file;
        assert_eq!(signers_config_in_history, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = second_entry.clone().signatures;
        assert_eq!(signatures_in_history, original_signatures);

        // Verify entries are sorted chronologically
        assert!(first_entry.obsoleted_at < second_entry.obsoleted_at);

        Ok(())
    }

    #[test]
    fn test_move_to_history_preserves_all_existing_entries() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create multiple existing history entries
        let entry1 = serde_json::from_str(
            r#"{
            "obsoleted_at": "2023-01-01T00:00:00Z",
            "signers_file": {
                "version": 1,
                "timestamp": "TIMESTAMP",
                "artifact_signers": [],
                "master_keys": []
            },
            "signatures": {"key1": "sig1"}
        }"#
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .as_str(),
        )?;

        let entry2 = serde_json::from_str(
            r#"{
            "obsoleted_at": "2023-02-01T00:00:00Z",
            "signers_file": {
                "version": 2,
                "timestamp": "TIMESTAMP",
                "artifact_signers": [],
                "master_keys": []
            },
            "signatures": {"key2": "sig2"}
        }"#
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .as_str(),
        )?;

        let mut existing_history: HistoryFile = HistoryFile::new();
        existing_history.add_entry(entry1);
        existing_history.add_entry(entry2);
        fs::write(
            &history_file_path,
            serde_json::to_string_pretty(&existing_history)?,
        )?;

        assert_eq!(existing_history.entries.len(), 2);

        // Create active signers setup
        let signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Read the original signers file content
        let original_signers_content = fs::read_to_string(&signers_file_path)?;
        let original_signers_config: SignersConfig =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 3);

        // Verify all existing entries are unchanged
        for i in 0..existing_history.entries.len() {
            assert_eq!(&history.entries[i], &existing_history.entries[i]);
        }

        // Verify the new entry is the last one with correct content
        let new_entry = &history.entries[2];

        // Verify signers file content matches original
        let signers_file_in_history = new_entry.signers_file.clone();
        assert_eq!(signers_file_in_history, original_signers_config);

        // Verify signatures content matches original
        let signatures_in_history = new_entry.signatures.clone();
        assert_eq!(signatures_in_history, original_signatures);

        // Verify entries are sorted chronologically
        for i in 0..history.entries.len() - 1 {
            let current_time = history.entries[i].obsoleted_at;
            let next_time = history.entries[i + 1].obsoleted_at;
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
        let _signers_file_path = create_test_active_signers(root_dir, &test_keys)?;
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Record time before operation
        let before_time = Utc::now();

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Record time after operation
        let after_time = Utc::now();

        // Verify history content
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        let entry = &history.entries[0];
        let timestamp = entry.obsoleted_at;

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
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        let entry = &history.entries[0];
        let signatures_in_history = entry.signatures.clone();

        // Verify signatures content is preserved
        assert_eq!(signatures_in_history, original_signatures);

        Ok(())
    }

    #[test]
    fn test_move_to_history_with_multiple_entries_sorted() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);
        let history_file_path = root_dir.join(SIGNERS_HISTORY_FILE);

        // Create multiple existing history entries with different timestamps
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z".parse().unwrap());

        let mut existing_history: HistoryFile = HistoryFile::new();
        existing_history.add_entry(entry1);
        existing_history.add_entry(entry2);
        existing_history.save_to_file(&history_file_path)?;

        // Create active signers setup
        let _signers_file_path = create_test_active_signers(root_dir, &test_keys)?;

        // Record time before operation
        let before_time = Utc::now();

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 3);

        // Verify entries are sorted chronologically
        for i in 0..history.entries.len() - 1 {
            let current_time: DateTime<Utc> = history.entries[i].obsoleted_at;
            let next_time: DateTime<Utc> = history.entries[i + 1].obsoleted_at;
            assert!(current_time <= next_time);
        }

        // Verify the new entry is the last one
        let last_entry = &history.entries[2];
        let last_timestamp: DateTime<Utc> = last_entry.obsoleted_at;
        assert!(last_timestamp >= before_time);

        Ok(())
    }

    #[test]
    fn test_move_to_history_error_when_no_active_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();

        // Don't create active signers directory
        let result = move_current_signers_to_history(root_dir);

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
        let result = move_current_signers_to_history(root_dir);

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
        let original_signers_config: SignersConfig =
            parse_signers_config(&original_signers_content)?;

        // Read the original signatures file content
        let signatures_file_path = signatures_path_for(&signers_file_path)?;
        let original_signatures_content = fs::read_to_string(&signatures_file_path)?;
        let original_signatures: HashMap<String, String> =
            serde_json::from_str(&original_signatures_content)?;

        // Move to history
        move_current_signers_to_history(root_dir)?;

        // Verify history content
        let history: HistoryFile = HistoryFile::load_from_file(&history_file_path)?;
        assert_eq!(history.entries.len(), 1);

        let entry = &history.entries[0];

        // Verify signers file content matches original
        assert_eq!(entry.signers_file, original_signers_config);

        // Verify signatures content matches original
        assert_eq!(entry.signatures, original_signatures);

        // Verify active directory was removed
        assert!(!signers_file_path.exists());
        assert!(!root_dir.join(SIGNERS_DIR).exists());

        Ok(())
    }
    // History file serialisation tests
    // --------------------------------

    // Helper function to create a test signers config
    fn create_test_signers_config(test_keys: &TestKeys) -> SignersConfig
    where
        AsfaloadPublicKey<minisign::PublicKey>: AsfaloadPublicKeyTrait,
    {
        SignersConfig::with_keys(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
            None,
            None,
        )
        .unwrap()
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
    fn create_test_history_entry(test_keys: &TestKeys, timestamp: DateTime<Utc>) -> HistoryEntry {
        HistoryEntry {
            obsoleted_at: timestamp,
            signers_file: create_test_signers_config(test_keys),
            signatures: create_test_signatures(test_keys),
        }
    }

    #[test]
    fn test_history_entry_creation() {
        let test_keys = TestKeys::new(2);
        let timestamp: DateTime<Utc> = "2023-01-01T00:00:00Z".parse().unwrap();

        let entry = create_test_history_entry(&test_keys, timestamp);

        assert_eq!(entry.obsoleted_at, timestamp);
        assert_eq!(entry.signers_file.version(), 1);
        assert_eq!(entry.signers_file.artifact_signers().len(), 1);
        assert_eq!(entry.signers_file.artifact_signers()[0].threshold, 2);
        assert_eq!(entry.signers_file.artifact_signers()[0].signers.len(), 2);
        assert_eq!(entry.signatures.len(), 2);
    }

    #[test]
    fn test_history_file_new() {
        let history_file: HistoryFile = HistoryFile::new();

        assert!(history_file.entries().is_empty());
    }

    #[test]
    fn test_history_file_default() {
        let history_file: HistoryFile = HistoryFile::default();

        assert!(history_file.entries().is_empty());
    }

    #[test]
    fn test_history_file_add_entry() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z".parse().unwrap());

        history_file.add_entry(entry1);
        history_file.add_entry(entry2);

        assert_eq!(history_file.entries().len(), 2);
        assert_eq!(
            history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(
            history_file.entries()[1].obsoleted_at,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_history_file_latest_entry() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        // Empty history file
        assert!(history_file.latest_entry().is_none());

        // Add one entry
        let entry1 = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry1);
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // Add another entry
        let entry2 = create_test_history_entry(
            &test_keys,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry2);
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_history_file_to_json() {
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
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
        "timestamp": "TIMESTAMP",
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
            .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str())
            .replace("PUBKEY0_PLACEHOLDER", &pubkey0)
            .replace("PUBKEY1_PLACEHOLDER", &pubkey1)
            .replace("SIGNATURE0_PLACEHOLDER", &signature0_b64)
            .replace("SIGNATURE1_PLACEHOLDER", &signature1_b64);

        // Parse the history file
        let history_file: HistoryFile = parse_history_file(&json_content).unwrap();

        // Verify the content
        assert_eq!(history_file.entries().len(), 1);
        assert_eq!(
            history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(history_file.entries()[0].signers_file.version(), 1);
        assert_eq!(
            history_file.entries()[0]
                .signers_file
                .artifact_signers()
                .len(),
            1
        );
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers()[0].threshold,
            2
        );
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers()[0]
                .signers
                .len(),
            2
        );

        // Verify the public keys in the signers file
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers()[0].signers[0]
                .data
                .pubkey
                .to_base64(),
            pubkey0
        );
        assert_eq!(
            history_file.entries()[0].signers_file.artifact_signers()[0].signers[1]
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
          "timestamp": "TIMESTAMP",
      "artifact_signers": [],
      "master_keys": [],
      "admin_keys": null
    },
    "signatures": {}
  }
]
}
"#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let result: Result<HistoryFile, _> = parse_history_file(&invalid_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_history_file_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history.json");
        let test_keys = TestKeys::new(2);
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        history_file.add_entry(entry);

        // Save to file
        history_file.save_to_file(&file_path).unwrap();
        assert!(file_path.exists());

        // Load from file
        let loaded_history_file: HistoryFile = HistoryFile::load_from_file(&file_path).unwrap();

        // Verify content
        assert_eq!(loaded_history_file.entries().len(), 1);
        assert_eq!(
            loaded_history_file.entries()[0].obsoleted_at,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(loaded_history_file.entries()[0].signers_file.version(), 1);
        assert_eq!(loaded_history_file.entries()[0].signatures.len(), 2);
    }

    #[test]
    fn test_history_file_load_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.json");

        let result: Result<HistoryFile, _> = HistoryFile::load_from_file(&file_path);

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
        let mut history_file: HistoryFile = HistoryFile::new();

        let entry = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
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
        let mut history_file: HistoryFile = HistoryFile::new();

        // Add multiple entries with different timestamps
        let entry1 = create_test_history_entry(
            &test_keys,
            "2023-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        let entry2 = create_test_history_entry(
            &test_keys,
            "2023-02-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );
        let entry3 = create_test_history_entry(
            &test_keys,
            "2023-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        );

        history_file.add_entry(entry1);
        history_file.add_entry(entry2);
        history_file.add_entry(entry3);

        // Verify all entries are present
        assert_eq!(history_file.entries().len(), 3);

        // Verify chronological order
        for i in 0..history_file.entries().len() - 1 {
            let current_time: DateTime<Utc> = history_file.entries()[i].obsoleted_at;
            let next_time: DateTime<Utc> = history_file.entries()[i + 1].obsoleted_at;
            assert!(current_time <= next_time);
        }

        // Verify latest entry
        assert_eq!(
            history_file.latest_entry().unwrap().obsoleted_at,
            "2023-03-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_history_file_roundtrip() {
        let test_keys = TestKeys::new(2);
        let mut original_history_file: HistoryFile = HistoryFile::new();

        // Add multiple entries
        let entry1 = create_test_history_entry(&test_keys, "2023-01-01T00:00:00Z".parse().unwrap());
        let entry2 = create_test_history_entry(&test_keys, "2023-02-01T00:00:00Z".parse().unwrap());

        original_history_file.add_entry(entry1);
        original_history_file.add_entry(entry2);

        // Convert to JSON and back
        let json = original_history_file.to_json().unwrap();
        let deserialized_history_file: HistoryFile = parse_history_file(&json).unwrap();

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
        let mut history_file: HistoryFile = HistoryFile::new();

        // Create an entry with empty signatures
        let entry = HistoryEntry {
            obsoleted_at: "2023-01-01T00:00:00Z".parse().unwrap(),
            signers_file: create_test_signers_config(&test_keys),
            signatures: HashMap::new(),
        };

        history_file.add_entry(entry);

        // Verify it serializes and deserializes correctly
        let json = history_file.to_json().unwrap();
        let deserialized: HistoryFile = parse_history_file(&json).unwrap();

        assert_eq!(deserialized.entries().len(), 1);
        assert_eq!(deserialized.entries()[0].signatures.len(), 0);
    }

    // Helper function to create a test active signers setup
    fn create_test_active_signers_for_update(
        root_dir: &Path,
        test_keys: &TestKeys,
        admin_count: usize,
        master_count: usize,
    ) -> Result<PathBuf, SignersFileError> {
        let active_signers_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;

        let signers_file_path = active_signers_dir.join(SIGNERS_FILE);

        // Create a template for the active signers content
        let mut template = r#"
{
  "version": 1,
  "timestamp": "TIMESTAMP",
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER" } },
        { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
      ],
      "threshold": 2
    }
  ]
  "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());
        let mut key_index = 2;

        if master_count > 0 {
            template.push_str(
                r#",
  "master_keys": [
    {
      "signers": [ "#,
            );

            for master in 0..master_count {
                template.push_str(
                format!(r#"        {{ "kind": "key", "data": {{ "format": "minisign", "pubkey": "PUBKEY{key_index}_PLACEHOLDER" }} }}
  "#).as_ref(),
            );
                if master < master_count - 1 {
                    template.push(',');
                }
                key_index += 1;
            }

            template.push_str(
                format!(
                    r#"
        ],
      "threshold": {master_count}
    }}
  ]"#
                )
                .as_ref(),
            );
        } else {
            template.push_str(
                r#",
  "master_keys": []"#,
            );
        }

        if admin_count > 0 {
            template.push_str(
                r#",
  "admin_keys": [
    {
      "signers": [ "#,
            );

            for admin in 0..admin_count {
                template.push_str(
                format!(r#"        {{ "kind": "key", "data": {{ "format": "minisign", "pubkey": "PUBKEY{key_index}_PLACEHOLDER" }} }}
  "#).as_ref(),
            );
                key_index += 1;
                if admin < admin_count - 1 {
                    template.push(',');
                }
            }

            template.push_str(
                format!(
                    r#"
        ],
      "threshold": {admin_count}
    }}
  ]"#
                )
                .as_ref(),
            );
        }

        template.push_str("\n}");

        // Substitute placeholders with actual keys
        let content = test_keys.substitute_keys(template);
        fs::write(&signers_file_path, content)?;

        // Create signatures for the active signers file
        let hash = common::sha512_for_file(&signers_file_path)?;

        // Sign with the first two keys (artifact signers)
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the aggregate signature
        SignatureWithState::load_for_file(&signers_file_path)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature1, pubkey1)?;

        let key_index = 2;
        // If master keys are included, sign with them too
        if master_count > 0 {
            let sig = SignatureWithState::load_for_file(&signers_file_path)?;

            (0..master_count)
                .collect::<Vec<usize>>()
                .iter()
                .fold(sig, |acc, i| {
                    let pubkey = test_keys.pub_key(i + key_index).unwrap();
                    let seckey = test_keys.sec_key(i + key_index).unwrap();
                    let signature = seckey.sign(&hash).unwrap();

                    acc.get_pending()
                        .unwrap()
                        .add_individual_signature(&signature, pubkey)
                        .unwrap()
                });
        }

        let key_index = 2 + master_count;
        // If admin keys are included, sign with them too
        if admin_count > 0 {
            let sig = SignatureWithState::load_for_file(&signers_file_path)?;

            (0..admin_count)
                .collect::<Vec<usize>>()
                .iter()
                .fold(sig, |acc, i| {
                    let pubkey = test_keys.pub_key(i + key_index).unwrap();
                    let seckey = test_keys.sec_key(i + key_index).unwrap();
                    let signature = seckey.sign(&hash).unwrap();

                    acc.get_pending()
                        .unwrap()
                        .add_individual_signature(&signature, pubkey)
                        .unwrap()
                });
        }

        Ok(signers_file_path)
    }

    // Helper function to create a test proposal
    fn create_test_proposal(
        test_keys: &TestKeys,
        signer_index: usize,
    ) -> (String, AsfaloadSignatures, &AsfaloadPublicKeys) {
        // Create a template for the proposal
        let template = r#"
{
  "version": 2,
          "timestamp": "TIMESTAMP",
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
"#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Substitute placeholders with actual keys
        let content = test_keys.substitute_keys(template.to_string());

        // Compute hash and sign
        let hash = common::sha512_for_content(content.as_bytes().to_vec()).unwrap();
        let pubkey = test_keys.pub_key(signer_index).unwrap();
        let seckey = test_keys.sec_key(signer_index).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        (content, signature, pubkey)
    }

    #[test]
    fn test_propose_signers_file_with_admin_signer() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create a proposal signed by an admin key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 2);

        // Propose the new signers file
        propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        )?;

        // Verify the active file was created as we have a threshold of 1
        let pending_file_path = root_dir.join(format!("{}/{}", SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        // Verify the pending signature is not there as signature is complete
        let pending_sig_file_path = root_dir.join(format!(
            "{}/{}.{}",
            SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(!pending_sig_file_path.exists());

        // Verify the complete signature file is present
        let complete_sig_file_path = root_dir.join(format!(
            "{}/{}.{}",
            SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(complete_sig_file_path.exists());

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_wrong_timestamp() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create a proposal signed by an admin key before we setup the active signers file
        // This means that the timestamp of the update will be smaller than the active signers
        // file, which we reject
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 2);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        match result {
            Err(SignersFileError::InvalidData(s)) => {
                assert!(s.starts_with("Timestamp of update is smaller than active signers file's:"))
            }
            Err(e) => panic!(
                "Expected InvalidaData(Timestamp of update is smaller than active signers file's), but got {} ",
                e
            ),
            Ok(_) => panic!(
                "Expected InvalidaData(Timestamp of update is smaller than active signers file's) but got a success result!"
            ),
        }
        Ok(())
    }
    #[test]
    fn test_propose_signers_file_with_multiple_admin_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(5);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 2, 0)?;

        // Create a proposal signed by an admin key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 2);

        // Propose the new signers file
        propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        )?;

        // Verify the pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        // Verify the pending signature is there as signature is incomplete
        let pending_sig_file_path = root_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_file_path.exists());

        // Verify the complete signature file was created
        let complete_sig_file_path = root_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!complete_sig_file_path.exists());

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_multiple_master_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(5);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 2)?;

        // Create a proposal signed by an admin key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 2);

        // Propose the new signers file
        propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        )?;

        // Verify the pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        // Verify the pending signature not there as signature is incomplete
        let pending_sig_file_path = root_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_file_path.exists());

        // Verify the complete signature file was created
        let complete_sig_file_path = root_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!complete_sig_file_path.exists());

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_master_signer() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // Create active signers with master keys
        create_test_active_signers_for_update(root_dir, &test_keys, 0, 1)?;

        // Create a proposal signed by a master key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 2);

        // Propose the new signers file
        propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        )?;

        // Verify the pending file is created. Threshold is 1, but need signature from previous
        // signers file.
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Check the pending signers dir is  present
        let pending_signers_dir = root_dir.join(PENDING_SIGNERS_DIR);
        assert!(pending_signers_dir.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        // Verify the pending signature is there (previous signers have not signed!)
        let pending_signatures_file_path = root_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_signatures_file_path.exists());

        // Verify the complete signature file was not created
        let complete_signatures_file_path = root_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!complete_signatures_file_path.exists());
        // Check no local copy of the signers was taken as it is a signers file
        let local_signers_path = root_dir.join(format!(
            "{}/{}.{}",
            SIGNERS_DIR, SIGNERS_FILE, SIGNERS_SUFFIX
        ));
        assert!(!local_signers_path.exists());

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_artifact_signer_fails_when_admin_group_present() -> Result<()>
    {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers without admin or master keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create a proposal signed by an artifact key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 0);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        // Verify it fails because when there is an admin group, the artifact signers cannot
        // propose a new signers file
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(_) => {} // Expected
            e => panic!("Expected InvalidSigner error, got {}", e),
        }

        // Verify no pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_artifact_signer_ok_when_no_admin_group_present() -> Result<()>
    {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create active signers without admin or master keys
        create_test_active_signers_for_update(root_dir, &test_keys, 0, 0)?;

        // Create a proposal signed by an artifact key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 0);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        assert!(result.is_ok());

        // Verify no pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        assert_metadata_file_valid(root_dir, false);
        Ok(())
    }
    #[test]
    fn test_propose_signers_file_without_active_signers_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Don't create active signers

        // Create a proposal
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 0);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify no pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_invalid_signature_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create a proposal
        let (proposal_content, _, pubkey) = create_test_proposal(&test_keys, 2);

        // Create an invalid signature (sign wrong data)
        let wrong_hash = common::sha512_for_content(b"wrong data".to_vec())?;
        let seckey = test_keys.sec_key(3).unwrap();
        let invalid_signature = seckey.sign(&wrong_hash).unwrap();

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &invalid_signature,
            pubkey,
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::SignatureVerificationFailed(_) => {} // Expected
            e => panic!("Expected SignatureVerificationFailed error, got {}", e),
        }

        // Verify no pending file was created
        let pending_file_path = root_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(!pending_file_path.exists());

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_existing_pending_file_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create an existing pending file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_file_path = pending_dir.join(SIGNERS_FILE);
        fs::write(&pending_file_path, "existing content")?;

        // Create a proposal
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 3);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify the existing pending file is unchanged
        let content = fs::read_to_string(&pending_file_path)?;
        assert_eq!(content, "existing content");

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_existing_pending_signature_file_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create an existing pending signature file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let pending_sig_file_path =
            pending_dir.join(format!("{}.{}", SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX));
        fs::write(&pending_sig_file_path, "existing signature")?;

        // Create a proposal
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 3);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify the existing pending signature file is unchanged
        let content = fs::read_to_string(&pending_sig_file_path)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_with_existing_complete_signature_file_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create an existing complete signature file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let complete_sig_file_path =
            pending_dir.join(format!("{}.{}", SIGNERS_FILE, SIGNATURES_SUFFIX));
        fs::write(&complete_sig_file_path, "existing signature")?;

        // Create a proposal
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 3);

        // Try to propose the new signers file
        let result = propose_signers_file(
            root_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        );

        // Verify it fails
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(_) => {} // Expected
            _ => panic!("Expected InitialisationError error"),
        }

        // Verify the existing complete signature file is unchanged
        let content = fs::read_to_string(&complete_sig_file_path)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_propose_signers_file_for_nested_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        let test_keys = TestKeys::new(4);

        // Create active signers with admin keys in nested directory
        create_test_active_signers_for_update(root_dir, &test_keys, 1, 0)?;

        // Create a proposal signed by an admin key
        let (proposal_content, signature, pubkey) = create_test_proposal(&test_keys, 2);

        // Propose the new signers file
        propose_signers_file(
            &nested_dir,
            &proposal_content,
            test_metadata(),
            &signature,
            pubkey,
        )?;

        // Verify the pending file was created in the nested directory
        // File is pending as old signers did not sign the update
        let pending_file_path =
            nested_dir.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_file_path)?;
        let _config: SignersConfig = parse_signers_config(&content)?;

        // Check the signature was transitioned to complete
        let pending_signature_path = nested_dir.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_signature_path.exists());

        assert_metadata_file_valid(&nested_dir, false);
        Ok(())
    }

    // is_valid_signer_for_signer_init
    // -------------------------------
    #[test]
    fn test_is_valid_signer_for_signer_init() {
        let test_keys = TestKeys::new(5);

        // Create a test config with admin and artifact signers
        let json_content_template = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
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
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content = test_keys.substitute_keys(json_content_template.to_string());
        let config: SignersConfig = parse_signers_config(&json_content).unwrap();

        // Test with a valid admin signer
        let admin_pubkey = test_keys.pub_key(2).unwrap();
        assert!(is_valid_signer_for_signer_init(admin_pubkey, &config).is_ok());

        // Test with a valid artifact signer, but not accepted as first signer (when admin_keys is present, artifact signers are not valid)
        let artifact_pubkey = test_keys.pub_key(0).unwrap();
        assert!(is_valid_signer_for_signer_init(artifact_pubkey, &config).is_err());

        // Test with an invalid signer (not in the config)
        let invalid_pubkey = test_keys.pub_key(4).unwrap();
        let result = is_valid_signer_for_signer_init(invalid_pubkey, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(msg) => {
                assert!(msg.contains("not in the required groups for signers init"));
            }
            _ => panic!("Expected InvalidSigner error"),
        }

        // Test with a config that has no admin_keys (artifact_signers should be valid)
        let json_content_no_admin = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} },
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER"} }
              ],
              "threshold": 2
            }
          ],
          "master_keys": []
        }
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content_no_admin = test_keys.substitute_keys(json_content_no_admin.to_string());
        let config_no_admin: SignersConfig = parse_signers_config(&json_content_no_admin).unwrap();

        // Test with a valid artifact signer (when admin_keys is not present)
        let artifact_pubkey = test_keys.pub_key(0).unwrap();
        assert!(is_valid_signer_for_signer_init(artifact_pubkey, &config_no_admin).is_ok());

        // Test with an invalid signer (not in the config)
        let invalid_pubkey = test_keys.pub_key(2).unwrap(); // This key is not in the artifact_signers
        let result = is_valid_signer_for_signer_init(invalid_pubkey, &config_no_admin);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(msg) => {
                assert!(msg.contains("not in the required groups for signers init"));
            }
            e => panic!("Expected InvalidSigner error, got {}", e),
        }
    }

    #[test]
    fn test_is_valid_signer_for_update_of() {
        let test_keys = TestKeys::new(5);

        // Create a test config with admin, master, and artifact signers
        let json_content_template = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} },
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER"} }
              ],
              "threshold": 2
            }
          ],
          "master_keys": [
            {
              "signers": [
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER"} }
              ],
              "threshold": 1
            }
          ],
          "admin_keys": [
            {
              "signers": [
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER"} }
              ],
              "threshold": 1
            }
          ]
        }
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content = test_keys.substitute_keys(json_content_template.to_string());
        let config: SignersConfig = parse_signers_config(&json_content).unwrap();

        // Test with a valid admin signer
        let admin_pubkey = test_keys.pub_key(3).unwrap();
        assert!(is_valid_signer_for_update_of(admin_pubkey, &config).is_ok());

        // Test with a valid master signer
        let master_pubkey = test_keys.pub_key(2).unwrap();
        assert!(is_valid_signer_for_update_of(master_pubkey, &config).is_ok());

        // Test with an artifact signer (should not be valid for updates as there is an admin group)
        let artifact_pubkey = test_keys.pub_key(0).unwrap();
        let result = is_valid_signer_for_update_of(artifact_pubkey, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(msg) => {
                assert!(
                    msg.contains("not in the required groups of current config for signers update")
                );
            }
            e => panic!("Expected InvalidSigner error, got {}", e),
        }

        // Test with an invalid signer (not in the config)
        let invalid_pubkey = test_keys.pub_key(4).unwrap();
        let result = is_valid_signer_for_update_of(invalid_pubkey, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(msg) => {
                assert!(
                    msg.contains("not in the required groups of current config for signers update")
                );
            }
            _ => panic!("Expected InvalidSigner error"),
        }

        // Test with a config that has no admin_keys (artifact_signers should be used as admin)
        let json_content_no_admin = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
          "artifact_signers": [
            {
              "signers": [
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY0_PLACEHOLDER"} },
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER"} }
              ],
              "threshold": 2
            }
          ],
          "master_keys": [
            {
              "signers": [
                { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER"} }
              ],
              "threshold": 1
            }
          ]
        }
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content_no_admin = test_keys.substitute_keys(json_content_no_admin.to_string());
        let config_no_admin: SignersConfig = parse_signers_config(&json_content_no_admin).unwrap();

        // Test with a valid artifact signer (when admin_keys is not present, artifact_signers are used as admin)
        let artifact_pubkey = test_keys.pub_key(0).unwrap();
        assert!(is_valid_signer_for_update_of(artifact_pubkey, &config_no_admin).is_ok());

        // Test with a valid master signer
        let master_pubkey = test_keys.pub_key(2).unwrap();
        assert!(is_valid_signer_for_update_of(master_pubkey, &config_no_admin).is_ok());

        // Test with an invalid signer (not in the config)
        let invalid_pubkey = test_keys.pub_key(3).unwrap();
        let result = is_valid_signer_for_update_of(invalid_pubkey, &config_no_admin);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(msg) => {
                assert!(
                    msg.contains("not in the required groups of current config for signers update")
                );
            }
            e => panic!("Expected InvalidSigner error, got {}", e),
        }
    }

    // write_valid_signers_file
    // ------------------------
    #[test]
    fn test_write_valid_signers_file_success_incomplete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // Create a test config with threshold 2 (incomplete with 1 signature)
        let json_content_template = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
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
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content = test_keys.substitute_keys(json_content_template.to_string());
        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        // Create a validator that always succeeds
        let signer_validator = || Ok(());

        // Call write_valid_signers_file
        write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        )?;

        // Verify pending signers file exists
        let pending_file_path = dir_path.join(format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE));
        assert!(pending_file_path.exists());

        // Verify content matches
        let content = fs::read_to_string(&pending_file_path)?;
        assert_eq!(content, json_content);

        // Verify pending signature file exists (incomplete signature)
        let pending_sig_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify complete signature file does not exist
        let complete_sig_path = dir_path.join(format!(
            "{}/{}.{}",
            PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(!complete_sig_path.exists());

        // Verify signature content
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 1);
        assert!(sig_map.contains_key(&pubkey.to_base64()));
        assert_eq!(
            sig_map.get(&pubkey.to_base64()).unwrap(),
            &signature.to_base64()
        );

        assert_metadata_file_valid(dir_path, false);
        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_success_complete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test config with threshold 1 (complete with 1 signature)
        let json_content_template = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
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
        "#
        .replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let json_content = test_keys.substitute_keys(json_content_template.to_string());
        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;

        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        // Create a validator that always succeeds
        let signer_validator = || Ok(());

        // Call write_valid_signers_file
        write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        )?;

        // Verify pending signers file exists
        let active_file_path = dir_path.join(format!("{}/{}", SIGNERS_DIR, SIGNERS_FILE));
        assert!(active_file_path.exists());

        // Verify complete signature file exists (complete signature)
        let complete_sig_path = dir_path.join(format!(
            "{}/{}.{}",
            SIGNERS_DIR, SIGNERS_FILE, SIGNATURES_SUFFIX
        ));
        assert!(complete_sig_path.exists());

        // Verify pending signature file does not exist
        let pending_sig_dir = dir_path.join(PENDING_SIGNERS_DIR);
        assert!(!pending_sig_dir.exists());

        assert_metadata_file_valid(dir_path, true);
        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_existing_signers_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create an existing signers file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let existing_file = pending_dir.join(SIGNERS_FILE);
        fs::write(&existing_file, "existing content")?;

        let json_content = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let validator = || Ok(());

        // Should fail
        let result = write_valid_signers_file(
            dir_path,
            json_content.as_str(),
            test_metadata(),
            &signature,
            pubkey,
            validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Signers file exists"));
            }
            e => panic!("Expected InitialisationError, got {}", e),
        }

        // Verify existing file is unchanged
        let content = fs::read_to_string(&existing_file)?;
        assert_eq!(content, "existing content");

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_existing_pending_signature() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create an existing pending signature file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let existing_sig =
            pending_dir.join(format!("{}.{}", SIGNERS_FILE, PENDING_SIGNATURES_SUFFIX));
        fs::write(&existing_sig, "existing signature")?;

        let json_content = r#"
        {
          "version": 1,
      "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let validator = || Ok(());

        // Should fail
        let result = write_valid_signers_file(
            dir_path,
            json_content.as_str(),
            test_metadata(),
            &signature,
            pubkey,
            validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Pending signature file exists"));
            }
            _ => panic!("Expected InitialisationError"),
        }

        // Verify existing signature file is unchanged
        let content = fs::read_to_string(&existing_sig)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_existing_complete_signature() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create an existing complete signature file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let existing_sig = pending_dir.join(format!("{}.{}", SIGNERS_FILE, SIGNATURES_SUFFIX));
        fs::write(&existing_sig, "existing signature")?;

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let signer_validator = || Ok(());

        // Should fail
        let result = write_valid_signers_file(
            dir_path,
            json_content.as_str(),
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(msg.contains("Complete signature file exists"));
            }
            _ => panic!("Expected InitialisationError"),
        }

        // Verify existing signature file is unchanged
        let content = fs::read_to_string(&existing_sig)?;
        assert_eq!(content, "existing signature");

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_invalid_json() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let invalid_json = r#"
        {
          "version": "invalid",
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(invalid_json.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let signer_validator = || Ok(());

        // Should fail
        let result = write_valid_signers_file(
            dir_path,
            &invalid_json,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::JsonError(_) => {} // Expected
            e => panic!("Expected JsonError, got {}", e),
        }

        // Verify no files were created
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        assert!(!pending_dir.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_validator_error() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        // Create a validator that fails
        let signer_validator = || Err(SignersFileError::InvalidSigner("test error".to_string()));

        // Should fail
        let result = write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InvalidSigner(msg) => {
                assert_eq!(msg, "test error");
            }
            e => panic!("Expected InvalidSigner error, got {}", e),
        }

        // Verify no files were created
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        assert!(!pending_dir.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_fails_with_invalid_signature() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        // Sign wrong data
        let wrong_hash = common::sha512_for_content(b"wrong data".to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let invalid_signature = seckey.sign(&wrong_hash)?;

        let signer_validator = || Ok(());

        // Should fail
        let result = write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &invalid_signature,
            pubkey,
            signer_validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::SignatureVerificationFailed(_) => {} // Expected
            e => panic!("Expected SignatureVerificationFailed error, got {}", e),
        }

        // Verify no files were created
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        assert!(!pending_dir.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_with_nested_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let nested_dir = root_dir.join("nested");
        let test_keys = TestKeys::new(1);

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let signer_validator = || Ok(());

        // Should succeed
        write_valid_signers_file(
            &nested_dir,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        )?;

        // Verify files are in the nested directory
        let pending_dir = nested_dir.join(PENDING_SIGNERS_DIR);
        assert!(pending_dir.exists());

        let pending_file = pending_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_io_error_on_write() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create the pending directory but make it read-only
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;

        let mut perms = fs::metadata(&pending_dir)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&pending_dir, perms)?;

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let signer_validator = || Ok(());

        // Should fail with IO error
        let result = write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::IoError(e) => {} // Expected
            e => panic!("Expected IoError, got {}", e),
        }

        // The rollback in write_valid_signers_file removes the pending directory
        // (remove_dir_all succeeds because the parent directory is writable).
        assert!(
            !pending_dir.exists(),
            "Pending directory should have been cleaned up by rollback"
        );
        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_with_already_pending_dir() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        // Create the pending directory in advance
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let validator = || Ok(());

        // Should succeed
        write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            validator,
        )?;

        // Verify files were created
        let pending_file = pending_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        Ok(())
    }

    #[test]
    fn test_write_valid_signers_file_with_path_already_ending_in_pending() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        let test_keys = TestKeys::new(1);

        let json_content = r#"
        {
          "version": 1,
          "timestamp": "TIMESTAMP",
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
        "#.replace("TIMESTAMP", chrono::Utc::now().to_string().as_str());

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash)?;

        let signer_validator = || Ok(());

        // Pass path that already ends with PENDING_SIGNERS_DIR
        write_valid_signers_file(
            &pending_dir,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        )?;

        // Verify files were created in the correct location
        let pending_file = pending_dir.join(SIGNERS_FILE);
        assert!(pending_file.exists());

        // Verify no nested pending directory was created
        let nested_pending = pending_dir.join(PENDING_SIGNERS_DIR);
        assert!(!nested_pending.exists());

        Ok(())
    }

    // Tests for sign_signers_file
    // ---------------------------

    // Helper function to create a test signers file with given content
    fn create_test_signers_file_with_content(
        dir_path: &Path,
        content: &str,
    ) -> Result<PathBuf, SignersFileError> {
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        fs::write(&signers_file_path, content)?;
        Ok(signers_file_path)
    }

    // Helper function to create a test signature file
    fn create_test_signature_file(
        signers_file_path: &Path,
        test_keys: &TestKeys,
        signer_indices: &[usize],
    ) -> Result<(), SignersFileError> {
        let hash = common::sha512_for_file(signers_file_path)?;
        let mut signatures = HashMap::new();

        for &index in signer_indices {
            let pubkey = test_keys.pub_key(index).unwrap();
            let seckey = test_keys.sec_key(index).unwrap();
            let signature = seckey.sign(&hash).unwrap();
            signatures.insert(pubkey.to_base64(), signature.to_base64());
        }

        let pending_sig_path = pending_signatures_path_for(signers_file_path)?;
        fs::write(pending_sig_path, serde_json::to_string(&signatures)?)?;

        Ok(())
    }

    #[test]
    fn test_sign_signers_file_success() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        // Call sign_signers_file
        sign_signers_file(&signers_file_path, &signature, pubkey)?;

        // Verify the pending signature file exists
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        assert!(pending_sig_path.exists());

        // Verify the signature file content
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 1);
        assert!(sig_map.contains_key(&pubkey.to_base64()));
        assert_eq!(
            sig_map.get(&pubkey.to_base64()).unwrap(),
            &signature.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_sign_signers_file_on_non_signers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;
        let my_file = dir_path.join("myfile");
        std::fs::rename(signers_file_path, &my_file)?;
        std::fs::remove_dir(dir_path.join(PENDING_SIGNERS_DIR))?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&my_file)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        // Call sign_signers_file
        let result = sign_signers_file(&my_file, &signature, pubkey);

        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::FileSystemHierarchyError(_) => {} // Expected
            e => panic!("Expected FileSystemHierarchyError, got {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_sign_signers_file_with_existing_signatures() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(3);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Create an existing signature file with one signature
        create_test_signature_file(&signers_file_path, &test_keys, &[0])?;

        // Compute hash and sign with a different key
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(1).unwrap();
        let seckey = test_keys.sec_key(1).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        // Call sign_signers_file
        sign_signers_file(&signers_file_path, &signature, pubkey)?;

        // Verify the signature is complete and the signers file was activated
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        assert!(!pending_sig_path.exists());
        let active_signers_path = temp_dir.path().join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;
        assert!(complete_sig_path.exists());

        // Verify the signature file content contains both signatures
        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 2);
        assert!(sig_map.contains_key(&test_keys.pub_key(0).unwrap().to_base64()));
        assert!(sig_map.contains_key(&pubkey.to_base64()));

        Ok(())
    }

    #[test]
    fn test_sign_signers_file_with_2_steps_to_complete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file with threshold 1
        let mut signers_config_proposal = create_test_signers_config(&test_keys).as_proposal();
        signers_config_proposal.artifact_signers[0].threshold = 1;
        let signers_config = signers_config_proposal.build();
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Define our pending and complete signatures path here.
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        let active_signers_path = temp_dir.path().join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;

        // Call sign_signers_file
        sign_signers_file(&signers_file_path, &signature0, pubkey0)?;

        // Verify we have still the pending signature in the
        // PENDING_SIGNERS_DIR. The threshold is 1, but for a new signers
        // file we need all sigers to sign before we activate it.
        assert!(pending_sig_path.exists());

        // Verify the signature file content
        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 1);
        assert!(sig_map.contains_key(&pubkey0.to_base64()));
        assert_eq!(
            sig_map.get(&pubkey0.to_base64()).unwrap(),
            &signature0.to_base64()
        );

        // Add second signature
        sign_signers_file(&signers_file_path, &signature1, pubkey1)?;
        assert!(!pending_sig_path.exists());
        assert!(complete_sig_path.exists());
        //
        // Verify the signature file content contains both signatures
        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 2);
        assert!(sig_map.contains_key(&pubkey0.to_base64()));
        assert!(sig_map.contains_key(&pubkey1.to_base64()));

        Ok(())
    }

    #[test]
    fn test_sign_signers_file_io_error() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        // Make the directory read-only to cause an IO error
        let pending_dir = signers_file_path.parent().unwrap();
        let mut perms = fs::metadata(pending_dir)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(pending_dir, perms)?;

        // Call sign_signers_file and expect an error
        let result = sign_signers_file(&signers_file_path, &signature, pubkey);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::IoError(_) => {} // Expected
            e => panic!("Expected IoError, got {}", e),
        }

        // Restore permissions for cleanup
        let mut perms = fs::metadata(pending_dir)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(pending_dir, perms)?;

        Ok(())
    }

    #[test]
    fn test_sign_signers_file_signature_operation_error() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create a test signers file
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path = create_test_signers_file_with_content(dir_path, &signers_content)?;

        // Create a corrupted signature file that will cause an error
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        fs::write(&pending_sig_path, "invalid json")?;

        // Compute hash and sign
        let hash = common::sha512_for_file(&signers_file_path)?;
        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();
        let signature = seckey.sign(&hash).unwrap();

        // Call sign_signers_file and expect an error
        let result = sign_signers_file(&signers_file_path, &signature, pubkey);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignersFileError::JsonError(_) => {} // Expected
            e => panic!("Expected JsonError, got {}", e),
        }

        Ok(())
    }

    // Tests for sign_signers_file with active signers file in parent directory
    // -------------------------------------------------------------------

    // Helper function to create an active signers file in a parent directory
    fn create_active_signers_in_parent(
        parent_dir: &Path,
        test_keys: &TestKeys,
    ) -> Result<PathBuf, SignersFileError> {
        let active_signers_dir = parent_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_signers_dir)?;
        let active_signers_file = active_signers_dir.join(SIGNERS_FILE);

        // Create a simple signers config with the test keys
        let signers_config = create_test_signers_config(test_keys);
        let signers_content = signers_config.to_json()?;
        fs::write(&active_signers_file, signers_content)?;

        // Create signatures for the active signers file
        let hash = common::sha512_for_file(&active_signers_file)?;

        // Sign with both keys to make it complete
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Create the aggregate signature
        SignatureWithState::load_for_file(&active_signers_file)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature0, pubkey0)?
            .get_pending()
            .unwrap()
            .add_individual_signature(&signature1, pubkey1)?;

        Ok(active_signers_file)
    }

    #[test]
    fn test_sign_signers_file_with_parent_active_signers_complete_after_all_signatures()
    -> Result<()> {
        let temp_dir = TempDir::new()?;
        let parent_dir = temp_dir.path();
        let child_dir = parent_dir.join("child");
        fs::create_dir(&child_dir)?;

        // These keys are used in the existing signers file, with a threshold of 2
        // It means those 2 keys have to sign for the activation to take place
        let test_keys = TestKeys::new(2);
        // These keys are used in the new signers file placed in a child directory,
        // with a threshold of 2
        // As those are new signers, both signatures have also to be collected for the
        // signers file to be activated.
        let new_keys = TestKeys::new(2);

        // Create active signers in parent directory
        let _active_signers_file = create_active_signers_in_parent(parent_dir, &test_keys)?;

        // Create a test signers file in child directory
        let signers_config = create_test_signers_config(&new_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path =
            create_test_signers_file_with_content(&child_dir, &signers_content)?;

        // Define paths for assertions
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        let active_signers_path = child_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;

        // Compute hash once
        let hash = common::sha512_for_file(&signers_file_path)?;

        // Sign with first key (present in existing signers file in parent dir)
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Call sign_signers_file with first signature
        sign_signers_file(&signers_file_path, &signature0, pubkey0)?;

        // Assert after first signature: pending exists, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should exist after first signature"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 1, "Should have one signature");
        assert!(
            sig_map.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert_eq!(
            sig_map.get(&pubkey0.to_base64()).unwrap(),
            &signature0.to_base64()
        );

        // Sign with second key (present in existing signers file in parent dir)
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Call sign_signers_file with second signature
        sign_signers_file(&signers_file_path, &signature1, pubkey1)?;

        // Assert after second signature: still pending, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should still exist"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 2, "Should have two signatures");
        assert!(
            sig_map.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert_eq!(
            sig_map.get(&pubkey1.to_base64()).unwrap(),
            &signature1.to_base64()
        );

        // Sign with third key (present in new signers file)
        let pubkey2 = new_keys.pub_key(0).unwrap();
        let seckey2 = new_keys.sec_key(0).unwrap();
        let signature2 = seckey2.sign(&hash).unwrap();

        // Call sign_signers_file with third signature
        sign_signers_file(&signers_file_path, &signature2, pubkey2)?;

        // Assert after third signature: still pending, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should still exist"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 3, "Should have three signatures");
        assert!(
            sig_map.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert!(
            sig_map.contains_key(&pubkey2.to_base64()),
            "Should contain third signature"
        );
        assert_eq!(
            sig_map.get(&pubkey2.to_base64()).unwrap(),
            &signature2.to_base64()
        );

        // Sign with fourth key (present in new signers file)
        let pubkey3 = new_keys.pub_key(1).unwrap();
        let seckey3 = new_keys.sec_key(1).unwrap();
        let signature3 = seckey3.sign(&hash).unwrap();

        // Call sign_signers_file with fourth signature
        sign_signers_file(&signers_file_path, &signature3, pubkey3)?;

        // Assert after fourth signature: complete, pending moved
        assert!(
            !pending_sig_path.exists(),
            "Pending signature file should be gone"
        );
        assert!(
            complete_sig_path.exists(),
            "Complete signature file should exist"
        );
        assert!(
            active_signers_path.exists(),
            "Active signers file should exist"
        );

        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 4, "Should have all four signatures");
        assert!(
            sig_map.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert!(
            sig_map.contains_key(&pubkey2.to_base64()),
            "Should contain third signature"
        );
        assert!(
            sig_map.contains_key(&pubkey3.to_base64()),
            "Should contain fourth signature"
        );
        assert_eq!(
            sig_map.get(&pubkey3.to_base64()).unwrap(),
            &signature3.to_base64()
        );

        Ok(())
    }
    #[test]
    fn test_sign_signers_file_with_parent_active_signers_complete_after_2_signatures() -> Result<()>
    {
        let temp_dir = TempDir::new()?;
        let parent_dir = temp_dir.path();
        let child_dir = parent_dir.join("child");
        fs::create_dir(&child_dir)?;

        // The parent and new signers file have the same signers.
        // There's no reason to not support that scenario. It could be useful
        // to copy a signers file to a child dir before making chages in the parent.
        let test_keys = TestKeys::new(2);

        // Create active signers in parent directory
        let _active_signers_file = create_active_signers_in_parent(parent_dir, &test_keys)?;

        // Create a test signers file in child directory
        let signers_config = create_test_signers_config(&test_keys);
        let signers_content = signers_config.to_json()?;
        let signers_file_path =
            create_test_signers_file_with_content(&child_dir, &signers_content)?;

        // Define paths for assertions
        let pending_sig_path = pending_signatures_path_for(&signers_file_path)?;
        let active_signers_path = child_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let complete_sig_path = signatures_path_for(&active_signers_path)?;

        // Compute hash once
        let hash = common::sha512_for_file(&signers_file_path)?;

        // Sign with first key
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let signature0 = seckey0.sign(&hash).unwrap();

        // Call sign_signers_file with first signature
        sign_signers_file(&signers_file_path, &signature0, pubkey0)?;

        // Assert after first signature: pending exists, not complete
        assert!(
            pending_sig_path.exists(),
            "Pending signature file should exist after first signature"
        );
        assert!(
            !complete_sig_path.exists(),
            "Complete signature file should not exist yet"
        );

        let sig_content = fs::read_to_string(&pending_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 1, "Should have one signature");
        assert!(
            sig_map.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert_eq!(
            sig_map.get(&pubkey0.to_base64()).unwrap(),
            &signature0.to_base64()
        );

        // Sign with second key
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let signature1 = seckey1.sign(&hash).unwrap();

        // Call sign_signers_file with second signature
        sign_signers_file(&signers_file_path, &signature1, pubkey1)?;

        // Assert after second signature: complete as the signers are the same
        // in parent and new signers files
        assert!(
            !pending_sig_path.exists(),
            "Pending signature file should not exist"
        );
        assert!(
            complete_sig_path.exists(),
            "Complete signature file should exist"
        );

        let sig_content = fs::read_to_string(&complete_sig_path)?;
        let sig_map: HashMap<String, String> = serde_json::from_str(&sig_content)?;
        assert_eq!(sig_map.len(), 2, "Should have two signatures");
        assert!(
            sig_map.contains_key(&pubkey0.to_base64()),
            "Should contain first signature"
        );
        assert!(
            sig_map.contains_key(&pubkey1.to_base64()),
            "Should contain second signature"
        );
        assert_eq!(
            sig_map.get(&pubkey1.to_base64()).unwrap(),
            &signature1.to_base64()
        );

        Ok(())
    }

    // Tests for metadata behavior
    // ---------------------------

    #[test]
    fn test_metadata_file_is_created() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();

        let json_content = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![pubkey.clone(), test_keys.pub_key(1).unwrap().clone()],
                2,
            ),
        )?
        .to_json()?;

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let signature = seckey.sign(&hash)?;

        let signer_validator = || Ok(());
        write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        )?;

        // Verify metadata.json exists in the pending directory
        let metadata_path = dir_path.join(PENDING_SIGNERS_DIR).join(METADATA_FILE);
        assert!(metadata_path.exists(), "metadata.json should exist");

        // Verify it deserializes to a valid SignersConfigMetadata
        let metadata_content = fs::read_to_string(&metadata_path)?;
        let _metadata: SignersConfigMetadata = serde_json::from_str(&metadata_content)?;

        Ok(())
    }

    #[test]
    fn test_metadata_file_overwrite_guard() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(1);

        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();

        let json_content =
            SignersConfig::with_artifact_signers_only(1, (vec![pubkey.clone()], 1))?.to_json()?;
        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let signature = seckey.sign(&hash)?;

        // Pre-create the metadata.json file
        let pending_dir = dir_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let metadata_path = pending_dir.join(METADATA_FILE);
        fs::write(&metadata_path, "{}")?;

        let signer_validator = || Ok(());
        let result = write_valid_signers_file(
            dir_path,
            &json_content,
            test_metadata(),
            &signature,
            pubkey,
            signer_validator,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            SignersFileError::InitialisationError(msg) => {
                assert!(
                    msg.contains("Metadata file exists"),
                    "Expected 'Metadata file exists' in error, got: {}",
                    msg
                );
            }
            e => panic!("Expected InitialisationError, got {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_metadata_content_matches_input() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir_path = temp_dir.path();
        let test_keys = TestKeys::new(2);

        let pubkey = test_keys.pub_key(0).unwrap();
        let seckey = test_keys.sec_key(0).unwrap();

        let json_content = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![pubkey.clone(), test_keys.pub_key(1).unwrap().clone()],
                2,
            ),
        )?
        .to_json()?;

        let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
        let signature = seckey.sign(&hash)?;

        let metadata = test_metadata();
        // Serialize to compare later
        let expected_json = serde_json::to_string_pretty(&metadata)?;

        let signer_validator = || Ok(());
        write_valid_signers_file(
            dir_path,
            &json_content,
            metadata,
            &signature,
            pubkey,
            signer_validator,
        )?;

        // Read back the metadata file and compare
        let metadata_path = dir_path.join(PENDING_SIGNERS_DIR).join(METADATA_FILE);
        let actual_json = fs::read_to_string(&metadata_path)?;
        // Both should deserialize to valid metadata
        let actual: SignersConfigMetadata = serde_json::from_str(&actual_json)?;
        let expected: SignersConfigMetadata = serde_json::from_str(&expected_json)?;
        // Verify round-trip: re-serialize and compare
        assert_eq!(actual, expected);

        Ok(())
    }
}
