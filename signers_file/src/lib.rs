use aggregate_signature::{
    AggregateSignature, CompleteSignature, SignatureWithState, check_all_signers,
};
use common::fs::names::{
    PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE,
    pending_signatures_path_for, signatures_path_for,
};
use core::hash;
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

    // Read or create history entries
    let mut history_entries: Vec<serde_json::Value> = if history_file_path.exists() {
        let history_content = fs::read_to_string(&history_file_path)?;
        serde_json::from_str(&history_content)?
    } else {
        Vec::new()
    };

    // Add existing config to history
    history_entries.push(serde_json::to_value(existing_config)?);

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
    // Helper function to create a test signers config
    fn create_test_signers_config(test_keys: &TestKeys) -> String {
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
        test_keys.substitute_keys(json_content_template.to_string())
    }

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

        // Write the signature to the complete signature file
        let complete_sig_path = common::fs::names::signatures_path_for(signers_file_path)?;
        let mut signatures = std::collections::HashMap::new();
        signatures.insert(pubkey0.to_base64(), signature0.to_base64());
        signatures.insert(pubkey1.to_base64(), signature1.to_base64());
        fs::write(
            &complete_sig_path,
            serde_json::to_string_pretty(&signatures)?,
        )?;

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
        fs::write(&signers_file_path, signers_content)?;

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
        assert_eq!(active_content, expected_content);

        Ok(())
    }

    #[test]
    fn test_activate_signers_file_with_existing_active() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root_dir = temp_dir.path();
        let test_keys = TestKeys::new(2);

        // Create existing active directory and signers file
        let active_dir = root_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&active_dir)?;
        let existing_signers_file = active_dir.join(SIGNERS_FILE);
        let existing_content = r#"
{
  "version": 1,
  "initial_version": {
    "permalink": "https://old.example.com",
    "mirrors": []
  },
  "artifact_signers": [
    {
      "signers": [
        { "kind": "key", "data": { "format": "minisign", "pubkey": "RWTUManqs3axpHvnTGZVvmaIOOz0jaV+SAKax8uxsWHFkcnACqzL1xyv" } }
      ],
      "threshold": 1
    }
  ],
  "master_keys": [],
  "admin_keys": null
}
"#;
        fs::write(&existing_signers_file, existing_content)?;

        // Create pending directory and signers file
        let pending_dir = root_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_dir)?;
        let signers_file_path = pending_dir.join(SIGNERS_FILE);
        let new_content = create_test_signers_config(&test_keys);
        fs::write(&signers_file_path, &new_content)?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

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
            .get("initial_version")
            .and_then(|v| v.get("permalink"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(old_config_in_history, "https://old.example.com");

        // Verify the new configuration is active
        let new_active_content = fs::read_to_string(&active_dir.join(SIGNERS_FILE))?;
        assert_eq!(new_active_content, new_content);

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
        let signers_content = create_test_signers_config(&test_keys);
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
        let signers_content = create_test_signers_config(&test_keys);
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
        let signers_content = create_test_signers_config(&test_keys);
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
        let signers_content = create_test_signers_config(&test_keys);
        fs::write(&signers_file_path, signers_content)?;

        // Create signature files
        let pending_sig_path = common::fs::names::pending_signatures_path_for(&signers_file_path)?;
        let complete_sig_path = common::fs::names::signatures_path_for(&signers_file_path)?;
        fs::write(&pending_sig_path, "{}")?;
        fs::write(&complete_sig_path, "{}")?;

        // Create aggregate signature
        let agg_sig = create_test_aggregate_signature(&signers_file_path, &test_keys)?;

        // Activate the signers file
        activate_signers_file(&signers_file_path, agg_sig)?;

        // Verify the pending directory was renamed to active
        let active_dir = root_dir.join(SIGNERS_DIR);
        assert!(active_dir.exists());
        assert!(!pending_dir.exists());

        // Verify the signature files were removed
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
        let signers_content = create_test_signers_config(&test_keys);
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
        let expected_content = create_test_signers_config(&test_keys);
        assert_eq!(active_content, expected_content);

        Ok(())
    }
}
