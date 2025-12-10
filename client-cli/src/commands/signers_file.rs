use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{ClientCliError, Result};
use crate::utils::{ensure_dir_exists, validate_threshold};
use features_lib::PublicKey;
use features_lib::PublicKeyTrait;
use features_lib::SignersConfig;

fn get_group_info<P: PublicKeyTrait>(
    keys: &[String],
    threshold: Option<u32>,
) -> std::result::Result<(Vec<P>, Option<u32>), ClientCliError> {
    if keys.is_empty() {
        Ok((vec![], None))
    } else {
        let parsed_admin_keys = parse_public_keys::<P>(keys)?;
        if let Some(threshold) = threshold {
            validate_threshold(threshold, parsed_admin_keys.len())?;
            Ok((parsed_admin_keys, Some(threshold)))
        } else {
            Err(crate::error::ClientCliError::InvalidInput(
                "Admin threshold is required when admin keys are provided".to_string(),
            ))
        }
    }
}
/// Handles the `signers_file` command.
///
/// # Arguments
/// * `artifact_signer` - List of artifact signer public keys (base64 strings)
/// * `artifact_signer_file` - List of artifact signer public key files (.pub files)
/// * `artifact_threshold` - Threshold for artifact signers
/// * `admin_key` - List of admin public keys (base64 strings)
/// * `admin_key_file` - List of admin public key files (.pub files)
/// * `admin_threshold` - Threshold for admin keys (optional)
/// * `master_key` - List of master public keys (base64 strings)
/// * `master_key_file` - List of master public key files (.pub files)
/// * `master_threshold` - Threshold for master keys (optional)
/// * `output_file` - Path to the output signers file
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
#[allow(clippy::too_many_arguments)]
pub fn handle_new_signers_file_command(
    artifact_signer: &[String],
    artifact_signer_file: &[PathBuf],
    artifact_threshold: u32,
    admin_key: &[String],
    admin_key_file: &[PathBuf],
    admin_threshold: Option<u32>,
    master_key: &[String],
    master_key_file: &[PathBuf],
    master_threshold: Option<u32>,
    output_file: &Path,
) -> Result<()> {
    // We do not geve a default name to the file, so we cannot work
    // with the path to a dir.
    if output_file.is_dir() {
        return Err(crate::error::ClientCliError::InvalidInput(format!(
            "Output file {:?} is a directory but it must be the path to a new file.",
            output_file
        )));
    }
    // Check if the output file already exists
    if output_file.exists() {
        return Err(crate::error::ClientCliError::InvalidInput(format!(
            "Output file {:?} already exists, refusing to overwrite",
            output_file
        )));
    }

    // Get parent directory and create it if it doesn't exist
    if let Some(parent_dir) = output_file.parent() {
        ensure_dir_exists(parent_dir)?;
    }

    // Combine string and file-based artifact signers
    let all_artifact_signers = combine_key_sources(artifact_signer, artifact_signer_file)?;

    // Validate artifact threshold
    validate_threshold(artifact_threshold, all_artifact_signers.len())?;

    // Parse public keys from strings and files
    let artifact_signers = parse_public_keys::<PublicKey<_>>(&all_artifact_signers)?;

    // Combine string and file-based admin keys
    let all_admin_keys = combine_key_sources(admin_key, admin_key_file)?;
    let (admin_keys, admin_threshold) = get_group_info(&all_admin_keys, admin_threshold)?;

    // Combine string and file-based master keys
    let all_master_keys = combine_key_sources(master_key, master_key_file)?;
    let (master_keys, master_threshold_value) = get_group_info(&all_master_keys, master_threshold)?;
    //
    // Create signers config using the with_keys method
    let signers_config = SignersConfig::with_keys(
        1, // version
        (artifact_signers, artifact_threshold),
        if admin_keys.is_empty() {
            None
        } else {
            Some((admin_keys, admin_threshold.unwrap()))
        },
        if master_keys.is_empty() {
            None
        } else {
            Some((master_keys, master_threshold_value.unwrap()))
        },
    )
    .map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!("Failed to create signers config: {}", e))
    })?;

    // Serialize to JSON
    let json_content = signers_config.to_json().map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!(
            "Failed to serialize signers config: {}",
            e
        ))
    })?;

    // Write to file
    let mut file = fs::File::create(output_file).map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!("Failed to create signers file: {}", e))
    })?;

    file.write_all(json_content.as_bytes()).map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!("Failed to write signers file: {}", e))
    })?;

    println!("Signers file created successfully at: {:?}", output_file);
    println!(
        "Artifact signers: {} (threshold: {})",
        all_artifact_signers.len(),
        artifact_threshold
    );
    println!(
        "Admin keys: {} (threshold: {})",
        all_admin_keys.len(),
        admin_threshold.map_or("none".to_string(), |t| t.to_string())
    );
    println!(
        "Master keys: {} (threshold: {})",
        all_master_keys.len(),
        master_threshold.map_or("none".to_string(), |t| t.to_string())
    );

    Ok(())
}

/// Combine string-based keys and file-based keys into a single Vec of strings
fn combine_key_sources(string_keys: &[String], file_keys: &[PathBuf]) -> Result<Vec<String>> {
    let mut combined = Vec::new();

    // Add string keys
    combined.extend(string_keys.iter().cloned());

    // Add file keys by reading the public key from each file
    for file_path in file_keys {
        let key_content = fs::read_to_string(file_path).map_err(|e| {
            crate::error::ClientCliError::SignersFile(format!(
                "Failed to read public key file {:?}: {}",
                file_path, e
            ))
        })?;

        // Extract the second line which contains the base64-encoded public key
        let public_key_line = key_content
            .lines()
            .nth(1)
            .ok_or_else(|| {
                crate::error::ClientCliError::SignersFile(format!(
                    "Public key file {:?} does not contain a second line with the key",
                    file_path
                ))
            })?
            .to_string();

        combined.push(public_key_line);
    }

    Ok(combined)
}

/// Parse public keys from string representations
fn parse_public_keys<P: PublicKeyTrait>(key_strings: &[String]) -> Result<Vec<P>> {
    key_strings
        .iter()
        .enumerate()
        .map(|(i, key_str)| {
            P::from_base64(key_str.clone()).map_err(|e| {
                crate::error::ClientCliError::SignersFile(format!(
                    "Failed to parse public key {}: {}",
                    i + 1,
                    e
                ))
            })
        })
        .collect()
}
