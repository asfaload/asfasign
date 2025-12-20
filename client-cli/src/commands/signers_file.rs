use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{ClientCliError, Result};
use crate::utils::{ensure_dir_exists, validate_threshold};
use features_lib::{AsfaloadPublicKeys, SignersConfig, AsfaloadPublicKeyTrait};

fn get_group_info<P: AsfaloadPublicKeyTrait>(
    keys: Vec<P>,
    threshold: Option<u32>,
) -> std::result::Result<Option<(Vec<P>, u32)>, ClientCliError> {
    if keys.is_empty() {
        Ok(None)
    } else if let Some(threshold) = threshold {
        validate_threshold(threshold, keys.len())?;
        Ok(Some((keys, threshold)))
    } else {
        Err(crate::error::ClientCliError::InvalidInput(
            "Grouo threshold is required when keys are provided for a group".to_string(),
        ))
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
    let all_artifact_signers: Vec<AsfaloadPublicKeys> =
        combine_key_sources(artifact_signer, artifact_signer_file)?;
    let all_artifact_signers_count = all_artifact_signers.len();

    if all_artifact_signers_count == 0 {
        return Err(crate::error::ClientCliError::InvalidInput(
            "At least one artifact signer must be provided.".to_string(),
        ));
    }
    // Validate artifact threshold
    validate_threshold(artifact_threshold, all_artifact_signers.len())?;

    // Combine string and file-based admin keys
    let all_admin_keys: Vec<AsfaloadPublicKeys> = combine_key_sources(admin_key, admin_key_file)?;
    let all_admin_keys_count = all_admin_keys.len();
    let admin_group_info = get_group_info(all_admin_keys, admin_threshold)?;

    // Combine string and file-based master keys
    let all_master_keys: Vec<AsfaloadPublicKeys> = combine_key_sources(master_key, master_key_file)?;
    let all_master_keys_count = all_master_keys.len();
    let master_group_info = get_group_info(all_master_keys, master_threshold)?;
    //
    // Create signers config using the with_keys method
    let signers_config = SignersConfig::with_keys(
        1, // version
        (all_artifact_signers, artifact_threshold),
        admin_group_info,
        master_group_info,
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
        all_artifact_signers_count, artifact_threshold
    );
    println!(
        "Admin keys: {} (threshold: {})",
        all_admin_keys_count,
        admin_threshold.map_or("none".to_string(), |t| t.to_string())
    );
    println!(
        "Master keys: {} (threshold: {})",
        all_master_keys_count,
        master_threshold.map_or("none".to_string(), |t| t.to_string())
    );

    Ok(())
}

/// Combine string-based keys and file-based keys into a single Vec of strings
fn combine_key_sources<P: AsfaloadPublicKeyTrait>(
    string_keys: &[String],
    file_keys: &[PathBuf],
) -> Result<Vec<P>> {
    // Collect public keys from base64 strings we got
    let mut combined: Vec<Result<P>> = string_keys
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
        .collect();

    // Add file keys by reading the public key from each file we got
    for file_path in file_keys {
        let key_result = P::from_file(file_path).map_err(|e| {
            crate::error::ClientCliError::SignersFile(format!(
                "Failed to read public key from file {:?}: {}",
                file_path, e
            ))
        });

        combined.push(key_result);
    }

    combined.into_iter().collect()
}
