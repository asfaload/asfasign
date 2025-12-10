use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::utils::{ensure_dir_exists, validate_threshold};
use features_lib::PublicKey;
use features_lib::PublicKeyTrait;
use features_lib::SignersConfig;

/// Handles the `signers_file` command.
///
/// # Arguments
/// * `artifact_signer` - List of artifact signer public keys
/// * `artifact_threshold` - Threshold for artifact signers
/// * `admin_key` - List of admin public keys
/// * `admin_threshold` - Threshold for admin keys (optional)
/// * `master_key` - List of master public keys
/// * `master_threshold` - Threshold for master keys (optional)
/// * `output_dir` - Directory to store the signers file
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
pub fn handle_new_signers_file_command(
    artifact_signer: &[String],
    artifact_threshold: u32,
    admin_key: &[String],
    admin_threshold: Option<u32>,
    master_key: &[String],
    master_threshold: Option<u32>,
    output_dir: &Path,
) -> Result<()> {
    // Ensure output directory exists
    ensure_dir_exists(output_dir)?;

    // Validate artifact threshold
    validate_threshold(artifact_threshold, artifact_signer.len())?;

    // Parse public keys from strings
    let artifact_signers = parse_public_keys::<PublicKey<_>>(artifact_signer)?;

    // Handle admin keys and threshold
    let (admin_keys, admin_threshold) = if admin_key.is_empty() {
        (vec![], None)
    } else {
        let parsed_admin_keys = parse_public_keys::<PublicKey<_>>(admin_key)?;
        if let Some(threshold) = admin_threshold {
            validate_threshold(threshold, parsed_admin_keys.len())?;
            (parsed_admin_keys, Some(threshold))
        } else {
            return Err(crate::error::ClientCliError::InvalidInput(
                "Admin threshold is required when admin keys are provided".to_string(),
            ));
        }
    };

    // Handle master keys and threshold
    let (master_keys, master_threshold_value) = if master_key.is_empty() {
        (vec![], None)
    } else {
        let parsed_master_keys = parse_public_keys::<PublicKey<_>>(master_key)?;
        if let Some(threshold) = master_threshold {
            validate_threshold(threshold, parsed_master_keys.len())?;
            (parsed_master_keys, Some(threshold))
        } else {
            return Err(crate::error::ClientCliError::InvalidInput(
                "Master threshold is required when master keys are provided".to_string(),
            ));
        }
    };

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
    let output_path = output_dir.join("signers.json");
    let mut file = fs::File::create(&output_path).map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!("Failed to create signers file: {}", e))
    })?;

    file.write_all(json_content.as_bytes()).map_err(|e| {
        crate::error::ClientCliError::SignersFile(format!("Failed to write signers file: {}", e))
    })?;

    println!("Signers file created successfully at: {:?}", output_path);
    println!(
        "Artifact signers: {} (threshold: {})",
        artifact_signer.len(),
        artifact_threshold
    );
    println!(
        "Admin keys: {} (threshold: {})",
        admin_key.len(),
        admin_threshold.map_or("none".to_string(), |t| t.to_string())
    );
    println!(
        "Master keys: {} (threshold: {})",
        master_key.len(),
        master_threshold.map_or("none".to_string(), |t| t.to_string())
    );

    Ok(())
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
