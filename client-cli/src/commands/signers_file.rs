use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::{ClientCliError, Result};
use crate::utils::{ensure_dir_exists, validate_threshold};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys, SignersConfig};

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
    revocation_key: &[String],
    revocation_key_file: &[PathBuf],
    revocation_threshold: Option<u32>,
    output_file: &Path,
    json: bool,
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
    let all_master_keys: Vec<AsfaloadPublicKeys> =
        combine_key_sources(master_key, master_key_file)?;
    let all_master_keys_count = all_master_keys.len();
    let master_group_info = get_group_info(all_master_keys, master_threshold)?;
    // Revocation keys
    let all_revocation_keys: Vec<AsfaloadPublicKeys> =
        combine_key_sources(revocation_key, revocation_key_file)?;
    let all_revocation_keys_count = all_revocation_keys.len();
    let revocation_group_info = get_group_info(all_revocation_keys, revocation_threshold)?;
    // Create signers config using the with_keys method
    let signers_config = SignersConfig::with_keys(
        1, // version
        (all_artifact_signers, artifact_threshold),
        admin_group_info,
        master_group_info,
        revocation_group_info,
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

    if json {
        let output = crate::output::NewSignersFileOutput {
            output_file: output_file.to_string_lossy().to_string(),
            artifact_signers_count: all_artifact_signers_count,
            artifact_threshold,
            admin_keys_count: all_admin_keys_count,
            admin_threshold,
            master_keys_count: all_master_keys_count,
            master_threshold,
            revocation_keys_count: all_revocation_keys_count,
            revocation_threshold,
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
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
        println!(
            "Revocation keys: {} (threshold: {})",
            all_revocation_keys_count,
            revocation_threshold.map_or("none".to_string(), |t| t.to_string())
        );
    }

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
        .map(|key_str| {
            P::from_base64(key_str).map_err(|e| {
                let path_buf = PathBuf::from_str(key_str).unwrap_or(PathBuf::new());
                if path_buf.as_path().exists() {
                    crate::error::ClientCliError::SignersFile(format!(
                       "You passed a string as a public key, but it seems to be a path to a file: {}.\nUse the flag with -file suffix to pass a key stored on disk.\n{}",
                        key_str, e
                    ))
                } else {
                    crate::error::ClientCliError::SignersFile(format!(
                        "Failed to parse public key from string \"{}\": {}",
                        key_str, e
                    ))
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use test_helpers::fixtures_pub_key;

    // A valid minisign public key base64 string (from fixtures key_0)
    const VALID_PUBKEY_B64: &str = "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8";

    #[test]
    fn combine_key_sources_empty_inputs() {
        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn combine_key_sources_valid_base64_string() {
        let keys = vec![VALID_PUBKEY_B64.to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_base64(), VALID_PUBKEY_B64);
    }

    #[test]
    fn combine_key_sources_multiple_valid_base64_strings() {
        let keys = vec![
            "asfaload-pub:p8p1Hb8ux9xf9mo8BGedkpv4RUFZgwXuYGu5x0grsdU".to_string(),
            "asfaload-pub:YCuPAtMNZQaYPDjWmp8voWh6bVg0bRyLu2zEkH6zYZI".to_string(),
        ];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn combine_key_sources_invalid_base64_string_returns_error() {
        let keys = vec!["not-a-valid-key".to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to parse public key from string"),
            "Expected parse error message, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("not-a-valid-key"),
            "Error should contain the invalid input, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_string_that_is_a_path_returns_path_hint() {
        // Use a fixture key file — its path exists on disk, and passing the path
        // string as a base64 key will fail, triggering the path-detection hint.
        let file_path = fixtures_pub_key(0);

        let keys = vec![file_path.to_string_lossy().to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("seems to be a path to a file"),
            "Expected path hint in error message, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("-file suffix"),
            "Expected flag hint in error message, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_nonexistent_path_string_gives_parse_error_not_path_hint() {
        // A path-like string that does NOT exist on disk should not trigger the path hint
        let keys = vec!["/tmp/nonexistent_key_file_12345.pub".to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to parse public key from string"),
            "Non-existent path should get generic parse error, got: {}",
            err_msg
        );
        assert!(
            !err_msg.contains("seems to be a path to a file"),
            "Non-existent path should NOT get path hint, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_valid_file_key() {
        let key_file = fixtures_pub_key(0);

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[key_file]);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_base64(), VALID_PUBKEY_B64);
    }

    #[test]
    fn combine_key_sources_nonexistent_file_returns_error() {
        let bad_path = PathBuf::from("/tmp/does_not_exist_key_12345.pub");
        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[bad_path]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read public key from file"),
            "Expected file read error, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_invalid_file_content_returns_error() {
        let temp_dir = TempDir::new().unwrap();
        let key_file = temp_dir.path().join("bad.pub");
        std::fs::write(&key_file, "this is not a valid key file").unwrap();

        let result = combine_key_sources::<AsfaloadPublicKeys>(&[], &[key_file]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read public key from file"),
            "Expected file parse error, got: {}",
            err_msg
        );
    }

    #[test]
    fn combine_key_sources_mix_of_string_and_file_keys() {
        let key_file = fixtures_pub_key(1);

        let string_keys = vec![VALID_PUBKEY_B64.to_string()];
        let file_keys = vec![key_file.clone()];

        let result = combine_key_sources::<AsfaloadPublicKeys>(&string_keys, &file_keys);
        match result {
            Ok(parsed) => {
                assert_eq!(parsed.len(), 2);
                assert_eq!(parsed[0].to_base64(), VALID_PUBKEY_B64);
                let key_from_file = AsfaloadPublicKeys::from_file(&key_file)
                    .expect("Failed to load key from file for assertion");
                assert_eq!(parsed[1].to_base64(), key_from_file.to_base64());
            }
            Err(e) => panic!("Expected Ok, but got error: {}", e),
        }
    }

    #[test]
    fn combine_key_sources_first_invalid_string_fails_entire_call() {
        // One valid + one invalid string key: should fail
        let keys = vec![VALID_PUBKEY_B64.to_string(), "garbage".to_string()];
        let result = combine_key_sources::<AsfaloadPublicKeys>(&keys, &[]);
        assert!(result.is_err());
    }
}
