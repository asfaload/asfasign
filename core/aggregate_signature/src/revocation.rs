// aggregate_signature/src/revocation.rs

use common::{errors::RevocationError, fs::names::find_global_signers_for};
use constants::{REVOCATION_SUFFIX, REVOKED_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
use signatures::{
    keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait},
    types::{AsfaloadPublicKeys, AsfaloadSignatures},
};
use signers_file_types::{SignersConfig, parse_signers_config};
use std::fs;
use std::path::{Path, PathBuf};

use crate::can_revoke;

/// Revoke a signed file by creating a revocation file.
///
/// This function validates that the provided public key can revoke the signed file
/// (using the `can_revoke` function), verifies the signature against the revocation
/// JSON content, and creates the necessary revocation files.
///
/// # Arguments
/// * `signed_file_path` - The path to the signed file being revoked
/// * `json_content` - The revocation file as JSON string
/// * `signature` - Signature of the revocation JSON content
/// * `pubkey` - Public key of the revoker
///
/// # Returns
/// * `Ok(())` if revocation was successful
/// * `Err(RevocationError)` if there was an error validating, signing, or writing files
pub fn revoke_signed_file<P>(
    signed_file_path: P,
    json_content: &str,
    signature: &AsfaloadSignatures,
    pubkey: &AsfaloadPublicKeys,
) -> Result<(), RevocationError>
where
    P: AsRef<Path>,
{
    let signed_file_path = signed_file_path.as_ref();

    // 1. Validate the signed file exists and is a file
    if !signed_file_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Signed file not found: {}", signed_file_path.display()),
        )));
    }

    if signed_file_path.is_dir() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Cannot revoke a directory",
        )));
    }

    //  Load the active signers configuration (not the local one copied at time of
    //  signing the signed file we want to revoke)
    let signers_file_path = find_global_signers_for(signed_file_path)?;
    let signers_content = fs::read_to_string(&signers_file_path)?;
    let signers_config: SignersConfig = parse_signers_config(&signers_content)?;

    // Check if the public key can revoke
    if !can_revoke(pubkey, &signers_config) {
        return Err(RevocationError::Signature(
            "Public key is not authorized to revoke this file".to_string(),
        ));
    }

    //Validate the revocation JSON by parsing it
    let _revocation_file: signers_file_types::revocation::RevocationFile =
        serde_json::from_str(json_content)?;

    // Compute hash and verify signature
    let hash = common::sha512_for_content(json_content.as_bytes().to_vec())?;
    pubkey
        .verify(signature, &hash)
        .map_err(|e| RevocationError::Signature(format!("Signature verification failed: {}", e)))?;

    //  Create revocation file paths
    let revocation_file_path = get_revocation_file_path(signed_file_path)?;
    let revocation_sig_path = get_revocation_sig_path(signed_file_path)?;
    let revocation_signers_path = get_revocation_signers_path(signed_file_path)?;
    let revoked_sig_path = get_revoked_sig_path(signed_file_path)?;

    // 7. Check for existing files to avoid overwriting
    check_existing_files(
        &revocation_file_path,
        &revocation_sig_path,
        &revoked_sig_path,
    )?;

    // Write revocation JSON file
    fs::write(&revocation_file_path, json_content)?;

    // Write revocation signature file (single signature)
    let signature_map = serde_json::json!({
        pubkey.to_base64(): signature.to_base64()
    });
    fs::write(
        &revocation_sig_path,
        serde_json::to_string_pretty(&signature_map)?,
    )?;

    // Copy current signers file for reference (keep trace of which
    // signers file was used)
    fs::copy(&signers_file_path, &revocation_signers_path)?;

    // Move the original signatures file to .revoked if it exists
    let original_sig_path = signed_file_path.with_file_name(format!(
        "{}.{}",
        signed_file_path.file_name().unwrap().to_string_lossy(),
        SIGNATURES_SUFFIX
    ));

    if original_sig_path.exists() && original_sig_path.is_file() {
        fs::rename(&original_sig_path, &revoked_sig_path)?;
    }

    Ok(())
}

// {signed_file_name}.{REVOCATION_SUFFIX}
fn get_revocation_file_path(signed_file_path: &Path) -> Result<PathBuf, RevocationError> {
    let file_name = signed_file_path.file_name().ok_or_else(|| {
        RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid file path",
        ))
    })?;

    let revocation_name = format!("{}.{}", file_name.to_string_lossy(), REVOCATION_SUFFIX);
    let mut path = signed_file_path.to_path_buf();
    path.set_file_name(revocation_name);
    Ok(path)
}

// {signed_file_name}.{REVOCATION_SUFFIX}.{SIGNATURES_SUFFIX}
fn get_revocation_sig_path(signed_file_path: &Path) -> Result<PathBuf, RevocationError> {
    let revocation_file_path = get_revocation_file_path(signed_file_path)?;
    let sig_name = format!(
        "{}.{}",
        revocation_file_path.file_name().unwrap().to_string_lossy(),
        SIGNATURES_SUFFIX
    );
    let mut path = revocation_file_path.clone();
    path.set_file_name(sig_name);
    Ok(path)
}

// {signed_file_name}.{REVOCATION_SUFFIX}.{SIGNERS_SUFFIX}
fn get_revocation_signers_path(signed_file_path: &Path) -> Result<PathBuf, RevocationError> {
    let revocation_file_path = get_revocation_file_path(signed_file_path)?;
    let signers_name = format!(
        "{}.{}",
        revocation_file_path.file_name().unwrap().to_string_lossy(),
        SIGNERS_SUFFIX
    );
    let mut path = revocation_file_path.clone();
    path.set_file_name(signers_name);
    Ok(path)
}

// {signed_file_name}.{SIGNATURES_SUFFIX}.{REVOKED_SUFFIX}
fn get_revoked_sig_path(signed_file_path: &Path) -> Result<PathBuf, RevocationError> {
    let file_name = signed_file_path.file_name().ok_or_else(|| {
        RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid file path",
        ))
    })?;

    let revoked_name = format!(
        "{}.{}.{}",
        file_name.to_string_lossy(),
        SIGNATURES_SUFFIX,
        REVOKED_SUFFIX
    );
    let mut path = signed_file_path.to_path_buf();
    path.set_file_name(revoked_name);
    Ok(path)
}

/// Check for existing files to avoid overwriting
fn check_existing_files(
    revocation_file_path: &Path,
    revocation_sig_path: &Path,
    revoked_sig_path: &Path,
) -> Result<(), RevocationError> {
    if revocation_file_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Revocation file already exists: {}",
                revocation_file_path.display()
            ),
        )));
    }

    if revocation_sig_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Revocation signature file already exists: {}",
                revocation_sig_path.display()
            ),
        )));
    }

    if revoked_sig_path.exists() {
        return Err(RevocationError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "Revoked signatures file already exists: {}",
                revoked_sig_path.display()
            ),
        )));
    }

    Ok(())
}

// aggregate_signature/src/revocation.rs (additional tests section)

#[cfg(test)]
mod tests {
    use crate::SignatureWithState;

    use super::*;
    use common::fs::names::{
        local_signers_path_for, revocation_path_for, revocation_signatures_path_for,
        revocation_signers_path_for, revoked_signatures_path_for, signatures_path_for,
    };
    use constants::{REVOCATION_SUFFIX, REVOKED_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
    use signatures::types::AsfaloadPublicKeys;
    use std::path::PathBuf;

    // Helper function to create a test path
    fn create_test_path() -> PathBuf {
        PathBuf::from("/test/directory/file.txt")
    }

    #[test]
    fn test_get_revocation_file_path() {
        let test_path = create_test_path();
        let result = get_revocation_file_path(&test_path).unwrap();

        let expected_name = format!("file.txt.{}", REVOCATION_SUFFIX);
        let expected_path = PathBuf::from("/test/directory").join(expected_name);

        assert_eq!(result, expected_path);
        assert_eq!(
            result.file_name().unwrap().to_string_lossy(),
            format!("file.txt.{}", REVOCATION_SUFFIX)
        );
    }

    #[test]
    fn test_get_revocation_file_path_with_different_extensions() {
        let test_cases = vec![
            ("file.txt", format!("file.txt.{}", REVOCATION_SUFFIX)),
            ("file.tar.gz", format!("file.tar.gz.{}", REVOCATION_SUFFIX)),
            ("file", format!("file.{}", REVOCATION_SUFFIX)),
            (
                "file.with.dots.txt",
                format!("file.with.dots.txt.{}", REVOCATION_SUFFIX),
            ),
        ];

        for (input, expected_name) in test_cases {
            let test_path = PathBuf::from("/test/directory").join(input);
            let result = get_revocation_file_path(&test_path).unwrap();

            let expected_path = PathBuf::from("/test/directory").join(&expected_name);
            assert_eq!(result, expected_path);
            assert_eq!(result.file_name().unwrap().to_string_lossy(), expected_name);
        }
    }

    #[test]
    fn test_get_revocation_file_path_invalid_path() {
        // Test with empty path
        let empty_path = PathBuf::from("");
        let result = get_revocation_file_path(&empty_path);
        assert!(result.is_err());

        // Test with path ending with ..
        let dot_dot_path = PathBuf::from("/test/directory/..");
        let result = get_revocation_file_path(&dot_dot_path);
        assert!(result.is_err());

        // Test with path ending with .
        // FIXME: ideally this should fail, but  Path::file_name is
        // returning the directory in this case
        //let dot_path = PathBuf::from("/test/directory/.");
        //let result = get_revocation_file_path(&dot_path);
        //match result {
        //    Ok(ref p) => {
        //        dbg!(p);
        //    }
        //    Err(ref e) => {
        //        dbg!(e);
        //    }
        //}
        //assert!(result.is_err());
    }

    #[test]
    fn test_get_revocation_sig_path() {
        let test_path = create_test_path();
        let result = get_revocation_sig_path(&test_path).unwrap();

        let expected_name = format!("file.txt.{}.{}", REVOCATION_SUFFIX, SIGNATURES_SUFFIX);
        let expected_path = PathBuf::from("/test/directory").join(expected_name);

        assert_eq!(result, expected_path);
        assert_eq!(
            result.file_name().unwrap().to_string_lossy(),
            format!("file.txt.{}.{}", REVOCATION_SUFFIX, SIGNATURES_SUFFIX)
        );
    }

    #[test]
    fn test_get_revocation_signers_path() {
        let test_path = create_test_path();
        let result = get_revocation_signers_path(&test_path).unwrap();

        let expected_name = format!("file.txt.{}.{}", REVOCATION_SUFFIX, SIGNERS_SUFFIX);
        let expected_path = PathBuf::from("/test/directory").join(expected_name);

        assert_eq!(result, expected_path);
        assert_eq!(
            result.file_name().unwrap().to_string_lossy(),
            format!("file.txt.{}.{}", REVOCATION_SUFFIX, SIGNERS_SUFFIX)
        );
    }

    #[test]
    fn test_get_revoked_sig_path() {
        let test_path = create_test_path();
        let result = get_revoked_sig_path(&test_path).unwrap();

        let expected_name = format!("file.txt.{}.{}", SIGNATURES_SUFFIX, REVOKED_SUFFIX);
        let expected_path = PathBuf::from("/test/directory").join(expected_name);

        assert_eq!(result, expected_path);
    }

    #[test]
    fn test_path_functions_with_unicode_characters() {
        let test_cases = vec![
            ("file_with_unicode_🚀.txt", "file_with_unicode_🚀.txt"),
            ("café.txt", "café.txt"),
            ("文件.txt", "文件.txt"),
        ];

        for (input, expected_base) in test_cases {
            let test_path = PathBuf::from("/test/directory").join(input);

            // Test get_revocation_file_path
            let revocation_path = get_revocation_file_path(&test_path).unwrap();
            assert_eq!(
                revocation_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}", expected_base, REVOCATION_SUFFIX)
            );

            // Test get_revocation_sig_path
            let sig_path = get_revocation_sig_path(&test_path).unwrap();
            assert_eq!(
                sig_path.file_name().unwrap().to_string_lossy(),
                format!(
                    "{}.{}.{}",
                    expected_base, REVOCATION_SUFFIX, SIGNATURES_SUFFIX
                )
            );

            // Test get_revocation_signers_path
            let signers_path = get_revocation_signers_path(&test_path).unwrap();
            assert_eq!(
                signers_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, REVOCATION_SUFFIX, SIGNERS_SUFFIX)
            );

            // Test get_revoked_sig_path
            let revoked_path = get_revoked_sig_path(&test_path).unwrap();
            assert_eq!(
                revoked_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, SIGNATURES_SUFFIX, REVOKED_SUFFIX)
            );
        }
    }

    #[test]
    fn test_path_functions_with_spaces_and_special_chars() {
        let test_cases = vec![
            ("file with spaces.txt", "file with spaces.txt"),
            ("file-with-dashes.txt", "file-with-dashes.txt"),
            ("file_with_underscores.txt", "file_with_underscores.txt"),
            ("file(mixed)chars.txt", "file(mixed)chars.txt"),
        ];

        for (input, expected_base) in test_cases {
            let test_path = PathBuf::from("/test/directory").join(input);

            // Test all path functions
            let revocation_path = get_revocation_file_path(&test_path).unwrap();
            assert_eq!(
                revocation_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}", expected_base, REVOCATION_SUFFIX)
            );

            let sig_path = get_revocation_sig_path(&test_path).unwrap();
            assert_eq!(
                sig_path.file_name().unwrap().to_string_lossy(),
                format!(
                    "{}.{}.{}",
                    expected_base, REVOCATION_SUFFIX, SIGNATURES_SUFFIX
                )
            );

            let signers_path = get_revocation_signers_path(&test_path).unwrap();
            assert_eq!(
                signers_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, REVOCATION_SUFFIX, SIGNERS_SUFFIX)
            );

            let revoked_path = get_revoked_sig_path(&test_path).unwrap();
            assert_eq!(
                revoked_path.file_name().unwrap().to_string_lossy(),
                format!("{}.{}.{}", expected_base, SIGNATURES_SUFFIX, REVOKED_SUFFIX)
            );
        }
    }

    #[test]
    fn test_path_functions_with_relative_paths() {
        let test_cases = vec![
            PathBuf::from("relative/file.txt"),
            PathBuf::from("./current/file.txt"),
            PathBuf::from("../parent/file.txt"),
        ];

        for test_path in test_cases {
            // All functions should work with relative paths
            let revocation_path = get_revocation_file_path(&test_path).unwrap();
            assert!(
                revocation_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}", REVOCATION_SUFFIX))
            );

            let sig_path = get_revocation_sig_path(&test_path).unwrap();
            assert!(
                sig_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}.{}", REVOCATION_SUFFIX, SIGNATURES_SUFFIX))
            );

            let signers_path = get_revocation_signers_path(&test_path).unwrap();
            assert!(
                signers_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}.{}", REVOCATION_SUFFIX, SIGNERS_SUFFIX))
            );

            let revoked_path = get_revoked_sig_path(&test_path).unwrap();
            assert!(
                revoked_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(&format!(".{}.{}", SIGNATURES_SUFFIX, REVOKED_SUFFIX))
            );
        }
    }

    #[test]
    fn test_check_existing_files() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create test files
        let revocation_file_path = temp_dir.path().join("test.revocation.json");
        let revocation_sig_path = temp_dir.path().join("test.revocation.json.signatures.json");
        let revoked_sig_path = temp_dir.path().join("test.signatures.json.revoked");

        // Initially, all files don't exist, so check should pass
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_ok());

        // Create one of the files and test
        std::fs::write(&revocation_file_path, "test content").unwrap();
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Clean up and test another file
        std::fs::remove_file(&revocation_file_path).unwrap();
        std::fs::write(&revocation_sig_path, "test content").unwrap();
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Clean up and test the third file
        std::fs::remove_file(&revocation_sig_path).unwrap();
        std::fs::write(&revoked_sig_path, "test content").unwrap();
        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_check_existing_files_with_directories() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create test directories instead of files
        let revocation_file_path = temp_dir.path().join("test.revocation.json");
        let revocation_sig_path = temp_dir.path().join("test.revocation.json.signatures.json");
        let revoked_sig_path = temp_dir.path().join("test.signatures.json.revoked");

        std::fs::create_dir(&revocation_file_path).unwrap();

        let result = check_existing_files(
            &revocation_file_path,
            &revocation_sig_path,
            &revoked_sig_path,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    //--------------------
    // Revocation tests
    //--------------------

    use chrono::Utc;
    use common::{AsfaloadHashes, fs::names::find_global_signers_for};
    use constants::{SIGNERS_DIR, SIGNERS_FILE};
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signers_file_types::{
        KeyFormat, Signer, SignerData, SignerGroup, SignerKind, SignersConfigProposal,
    };
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;
    use test_helpers::TestKeys;
    // ----------------
    // Helper functions
    // ----------------

    // Helper to create a complete signers file setup with signatures
    fn create_complete_signers_setup(
        temp_dir: &TempDir,
        test_keys: &TestKeys,
        admin_key_indices: Option<Vec<usize>>,
        master_key_indices: Option<Vec<usize>>,
        revocation_key_indices: Option<Vec<usize>>,
    ) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let root = temp_dir.path();

        // Create signers directory and file
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);

        // Create signers configuration
        let artifact_signers = vec![
            Signer {
                kind: SignerKind::Key,
                data: SignerData {
                    format: KeyFormat::Minisign,
                    pubkey: test_keys.pub_key(0).unwrap().clone(),
                },
            },
            Signer {
                kind: SignerKind::Key,
                data: SignerData {
                    format: KeyFormat::Minisign,
                    pubkey: test_keys.pub_key(1).unwrap().clone(),
                },
            },
        ];

        let master_keys = master_key_indices.clone().map(|indices| {
            vec![SignerGroup {
                signers: indices
                    .iter()
                    .map(|&i| Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: test_keys.pub_key(i).unwrap().clone(),
                        },
                    })
                    .collect(),
                threshold: indices.len() as u32,
            }]
        });

        let admin_keys = admin_key_indices.clone().map(|indices| {
            vec![SignerGroup {
                signers: indices
                    .iter()
                    .map(|&i| Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: test_keys.pub_key(i).unwrap().clone(),
                        },
                    })
                    .collect(),
                threshold: indices.len() as u32,
            }]
        });
        let revocation_keys = revocation_key_indices.map(|indices| {
            vec![SignerGroup {
                signers: indices
                    .iter()
                    .map(|&i| Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: test_keys.pub_key(i).unwrap().clone(),
                        },
                    })
                    .collect(),
                threshold: indices.len() as u32,
            }]
        });
        let signers_config_proposal = SignersConfigProposal {
            timestamp: chrono::Utc::now(),
            version: 1,
            artifact_signers: vec![SignerGroup {
                signers: artifact_signers,
                threshold: 2,
            }],
            master_keys: master_keys.clone(),
            admin_keys: admin_keys.clone(),
            revocation_keys,
        };

        let signers_config = signers_config_proposal.build();

        // Write signers configuration
        let config_json = serde_json::to_string_pretty(&signers_config)?;
        fs::write(&signers_file, config_json)?;

        // Sign the signers file itself to make it active
        let hash = common::sha512_for_file(&signers_file)?;

        // Create complete signature for the signers file
        let mut signatures = HashMap::new();

        // Sign with master keys if present, otherwise with artifact signers
        if let Some(indices) = master_key_indices {
            for &index in &indices {
                let pubkey = test_keys.pub_key(index).unwrap();
                let seckey = test_keys.sec_key(index).unwrap();
                let signature = seckey.sign(&hash)?;
                signatures.insert(pubkey.to_base64(), signature.to_base64());
            }
        } else {
            // Sign with both artifact signers
            for i in 0..2 {
                let pubkey = test_keys.pub_key(i).unwrap();
                let seckey = test_keys.sec_key(i).unwrap();
                let signature = seckey.sign(&hash)?;
                signatures.insert(pubkey.to_base64(), signature.to_base64());
            }
        }

        // Write signatures file
        let signatures_file = signers_file.with_file_name(format!(
            "{}.{}",
            signers_file.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));
        fs::write(&signatures_file, serde_json::to_string_pretty(&signatures)?)?;

        Ok((signers_file, signatures_file))
    }

    // Helper to create a signed artifact file with complete aggregate signature
    fn create_signed_artifact_file(
        temp_dir: &TempDir,
        test_keys: &TestKeys,
        artifact_content: &[u8],
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = temp_dir.path();

        // Create a test artifact file
        let artifact_path = root.join("artifact.bin");
        fs::write(&artifact_path, artifact_content)?;

        // Create complete aggregate signature for the artifact
        let hash = common::sha512_for_file(&artifact_path)?;

        let mut signatures = HashMap::new();

        let mut agg_sig = SignatureWithState::load_for_file(&artifact_path)?;
        // Sign with both required artifact signers (threshold 2)
        for i in 0..2 {
            // We reload the agg_sig bevause .get_pending() moves it.
            // This is slow but ensure we have the latest version.
            let pubkey = test_keys.pub_key(i).unwrap();
            let seckey = test_keys.sec_key(i).unwrap();
            let signature = seckey.sign(&hash)?;
            signatures.insert(pubkey.to_base64(), signature.to_base64());
            // We get the new, updated agg_sig back, to be used in next iteration.
            agg_sig = agg_sig
                .get_pending()
                .unwrap()
                .add_individual_signature(&signature, pubkey)?;
        }

        // Create local copy of signers file (as done when signature becomes complete)
        let global_signers = find_global_signers_for(&artifact_path)?;
        let local_signers_file = artifact_path.with_file_name(format!(
            "{}.{}",
            artifact_path.file_name().unwrap().to_string_lossy(),
            SIGNERS_SUFFIX
        ));
        fs::copy(&global_signers, &local_signers_file)?;

        Ok(artifact_path)
    }

    // Helper to create revocation JSON content
    fn create_revocation_json(
        timestamp: chrono::DateTime<Utc>,
        subject_digest: &AsfaloadHashes,
        initiator_pubkey: &AsfaloadPublicKeys,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let revocation_file = signers_file_types::revocation::RevocationFile {
            timestamp,
            subject_digest: subject_digest.clone(),
            initiator: initiator_pubkey.clone(),
        };

        Ok(serde_json::to_string_pretty(&revocation_file)?)
    }
    #[test]
    fn test_revoke_signed_file_with_revocation_key() -> Result<(), Box<dyn std::error::Error>> {
        // -----------------------------------------------------------------
        // Main test logic
        // -----------------------------------------------------------------

        // Create temporary directory
        let temp_dir = TempDir::new()?;

        // Generate test keys: 0,1 for artifact signing, 2 for master, 3 for revocation
        let test_keys = TestKeys::new(4);

        // Create signers setup with master keys (key 2) and revocation keys (key 3)
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_content = b"This is an artifact that will be revoked";
        let artifact_path = create_signed_artifact_file(&temp_dir, &test_keys, artifact_content)?;

        let signatures_file = signatures_path_for(&artifact_path)?;
        let local_signers_file = local_signers_path_for(&artifact_path)?;

        // Verify files exist before revocation
        assert!(artifact_path.exists());
        assert!(signatures_file.exists());
        assert!(local_signers_file.exists());

        // Prepare revocation with revocation key (key 3)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(3).unwrap(); // Revocation key
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(3).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        )?;

        // Verify revocation files were created
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(revocation_file_path.exists());

        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(revocation_sig_path.exists());

        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(revocation_signers_path.exists());

        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(revoked_sig_path.exists());

        // Verify original signatures file was moved
        assert!(!signatures_file.exists());

        // Verify revocation file content
        let parsed_revocation =
            signers_file_types::revocation::RevocationFile::from_file(revocation_file_path)?;

        assert_eq!(parsed_revocation.timestamp, timestamp);
        assert_eq!(parsed_revocation.subject_digest, subject_digest);
        assert_eq!(
            parsed_revocation.initiator.to_base64(),
            initiator_pubkey.to_base64()
        );

        // Verify revocation signature file content
        let revocation_sig_content = fs::read_to_string(&revocation_sig_path)?;
        let revocation_sig_map: HashMap<String, String> =
            serde_json::from_str(&revocation_sig_content)?;
        assert_eq!(revocation_sig_map.len(), 1);
        assert!(revocation_sig_map.contains_key(&initiator_pubkey.to_base64()));
        assert_eq!(
            revocation_sig_map
                .get(&initiator_pubkey.to_base64())
                .unwrap(),
            &revocation_signature.to_base64()
        );

        // Verify revocation signers file matches global signers
        let global_signers = find_global_signers_for(&artifact_path)?;
        let global_signers_content = fs::read_to_string(&global_signers)?;
        let revocation_signers_content = fs::read_to_string(&revocation_signers_path)?;
        assert_eq!(global_signers_content, revocation_signers_content);

        // Verify revoked signatures file content matches original
        let original_sig_content = fs::read_to_string(&revoked_sig_path)?;
        let original_sig_map: HashMap<String, String> =
            serde_json::from_str(&original_sig_content)?;
        assert_eq!(original_sig_map.len(), 2); // Should have both artifact signers

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_artifact_fail_when_master_present()
    -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup with master keys and explicit revocation keys (key 2)
        create_complete_signers_setup(&temp_dir2, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(0).unwrap(); // Artifact signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(0).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_artifact_fail_when_admin_present()
    -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(3);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup with admin keys (key 2), no master, no explicit revocation
        create_complete_signers_setup(&temp_dir2, &test_keys, Some(vec![2]), None, None)?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(0).unwrap(); // Artifact signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(0).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_admin_fail_when_master_present()
    -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(5);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup with admin (key 2), master (key 3), and explicit revocation
        create_complete_signers_setup(
            &temp_dir2,
            &test_keys,
            Some(vec![2]),
            Some(vec![3]),
            Some(vec![4]),
        )?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(2).unwrap(); // Admin signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(2).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_artifact_ok() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(3);

        // Create new temp dir for clean test
        let temp_dir2 = TempDir::new()?;

        // Create signers setup without admin or master keys
        create_complete_signers_setup(&temp_dir2, &test_keys, None, None, None)?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir2, &test_keys, b"Another artifact")?;
        let signatures_file = signatures_path_for(&artifact_path)?;

        // Prepare revocation with artifact signer (key 0)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let initiator_pubkey = test_keys.pub_key(0).unwrap(); // Artifact signer
        let revocation_json = create_revocation_json(timestamp, &subject_digest, initiator_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let initiator_seckey = test_keys.sec_key(0).unwrap();
        let revocation_signature = initiator_seckey.sign(&revocation_hash)?;

        // Perform revocation
        revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            initiator_pubkey,
        )?;

        // Verify revocation succeeded
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(revoked_sig_path.exists());
        // Verify original signatures file was moved
        assert!(!signatures_file.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);
        let temp_dir = TempDir::new()?;

        // Create signers setup with master keys and explicit revocation keys (key 2)
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Protected artifact")?;

        // Prepare revocation with non-master key (key 1 - artifact signer, not master)
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let unauthorized_pubkey = test_keys.pub_key(1).unwrap(); // Not a master key
        let revocation_json =
            create_revocation_json(timestamp, &subject_digest, unauthorized_pubkey)?;

        // Sign the revocation JSON
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let unauthorized_seckey = test_keys.sec_key(1).unwrap();
        let revocation_signature = unauthorized_seckey.sign(&revocation_hash)?;

        // Attempt revocation - should fail
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            unauthorized_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file")
                        || err_str.contains("Signature verification failed"),
                    "Unexpected error: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for unauthorized key"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }
    #[test]
    fn test_revoke_signed_file_with_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir4 = TempDir::new()?;
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);

        // Create signers setup with master keys and explicit revocation keys (key 2)
        create_complete_signers_setup(&temp_dir4, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        // Create signed artifact file
        let artifact_path =
            create_signed_artifact_file(&temp_dir4, &test_keys, b"Another artifact")?;

        // Prepare revocation with revocation key (key 3) but sign wrong data
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let revocation_pubkey = test_keys.pub_key(3).unwrap();
        let revocation_json =
            create_revocation_json(timestamp, &subject_digest, revocation_pubkey)?;

        // Sign WRONG data (different hash)
        let wrong_hash = common::sha512_for_content(b"wrong data".to_vec())?;
        let revocation_seckey = test_keys.sec_key(3).unwrap();
        let wrong_signature = revocation_seckey.sign(&wrong_hash)?;

        // Attempt revocation - should fail due to invalid signature
        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &wrong_signature,
            revocation_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Signature verification failed"),
                    "Expected signature verification error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail with invalid signature"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_inexisting_signed_file() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);
        let temp_dir = TempDir::new()?;
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        let non_existent_path = temp_dir.path().join("nonexistent.bin");
        let master_pubkey = test_keys.pub_key(2).unwrap();
        let master_seckey = test_keys.sec_key(2).unwrap();

        let timestamp = Utc::now();
        let dummy_digest = common::sha512_for_content(b"dummy".to_vec())?;
        let revocation_json = create_revocation_json(timestamp, &dummy_digest, master_pubkey)?;
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let signature = master_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &non_existent_path,
            &revocation_json,
            &signature,
            master_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Signed file not found"),
                    "Expected file not found error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for non-existent file"),
        }

        // Verify no revocation file was create
        let revocation_file_path = revocation_path_for(&non_existent_path)?;
        assert!(!revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&non_existent_path)?;
        assert!(!revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&non_existent_path)?;
        assert!(!revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&non_existent_path)?;
        assert!(!revoked_sig_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_directory_should_fail() -> Result<(), Box<dyn std::error::Error>> {
        // Generate test keys (we need at least 3: 2 for artifact signing, 1 for master/revocation)
        let test_keys = TestKeys::new(4);

        let temp_dir = TempDir::new()?;
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        let dir_path = temp_dir.path().join("subdir");
        fs::create_dir(&dir_path)?;

        let master_pubkey = test_keys.pub_key(2).unwrap();
        let master_seckey = test_keys.sec_key(2).unwrap();

        let timestamp = Utc::now();
        let dummy_digest = common::sha512_for_content(b"dummy".to_vec())?;
        let revocation_json = create_revocation_json(timestamp, &dummy_digest, master_pubkey)?;
        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let signature = master_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(&dir_path, &revocation_json, &signature, master_pubkey);

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Cannot revoke a directory"),
                    "Expected directory error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for directory"),
        }

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_master_fails_with_explicit_revocation_group()
    -> Result<(), Box<dyn std::error::Error>> {
        // When explicit revocation keys exist, master key should NOT be able to revoke
        let test_keys = TestKeys::new(4);
        let temp_dir = TempDir::new()?;

        // master=key 2, revocation=key 3
        create_complete_signers_setup(&temp_dir, &test_keys, None, Some(vec![2]), Some(vec![3]))?;

        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Protected artifact")?;

        // Try to revoke with master key (key 2) — should fail
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let master_pubkey = test_keys.pub_key(2).unwrap();
        let revocation_json = create_revocation_json(timestamp, &subject_digest, master_pubkey)?;

        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let master_seckey = test_keys.sec_key(2).unwrap();
        let revocation_signature = master_seckey.sign(&revocation_hash)?;

        let result = revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            master_pubkey,
        );

        assert!(result.is_err());
        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("Public key is not authorized to revoke this file"),
                    "Expected authorization error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected revocation to fail for master key when revocation group exists"),
        }

        // Verify no revocation files were created
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(!revocation_file_path.exists());

        Ok(())
    }

    #[test]
    fn test_revoke_signed_file_with_admin_ok() -> Result<(), Box<dyn std::error::Error>> {
        // When no master and no explicit revocation keys, admin is the revocation fallback
        let test_keys = TestKeys::new(3);
        let temp_dir = TempDir::new()?;

        // admin=key 2, no master, no revocation
        create_complete_signers_setup(&temp_dir, &test_keys, Some(vec![2]), None, None)?;

        let artifact_path =
            create_signed_artifact_file(&temp_dir, &test_keys, b"Admin revocable artifact")?;
        let signatures_file = signatures_path_for(&artifact_path)?;

        // Revoke with admin key (key 2) — should succeed via revocation_keys() fallback
        let timestamp = Utc::now();
        let subject_digest = common::sha512_for_file(&artifact_path)?;
        let admin_pubkey = test_keys.pub_key(2).unwrap();
        let revocation_json = create_revocation_json(timestamp, &subject_digest, admin_pubkey)?;

        let revocation_hash = common::sha512_for_content(revocation_json.as_bytes().to_vec())?;
        let admin_seckey = test_keys.sec_key(2).unwrap();
        let revocation_signature = admin_seckey.sign(&revocation_hash)?;

        revoke_signed_file(
            &artifact_path,
            &revocation_json,
            &revocation_signature,
            admin_pubkey,
        )?;

        // Verify revocation succeeded
        let revocation_file_path = revocation_path_for(&artifact_path)?;
        assert!(revocation_file_path.exists());
        let revocation_sig_path = revocation_signatures_path_for(&artifact_path)?;
        assert!(revocation_sig_path.exists());
        let revocation_signers_path = revocation_signers_path_for(&artifact_path)?;
        assert!(revocation_signers_path.exists());
        let revoked_sig_path = revoked_signatures_path_for(&artifact_path)?;
        assert!(revoked_sig_path.exists());
        // Original signatures file was moved
        assert!(!signatures_file.exists());

        Ok(())
    }
}
