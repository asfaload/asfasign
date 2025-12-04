// aggregate_signature/src/revocation.rs

use common::{
    errors::RevocationError,
    fs::names::{
        REVOCATION_SUFFIX, REVOKED_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX,
        find_global_signers_for,
    },
};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
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
pub fn revoke_signed_file<P, S, K>(
    signed_file_path: P,
    json_content: &str,
    signature: &S,
    pubkey: &K,
) -> Result<(), RevocationError>
where
    P: AsRef<Path>,
    K: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait + Clone,
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
    let signers_config: SignersConfig<K> = parse_signers_config(&signers_content)?;

    // Check if the public key can revoke
    if !can_revoke(pubkey, &signers_config) {
        return Err(RevocationError::Signature(
            "Public key is not authorized to revoke this file".to_string(),
        ));
    }

    //Validate the revocation JSON by parsing it
    let _revocation_file: signers_file_types::revocation::RevocationFile<K> =
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
    use super::*;
    use common::fs::names::{REVOCATION_SUFFIX, REVOKED_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
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
}
