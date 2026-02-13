use crate::keys::{
    AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait,
};
use anyhow::{Context, Result};
use common::errors::keys::{KeyError, SignatureError};
use constants::PENDING_SIGNATURES_SUFFIX;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use super::*;

//------------------------------------------------------------
// Keypairs
//------------------------------------------------------------

/// Path to the pre-generated fixture keys directory.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_helpers")
        .join("fixtures")
        .join("keys")
}

/// Load a key pair from fixture files (much faster than generating).
fn get_key_pair() -> Result<(AsfaloadPublicKeys, AsfaloadSecretKeys)> {
    let dir = fixtures_dir();
    let pk = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    Ok((pk, sk))
}

/// Load two key pairs from fixture files.
fn get_two_key_pairs() -> Result<(
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
)> {
    let dir = fixtures_dir();
    let pk1 = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk1 = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    let pk2 = AsfaloadPublicKeys::from_file(dir.join("key_1.pub"))?;
    let sk2 = AsfaloadSecretKeys::from_file(dir.join("key_1"), "password")?;
    Ok((pk1, sk1, pk2, sk2))
}

// Helper function to create a file to sign
pub fn create_file_to_sign(dir: std::path::PathBuf) -> Result<std::path::PathBuf, std::io::Error> {
    let to_signed_file_name = "my_signed_file";
    let to_signed_file_path = dir.as_path().join(to_signed_file_name);
    std::fs::write(&to_signed_file_path, "data").map(|_| to_signed_file_path)
}

#[test]
fn test_new() -> Result<()> {
    // Assign keypair then save it on disk, passing a dir
    let kp = AsfaloadKeyPairs::new("mypass")?;
    let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
    let temp_file_path = temp_dir.path();
    let _kpr = kp.save(temp_file_path)?;
    assert!(temp_dir.path().join("key").exists());
    assert!(temp_dir.path().join("key.pub").exists());
    // Load keys from just created files
    let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "mypass")?;
    let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
    // We can't access private fields, so we'll just verify that the keys work correctly
    // by signing and verifying
    let data = common::sha512_for_content(b"test verification".to_vec())?;
    let sig = sk.sign(&data)?;
    pk.verify(&sig, &data)?;
    // Check we can sign and verify with these keys
    let data = common::sha512_for_content(b"lorem ipsum".to_vec())?;
    let sig = sk.sign(&data)?;
    pk.verify(&sig, &data)?;

    // Assign keypair then save it on disk, passing a file name
    let kp = AsfaloadKeyPairs::new("mypass")?;
    let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
    let temp_file_path = temp_dir.path().join("mykey");
    let _kpr = kp.save(&temp_file_path)?;
    assert!(temp_dir.path().join("mykey").exists());
    assert!(temp_dir.path().join("mykey.pub").exists());

    // Saving keys does not overwrite existing files
    // ---------------------------------------------
    fn panic_if_writing_file(save_result: Result<&AsfaloadKeyPairs, KeyError>) {
        match save_result {
            Ok(_) => panic!("should not overwrite existing file!"),
            Err(e) => match e {
                KeyError::NotOverwriting(_) => (),
                _ => panic!("should not overwrite files!"),
            },
        }
    }
    let temp_dir = tempfile::tempdir().unwrap();
    // Default name "key"
    let existing_default_path = temp_dir.path().join("key");
    File::create(&existing_default_path)?;
    let kp = AsfaloadKeyPairs::new("mypass")?;
    let save_result = kp.save(&temp_dir);
    panic_if_writing_file(save_result);
    fs::remove_file(existing_default_path)?;

    // Default name "key.pub"
    let existing_default_path = temp_dir.path().join("key.pub");
    File::create(&existing_default_path)?;
    let kp = AsfaloadKeyPairs::new("mypass")?;
    let save_result = kp.save(&temp_dir);
    panic_if_writing_file(save_result);
    fs::remove_file(existing_default_path)?;

    // Custom file name, priv exists
    let temp_file_path = temp_dir.path().join("mykey");
    File::create(&temp_file_path)?;
    let kp = AsfaloadKeyPairs::new("mypass")?;
    let save_result = kp.save(&temp_file_path);
    panic_if_writing_file(save_result);
    fs::remove_file(&temp_file_path)?;

    // Custom file name, pub exists
    let pub_temp_file_path = temp_dir.path().join("mykey.pub");
    File::create(&pub_temp_file_path)?;
    let kp = AsfaloadKeyPairs::new("mypass")?;
    let save_result = kp.save(&temp_file_path);
    panic_if_writing_file(save_result);
    fs::remove_file(pub_temp_file_path)?;

    // Call new and save on the same line
    let temp_dir = tempfile::tempdir().context("Unable to create a temporary directory")?;
    let temp_file_path = temp_dir.path().join("key");
    let _kp = AsfaloadKeyPairs::new("mypass")?.save(temp_file_path)?;

    Ok(())
}

#[test]
fn test_keys_methods() -> Result<()> {
    // Save keypair in temp dir
    let temp_dir = tempfile::tempdir().unwrap();
    let kp = AsfaloadKeyPairs::new("mypass")?;
    kp.save(&temp_dir)?;

    // Load secret key from disk
    let secret_key_path = temp_dir.as_ref().to_path_buf().join("key");
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, "mypass")?;

    // Generate signature
    let bytes_to_sign = common::sha512_for_content(b"My string to sign".to_vec())?;
    let signature = secret_key.sign(&bytes_to_sign)?;

    // Load public key from disk
    let public_key_path = temp_dir.as_ref().to_path_buf().join("key.pub");
    let public_key = AsfaloadPublicKeys::from_file(&public_key_path)?;

    // Verify signature
    public_key.verify(&signature, &bytes_to_sign)?;

    // Load key from base64 and validate
    let value_read = fs::read_to_string(&public_key_path)?;
    // When we saved the key to disk using the minisign Box, it wrote a comment
    // followed by the base64 encoded key. Thus here we only need the second line.
    let public_key_string = value_read.lines().nth(1).ok_or_else(|| {
        KeyError::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Public key file does not contain a second line",
        ))
    })?;
    let public_key_from_string = AsfaloadPublicKeys::from_base64(public_key_string)?;
    public_key_from_string.verify(&signature, &bytes_to_sign)?;

    // Test AsfaloadPublicKey::from_base64
    let b64 = public_key_from_string.to_base64();
    assert_eq!(b64, public_key_string);

    Ok(())
}

#[test]
fn test_signature_from_string_formats() -> Result<()> {
    let (pk, sk) = get_key_pair()?;
    let data = common::sha512_for_content(b"lorem ipsum".to_vec())?;
    let sig = sk.sign(&data)?;

    // String serialisation
    let sig_str = sig.to_string();
    let sig_from_str = AsfaloadSignatures::from_string(sig_str.as_str())?;
    pk.verify(&sig_from_str, &data)?;

    // Base64 serialisation
    let sig_b64 = sig.to_base64();
    let sig_from_b64 = AsfaloadSignatures::from_base64(&sig_b64)?;
    pk.verify(&sig_from_b64, &data)?;

    // Saving signature to file
    let temp_dir = TempDir::new()?;
    let root_dir = temp_dir.as_ref();
    let sig_path = root_dir.join("signature");
    sig.to_file(&sig_path)?;

    // Reading signature from file
    let sig_from_file = AsfaloadSignatures::from_file(sig_path)?;
    pk.verify(&sig_from_file, &data)?;

    Ok(())
}

#[test]
fn test_add_to_aggregate() -> Result<()> {
    // Create a temporary directory
    let temp_dir = tempfile::tempdir()?;
    let dir_path = temp_dir.path();
    let signed_file_path = create_file_to_sign(dir_path.to_path_buf())?;
    std::fs::write(&signed_file_path, "test data")?;

    // Load keypairs from fixtures
    let (pubkey, seckey, pubkey2, seckey2) = get_two_key_pairs()?;

    let data = common::sha512_for_content(b"test data".to_vec())?;
    let wrong_data = common::sha512_for_content(b"wrong data".to_vec())?;
    let signature = seckey.sign(&data)?;
    let signature2 = seckey2.sign(&data)?;
    let wrong_signature = seckey.sign(&wrong_data)?;

    // Signing a directory causes an error
    let result = signature.add_to_aggregate_for_file(dir_path, &pubkey);
    assert!(result.is_err());
    match result.as_ref().unwrap_err() {
        SignatureError::IoError(io_err) => {
            let err: &std::io::Error = io_err; // Explicit type annotation
            if err.kind() != std::io::ErrorKind::IsADirectory {
                panic!(
                    "Expected IoError with IsADirectory kind, got something else: {:?}",
                    err
                )
            }
        }
        _ => panic!(
            "Expected SignatureError, got something else: {:?}",
            result.unwrap_err()
        ),
    }

    // Attempting to add the signature of another data than the signed file's hash to the aggregate should fail.
    let result = wrong_signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
    match result {
        Err(SignatureError::InvalidSignatureForAggregate(_)) => {
            // Expected
        }
        Ok(_) => panic!("Expected an error, but got Ok"),
        _ => panic!(
            "Expected InvalidsignatureForAggregate, got something else: {:?}",
            result.unwrap_err()
        ),
    }

    // Add the signature to the aggregate
    signature.add_to_aggregate_for_file(&signed_file_path, &pubkey)?;

    // Verify that the signature file was created
    let sig_file_path = signed_file_path.with_file_name(format!(
        "{}.{}",
        signed_file_path.to_string_lossy(),
        PENDING_SIGNATURES_SUFFIX
    ));
    assert!(
        sig_file_path.exists(),
        "Pending signature file should exist"
    );

    // Verify the content of the signatures file
    let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
    let sig_file: std::collections::HashMap<String, String> =
        serde_json::from_str(&sig_file_content)?;
    let pubkey_b64 = pubkey.to_base64();
    let pubkey2_b64 = pubkey2.to_base64();
    assert!(
        sig_file.contains_key(&pubkey_b64),
        "Signatures file should contain an entry for the public key"
    );
    assert!(
        !sig_file.contains_key(&pubkey2_b64),
        "Signatures file should NOT contain an entry for the second public key"
    );
    assert_eq!(
        sig_file.get(&pubkey_b64).unwrap(),
        &signature.to_base64(),
        "Signatures file should contain the correct signature"
    );

    // Add second signature to aggregate
    signature2.add_to_aggregate_for_file(signed_file_path, &pubkey2)?;

    // Re-read the signatures file as it should have been modified
    let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
    let sig_file: std::collections::HashMap<String, String> =
        serde_json::from_str(&sig_file_content)?;
    // First signature is still there
    assert!(
        sig_file.contains_key(&pubkey_b64),
        "Signatures file should contain an entry for the public key"
    );
    assert_eq!(
        sig_file.get(&pubkey_b64).unwrap(),
        &signature.to_base64(),
        "Signatures file should contain the correct signature"
    );
    // Second signature is added
    assert!(
        sig_file.contains_key(&pubkey2_b64),
        "Signatures file should contain an entry for the second public key"
    );
    assert_eq!(
        sig_file.get(&pubkey2_b64).unwrap(),
        &signature2.to_base64(),
        "Signatures file should contain the correct second signature"
    );
    Ok(())
}

#[test]
fn test_signature_trait_error_mapping() -> Result<()> {
    // Check underlying IO errors are mapped correctly to our IO error.
    let r = AsfaloadSignatures::from_file("/tmp/inexisting_path");
    assert!(matches!(r, Err(SignatureError::IoError(_))));

    let r = AsfaloadSignatures::from_base64("invalid");
    assert!(matches!(r, Err(SignatureError::Base64DecodeFailed(_))));

    // This seems to be reported as IO error by minisign
    let r = AsfaloadSignatures::from_string("invalid");
    assert!(matches!(r, Err(SignatureError::IoError(_))));
    Ok(())
}

#[test]
fn test_public_key_from_secret_key() -> Result<()> {
    let (pubkey, seckey) = get_key_pair()?;

    let derived_pubkey = AsfaloadPublicKeys::from_secret_key(&seckey)?;
    assert_eq!(derived_pubkey.to_base64(), pubkey.to_base64());
    Ok(())
}

#[test]
fn test_public_key_serde_round_trip() -> Result<()> {
    let (pubkey, _) = get_key_pair()?;

    // Serialize to JSON (should produce a base64 string)
    let json = serde_json::to_string(&pubkey)?;
    // The JSON value should be a quoted string matching to_base64()
    let expected_json = format!("\"{}\"", pubkey.to_base64());
    assert_eq!(json, expected_json);

    // Deserialize back from JSON
    let deserialized: AsfaloadPublicKeys = serde_json::from_str(&json)?;
    assert_eq!(deserialized.to_base64(), pubkey.to_base64());
    assert_eq!(deserialized, pubkey);

    // Deserializing invalid base64 should produce an error
    let bad_json = "\"not-a-valid-key\"";
    let result: std::result::Result<AsfaloadPublicKeys, _> = serde_json::from_str(bad_json);
    assert!(result.is_err());

    Ok(())
}
