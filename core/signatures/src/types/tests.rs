use crate::keys::{
    AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait,
    KeyFormat,
};
use anyhow::{Context, Result};
use common::errors::keys::{KeyError, SignatureError};
use constants::PENDING_SIGNATURES_SUFFIX;
use std::fs::{self, File};
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

/// Load a minisign key pair from fixture files.
fn get_key_pair() -> Result<(AsfaloadPublicKeys, AsfaloadSecretKeys)> {
    let dir = fixtures_dir();
    let pk = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    Ok((pk, sk))
}

/// Load two minisign key pairs from fixture files.
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

/// Load an ed25519 key pair from fixture files.
fn get_ed25519_key_pair() -> Result<(AsfaloadPublicKeys, AsfaloadSecretKeys)> {
    let dir = fixtures_dir();
    let pk = AsfaloadPublicKeys::from_file(dir.join("ed25519_key_0.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(dir.join("ed25519_key_0"), "password")?;
    Ok((pk, sk))
}

/// Load two ed25519 key pairs from fixture files.
fn get_two_ed25519_key_pairs() -> Result<(
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
    AsfaloadPublicKeys,
    AsfaloadSecretKeys,
)> {
    let dir = fixtures_dir();
    let pk1 = AsfaloadPublicKeys::from_file(dir.join("ed25519_key_0.pub"))?;
    let sk1 = AsfaloadSecretKeys::from_file(dir.join("ed25519_key_0"), "password")?;
    let pk2 = AsfaloadPublicKeys::from_file(dir.join("ed25519_key_1.pub"))?;
    let sk2 = AsfaloadSecretKeys::from_file(dir.join("ed25519_key_1"), "password")?;
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
    let bare_b64 = value_read.lines().nth(1).ok_or_else(|| {
        KeyError::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Public key file does not contain a second line",
        ))
    })?;
    // from_base64 now requires the format prefix
    let prefixed_b64 = format!("minisign:{}", bare_b64);
    let public_key_from_string = AsfaloadPublicKeys::from_base64(&prefixed_b64)?;
    public_key_from_string.verify(&signature, &bytes_to_sign)?;

    // Test round-trip: to_base64 should return the prefixed form
    let b64 = public_key_from_string.to_base64();
    assert_eq!(b64, prefixed_b64);

    Ok(())
}

#[test]
fn test_from_base64_missing_prefix_returns_error() {
    let bare_b64 = "RWS1kZJeKmeNOI0vl8hjI/YD7UQYxMq5uYkVWfHCHPtm7bOsbgZMovii";
    let result = AsfaloadPublicKeys::from_base64(bare_b64);
    assert!(result.is_err(), "from_base64 without prefix should fail");
}

#[test]
fn test_from_base64_unknown_prefix_returns_error() {
    let bad_prefix = "unknown:RWS1kZJeKmeNOI0vl8hjI/YD7UQYxMq5uYkVWfHCHPtm7bOsbgZMovii";
    let result = AsfaloadPublicKeys::from_base64(bad_prefix);
    assert!(
        result.is_err(),
        "from_base64 with unknown prefix should fail"
    );
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
    let sig_file: crate::signatures_file::SignaturesFile = serde_json::from_str(&sig_file_content)?;
    let pubkey_b64 = pubkey.to_base64();
    let pubkey2_b64 = pubkey2.to_base64();
    assert!(
        sig_file.entries.contains_key(&pubkey_b64),
        "Signatures file should contain an entry for the public key"
    );
    assert!(
        !sig_file.entries.contains_key(&pubkey2_b64),
        "Signatures file should NOT contain an entry for the second public key"
    );
    assert_eq!(
        sig_file.entries.get(&pubkey_b64).unwrap().signature,
        signature.to_base64(),
        "Signatures file should contain the correct signature"
    );

    // Add second signature to aggregate
    signature2.add_to_aggregate_for_file(signed_file_path, &pubkey2)?;

    // Re-read the signatures file as it should have been modified
    let sig_file_content = std::fs::read_to_string(&sig_file_path)?;
    let sig_file: crate::signatures_file::SignaturesFile = serde_json::from_str(&sig_file_content)?;
    // First signature is still there
    assert!(
        sig_file.entries.contains_key(&pubkey_b64),
        "Signatures file should contain an entry for the public key"
    );
    assert_eq!(
        sig_file.entries.get(&pubkey_b64).unwrap().signature,
        signature.to_base64(),
        "Signatures file should contain the correct signature"
    );
    // Second signature is added
    assert!(
        sig_file.entries.contains_key(&pubkey2_b64),
        "Signatures file should contain an entry for the second public key"
    );
    assert_eq!(
        sig_file.entries.get(&pubkey2_b64).unwrap().signature,
        signature2.to_base64(),
        "Signatures file should contain the correct second signature"
    );
    Ok(())
}

#[test]
fn test_add_to_aggregate_duplicate_signature() -> Result<()> {
    // Create a temporary directory
    let temp_dir = tempfile::tempdir()?;
    let dir_path = temp_dir.path();
    let signed_file_path = create_file_to_sign(dir_path.to_path_buf())?;
    std::fs::write(&signed_file_path, "test data")?;

    // Load keypair from fixtures
    let (pubkey, seckey) = get_key_pair()?;

    let data = common::sha512_for_content(b"test data".to_vec())?;
    let signature = seckey.sign(&data)?;

    // First signature should succeed
    signature.add_to_aggregate_for_file(&signed_file_path, &pubkey)?;

    // Attempting to sign again with the same key should fail with DuplicateSignature
    let result = signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
    match result {
        Err(SignatureError::DuplicateSignature) => {}
        Ok(_) => panic!("Expected DuplicateSignature error, but got Ok"),
        Err(e) => panic!("Expected DuplicateSignature error, got: {:?}", e),
    }

    Ok(())
}

#[test]
fn test_signature_trait_error_mapping() -> Result<()> {
    // Check underlying IO errors are mapped correctly to our IO error.
    let r = AsfaloadSignatures::from_file("/tmp/inexisting_path");
    assert!(matches!(r, Err(SignatureError::IoError(_))));

    let r = AsfaloadSignatures::from_base64("invalid");
    assert!(matches!(r, Err(SignatureError::Base64DecodeFailed(_))));

    // With multi-format support, from_string tries minisign first (which
    // reports this as IoError) then falls back to ed25519 (which fails
    // with Base64DecodeFailed). The last-tried format's error is returned.
    let r = AsfaloadSignatures::from_string("invalid");
    assert!(r.is_err());
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

#[test]
fn test_add_to_aggregate_rejects_revoked_file() -> Result<()> {
    // Create a temporary directory and a file to sign
    let temp_dir = tempfile::tempdir()?;
    let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;

    // Load a key pair and create a valid signature
    let (pubkey, seckey) = get_key_pair()?;
    let data = common::sha512_for_file(&signed_file_path)?;
    let signature = seckey.sign(&data)?;

    // Create a completed revocation file (filename.revocation.json)
    let revocation_path = common::fs::names::revocation_path_for(&signed_file_path)?;
    fs::write(&revocation_path, r#"{"revoked": true}"#)?;

    // Attempting to add a signature should fail with FileRevoked
    let result = signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
    assert!(result.is_err());
    match result.unwrap_err() {
        SignatureError::FileRevoked(path) => {
            assert_eq!(path, signed_file_path);
        }
        other => panic!("Expected FileRevoked error, got: {:?}", other),
    }

    Ok(())
}

#[test]
fn test_add_to_aggregate_allows_pending_revocation() -> Result<()> {
    // Create a temporary directory and a file to sign
    let temp_dir = tempfile::tempdir()?;
    let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;

    // Load a key pair and create a valid signature
    let (pubkey, seckey) = get_key_pair()?;
    let data = common::sha512_for_file(&signed_file_path)?;
    let signature = seckey.sign(&data)?;

    // Create a PENDING revocation file (should NOT block)
    let revocation_path = common::fs::names::revocation_path_for(&signed_file_path)?;
    let pending_revocation_path = PathBuf::from(format!(
        "{}.{}",
        revocation_path.to_string_lossy(),
        constants::PENDING_SUFFIX
    ));
    fs::write(&pending_revocation_path, r#"{"revoked": true}"#)?;

    // Attempting to add a signature should succeed
    let result = signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
    assert!(
        result.is_ok(),
        "Pending revocation should not block signature addition, but got: {:?}",
        result.unwrap_err()
    );

    Ok(())
}

#[test]
fn test_add_to_aggregate_works_without_revocation_file() -> Result<()> {
    // Create a temporary directory and a file to sign
    let temp_dir = tempfile::tempdir()?;
    let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;

    // Load a key pair and create a valid signature
    let (pubkey, seckey) = get_key_pair()?;
    let data = common::sha512_for_file(&signed_file_path)?;
    let signature = seckey.sign(&data)?;

    // No revocation file exists — signature should succeed
    let revocation_path = common::fs::names::revocation_path_for(&signed_file_path)?;
    assert!(
        !revocation_path.exists(),
        "Revocation file should not exist in this test"
    );

    let result = signature.add_to_aggregate_for_file(&signed_file_path, &pubkey);
    assert!(
        result.is_ok(),
        "Signature should succeed when no revocation file exists, but got: {:?}",
        result.unwrap_err()
    );

    Ok(())
}

//------------------------------------------------------------
// Ed25519 tests
//------------------------------------------------------------

// Intentionally uses production scrypt cost (via new_with_format -> new()) to verify
// the production key creation path works. Other ed25519 tests use TEST_SCRYPT_LOG_N.
#[test]
fn test_ed25519_new_with_format() -> Result<()> {
    let kp = AsfaloadKeyPairs::new_with_format("mypass", &KeyFormat::Ed25519)?;
    let temp_dir = tempfile::tempdir()?;
    kp.save(temp_dir.path())?;
    assert!(temp_dir.path().join("key").exists());
    assert!(temp_dir.path().join("key.pub").exists());

    let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "mypass")?;
    let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
    assert_eq!(pk.key_format(), KeyFormat::Ed25519);

    let data = common::sha512_for_content(b"ed25519 test".to_vec())?;
    let sig = sk.sign(&data)?;
    pk.verify(&sig, &data)?;

    Ok(())
}

#[test]
fn test_ed25519_fixture_sign_and_verify() -> Result<()> {
    let (pk, sk) = get_ed25519_key_pair()?;
    assert_eq!(pk.key_format(), KeyFormat::Ed25519);

    let data = common::sha512_for_content(b"ed25519 fixture test".to_vec())?;
    let sig = sk.sign(&data)?;
    pk.verify(&sig, &data)?;
    Ok(())
}

#[test]
fn test_ed25519_base64_round_trip() -> Result<()> {
    let (pk, _) = get_ed25519_key_pair()?;
    let b64 = pk.to_base64();
    assert!(b64.starts_with("ed25519:"));
    let pk2 = AsfaloadPublicKeys::from_base64(&b64)?;
    assert_eq!(pk, pk2);
    Ok(())
}

#[test]
fn test_ed25519_signature_serialisation() -> Result<()> {
    let (pk, sk) = get_ed25519_key_pair()?;
    let data = common::sha512_for_content(b"serialise me".to_vec())?;
    let sig = sk.sign(&data)?;

    // Base64 round-trip
    let b64 = sig.to_base64();
    let sig2 = AsfaloadSignatures::from_base64(&b64)?;
    pk.verify(&sig2, &data)?;

    // File round-trip
    let temp_dir = TempDir::new()?;
    let sig_path = temp_dir.path().join("ed25519_sig");
    sig.to_file(&sig_path)?;
    let sig3 = AsfaloadSignatures::from_file(&sig_path)?;
    pk.verify(&sig3, &data)?;

    Ok(())
}

#[test]
fn test_ed25519_public_key_from_secret_key() -> Result<()> {
    let (pk, sk) = get_ed25519_key_pair()?;
    let derived = AsfaloadPublicKeys::from_secret_key(&sk)?;
    assert_eq!(derived.to_base64(), pk.to_base64());
    Ok(())
}

#[test]
fn test_ed25519_public_key_serde_round_trip() -> Result<()> {
    let (pk, _) = get_ed25519_key_pair()?;
    let json = serde_json::to_string(&pk)?;
    let expected_json = format!("\"{}\"", pk.to_base64());
    assert_eq!(json, expected_json);

    let deserialized: AsfaloadPublicKeys = serde_json::from_str(&json)?;
    assert_eq!(deserialized, pk);
    Ok(())
}

#[test]
fn test_ed25519_add_to_aggregate() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;
    fs::write(&signed_file_path, "ed25519 aggregate test")?;

    let (pk1, sk1, pk2, sk2) = get_two_ed25519_key_pairs()?;
    let data = common::sha512_for_content(b"ed25519 aggregate test".to_vec())?;
    let sig1 = sk1.sign(&data)?;
    let sig2 = sk2.sign(&data)?;

    sig1.add_to_aggregate_for_file(&signed_file_path, &pk1)?;
    sig2.add_to_aggregate_for_file(&signed_file_path, &pk2)?;

    let sig_file_path = signed_file_path.with_file_name(format!(
        "{}.{}",
        signed_file_path.to_string_lossy(),
        PENDING_SIGNATURES_SUFFIX
    ));
    let content = fs::read_to_string(&sig_file_path)?;
    let sig_file: crate::signatures_file::SignaturesFile = serde_json::from_str(&content)?;
    assert_eq!(sig_file.entries.len(), 2);
    assert!(sig_file.entries.contains_key(&pk1.to_base64()));
    assert!(sig_file.entries.contains_key(&pk2.to_base64()));
    assert_eq!(
        sig_file.entries.get(&pk1.to_base64()).unwrap().format,
        KeyFormat::Ed25519
    );

    Ok(())
}

//------------------------------------------------------------
// Cross-algorithm tests
//------------------------------------------------------------

#[test]
fn test_cross_algorithm_verify_fails() -> Result<()> {
    let (minisign_pk, minisign_sk) = get_key_pair()?;
    let (ed25519_pk, ed25519_sk) = get_ed25519_key_pair()?;

    let data = common::sha512_for_content(b"cross-algo test".to_vec())?;
    let minisign_sig = minisign_sk.sign(&data)?;
    let ed25519_sig = ed25519_sk.sign(&data)?;

    // Minisign key cannot verify ed25519 signature
    let result = minisign_pk.verify(&ed25519_sig, &data);
    assert!(
        result.is_err(),
        "Minisign key should not verify ed25519 signature"
    );

    // Ed25519 key cannot verify minisign signature
    let result = ed25519_pk.verify(&minisign_sig, &data);
    assert!(
        result.is_err(),
        "Ed25519 key should not verify minisign signature"
    );

    // Same-algorithm verification still works
    minisign_pk.verify(&minisign_sig, &data)?;
    ed25519_pk.verify(&ed25519_sig, &data)?;

    Ok(())
}

#[test]
fn test_mixed_algorithm_aggregate() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let signed_file_path = create_file_to_sign(temp_dir.path().to_path_buf())?;
    fs::write(&signed_file_path, "mixed algo test")?;

    let (minisign_pk, minisign_sk) = get_key_pair()?;
    let (ed25519_pk, ed25519_sk) = get_ed25519_key_pair()?;

    let data = common::sha512_for_content(b"mixed algo test".to_vec())?;
    let minisign_sig = minisign_sk.sign(&data)?;
    let ed25519_sig = ed25519_sk.sign(&data)?;

    // Both algorithms can contribute to the same aggregate
    minisign_sig.add_to_aggregate_for_file(&signed_file_path, &minisign_pk)?;
    ed25519_sig.add_to_aggregate_for_file(&signed_file_path, &ed25519_pk)?;

    let sig_file_path = signed_file_path.with_file_name(format!(
        "{}.{}",
        signed_file_path.to_string_lossy(),
        PENDING_SIGNATURES_SUFFIX
    ));
    let content = fs::read_to_string(&sig_file_path)?;
    let sig_file: crate::signatures_file::SignaturesFile = serde_json::from_str(&content)?;
    assert_eq!(sig_file.entries.len(), 2);

    // Check format tags
    let minisign_entry = sig_file.entries.get(&minisign_pk.to_base64()).unwrap();
    assert_eq!(minisign_entry.format, KeyFormat::Minisign);
    let ed25519_entry = sig_file.entries.get(&ed25519_pk.to_base64()).unwrap();
    assert_eq!(ed25519_entry.format, KeyFormat::Ed25519);

    Ok(())
}
