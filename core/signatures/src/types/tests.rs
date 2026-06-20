use crate::keys::{
    AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait,
    KeyFormat, asfaload::format::Argon2Params,
};
use anyhow::{Context, Result};
use common::errors::keys::KeyError;
use std::{
    fs::{self, File},
    path::PathBuf,
};
use tempfile::TempDir;

use super::*;

//------------------------------------------------------------
// Duplicates to fix dependency cycles with test_helpers
//------------------------------------------------------------
// Tried to make it works with workspace dependencies, but it didn't work out.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_helpers/fixtures")
}
pub fn fixtures_keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}
/// Load a key pair from fixture files.
pub fn get_key_pair() -> anyhow::Result<(AsfaloadPublicKeys, AsfaloadSecretKeys)> {
    let dir = fixtures_keys_dir();
    println!("dir={}", dir.display());
    let pk = AsfaloadPublicKeys::from_file(dir.join("key_0.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(dir.join("key_0"), "password")?;
    Ok((pk, sk))
}
/// Generate a fresh asfaload key pair (fast TEST params) and save to temp dir.
/// Returns (public key, secret key) via the enum facade.
pub fn get_asfaload_key_pair() -> anyhow::Result<(TempDir, AsfaloadPublicKeys, AsfaloadSecretKeys)>
{
    let temp_dir = tempfile::tempdir()?;
    let kp = AsfaloadKeyPairs::new_with_format_and_argon2_params(
        "password",
        &KeyFormat::Asfaload,
        Argon2Params::TEST,
    )?;
    kp.save(temp_dir.path())?;
    let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
    let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "password")?;
    Ok((temp_dir, pk, sk))
}

//------------------------------------------------------------
// Keypairs
//------------------------------------------------------------

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
    [KeyFormat::Asfaload]
        .iter()
        .try_for_each(|t| -> anyhow::Result<()> {
            // Save keypair in temp dir
            let temp_dir = tempfile::tempdir().unwrap();
            let kp = AsfaloadKeyPairs::new_with_format("mypass", t)?;
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
            let public_key_string = fs::read_to_string(&public_key_path)?;
            let public_key_from_string = AsfaloadPublicKeys::from_base64(&public_key_string)?;
            public_key_from_string.verify(&signature, &bytes_to_sign)?;

            // Test AsfaloadPublicKey::from_base64
            let b64 = public_key_from_string.to_base64();
            assert_eq!(b64, public_key_string.trim());

            Ok(())
        })
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

//------------------------------------------------------------
// Cross-algorithm tests
//------------------------------------------------------------

#[test]
fn test_asfaload_secret_keys_from_file_for_openssh() -> anyhow::Result<()> {
    use crate::keys::{AsfaloadKeyPair, AsfaloadKeyPairTrait, asfaload::SshEncryptedKey};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use ssh_key::LineEnding;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    // Build an in-memory encrypted OpenSSH ed25519 key, write to tempfile.
    let sk = SigningKey::generate(&mut OsRng);
    let seed: [u8; 32] = sk.to_bytes();
    let ssh_ed = Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::PrivateKey::new(KeypairData::Ed25519(ssh_ed), "interop-test")
        .expect("PrivateKey::new");
    let encrypted = private.encrypt(&mut OsRng, b"pw").expect("encrypt");
    let pem = encrypted
        .to_openssh(LineEnding::LF)
        .expect("to_openssh")
        .to_string();

    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("id_ed25519");
    std::fs::write(&path, &pem)?;

    // Load via the enum facade with explicit OpenSsh format.
    let loaded = AsfaloadSecretKeys::from_file_for_format(&path, "pw", &KeyFormat::OpenSsh)?;

    // Should end up in the Asfaload variant (shared ed25519 types).
    assert!(matches!(loaded, AsfaloadSecretKeys::Asfaload(_)));

    // Sign + verify via the shared types works.
    let data = common::sha512_for_content(b"interop-payload".to_vec())?;
    let sig = loaded.sign(&data)?;

    // Public key derived by loading via AsfaloadKeyPair<SshEncryptedKey>.
    let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_file(&path)?;
    let pk = kp.public_key();
    let asfaload_pk = AsfaloadPublicKeys::Asfaload(pk);
    asfaload_pk.verify(&sig, &data)?;

    Ok(())
}

#[test]
fn test_asfaload_secret_keys_from_file_for_asfaload() -> anyhow::Result<()> {
    use crate::keys::{
        AsfaloadKeyPair, AsfaloadKeyPairTrait,
        asfaload::{AsfaloadKeysBlob, format::Argon2Params},
    };

    // Generate an asfaload key and save it to disk.
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("asfaload_key");
    let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new_with_argon2_params("pw", Argon2Params::TEST)?;
    kp.save(&path)?;

    // Load via the enum facade with explicit Asfaload format.
    let loaded = AsfaloadSecretKeys::from_file_for_format(&path, "pw", &KeyFormat::Asfaload)?;

    assert!(matches!(loaded, AsfaloadSecretKeys::Asfaload(_)));

    // Sign + verify works end-to-end.
    let data = common::sha512_for_content(b"payload".to_vec())?;
    let sig = loaded.sign(&data)?;
    let pk = AsfaloadPublicKeys::Asfaload(kp.public_key());
    pk.verify(&sig, &data)?;

    Ok(())
}

// Prefix-dispatch tests for AsfaloadSecretKeys::from_file / AsfaloadPublicKeys::from_file
// -------------------------------------------------------------------------------------

#[test]
fn sk_from_file_dispatches_asfaload_by_prefix() -> Result<()> {
    let (temp_dir, _pk, _sk) = get_asfaload_key_pair()?;
    // Re-load via the enum-level dispatcher to assert the variant explicitly.
    let sk = AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "password")?;
    #[allow(unreachable_patterns)]
    match sk {
        AsfaloadSecretKeys::Asfaload(_) => Ok(()),
        other => panic!("expected Asfaload variant, got {other:?}"),
    }
}

#[test]
fn sk_from_file_rejects_unknown_prefix_without_kdf() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("garbage.key");
    std::fs::write(&path, "not-a-key\n")?;

    match AsfaloadSecretKeys::from_file(&path, "any-password") {
        Err(KeyError::FormatError(msg)) => {
            assert!(
                msg.contains(&path.display().to_string()),
                "error should include the path, got: {msg}"
            );
        }
        Err(other) => panic!("expected CreationFailed, got {other:?}"),
        Ok(_) => panic!("expected an error, got Ok"),
    }
    Ok(())
}

/// Generate an encrypted OpenSSH ed25519 PEM containing a fresh keypair.
fn build_encrypted_ssh_ed25519_pem(passphrase: &str) -> String {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use ssh_key::LineEnding;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    let sk = SigningKey::generate(&mut OsRng);
    let seed = sk.to_bytes();
    let ssh_ed = Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::PrivateKey::new(KeypairData::Ed25519(ssh_ed), "asfaload-test")
        .expect("PrivateKey::new");
    let encrypted = private
        .encrypt(&mut OsRng, passphrase.as_bytes())
        .expect("encrypt");
    encrypted
        .to_openssh(LineEnding::LF)
        .expect("to_openssh")
        .to_string()
}

#[test]
fn sk_from_file_dispatches_openssh_by_prefix() -> Result<()> {
    let pem = build_encrypted_ssh_ed25519_pem("ssh-pw");
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("id_ed25519");
    std::fs::write(&path, &pem)?;

    let sk = AsfaloadSecretKeys::from_file(&path, "ssh-pw")?;
    #[allow(unreachable_patterns)]
    match sk {
        AsfaloadSecretKeys::Asfaload(_) => {}
        other => panic!("expected Asfaload variant (SSH keys share ed25519 type), got {other:?}"),
    }
    Ok(())
}

#[test]
fn sk_from_file_wrong_asfaload_password_returns_format_error() -> Result<()> {
    let (temp_dir, _pk, _sk) = get_asfaload_key_pair()?;
    match AsfaloadSecretKeys::from_file(temp_dir.path().join("key"), "wrong-pw") {
        Err(KeyError::AsfaloadFormat(_)) => Ok(()),
        Err(other) => panic!("expected AsfaloadFormat, got {other:?}"),
        Ok(_) => panic!("expected an error, got Ok"),
    }
}

#[test]
fn sk_from_file_wrong_ssh_passphrase_returns_creation_failed() -> Result<()> {
    let pem = build_encrypted_ssh_ed25519_pem("right");
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("id_ed25519");
    std::fs::write(&path, &pem)?;

    match AsfaloadSecretKeys::from_file(&path, "wrong") {
        Err(KeyError::CreationFailed(_)) => Ok(()),
        Err(other) => panic!("expected CreationFailed, got {other:?}"),
        Ok(_) => panic!("expected an error, got Ok"),
    }
}

#[test]
fn pk_from_file_rejects_unknown_prefix() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("garbage.pub");
    std::fs::write(&path, "not-a-key\n")?;

    match AsfaloadPublicKeys::from_file(&path) {
        Err(KeyError::FormatError(msg)) => {
            assert!(
                msg.contains(&path.display().to_string()),
                "error should include the path, got: {msg}"
            );
            Ok(())
        }
        Err(other) => panic!("expected CreationFailed, got {other:?}"),
        Ok(_) => panic!("expected an error, got Ok"),
    }
}

#[test]
fn pk_from_file_dispatches_asfaload_by_prefix() -> Result<()> {
    let (temp_dir, _pk, _sk) = get_asfaload_key_pair()?;
    let pk = AsfaloadPublicKeys::from_file(temp_dir.path().join("key.pub"))?;
    #[allow(unreachable_patterns)]
    match pk {
        AsfaloadPublicKeys::Asfaload(_) => Ok(()),
        other => panic!("expected Asfaload variant, got {other:?}"),
    }
}

#[test]
fn pk_from_file_dispatches_openssh_by_prefix() -> Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    // Produce a real SSH-format ed25519 public-key line via the ssh-key crate,
    // mirroring how build_encrypted_ssh_ed25519_pem uses it for private keys.
    let sk = SigningKey::generate(&mut OsRng);
    let seed = sk.to_bytes();
    let ssh_ed = Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::PrivateKey::new(KeypairData::Ed25519(ssh_ed), "asfaload-test")
        .expect("PrivateKey::new");
    let line = private.public_key().to_openssh().expect("to_openssh");

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("id_ed25519.pub");
    std::fs::write(&path, &line)?;

    let pk = AsfaloadPublicKeys::from_file(&path)?;
    #[allow(unreachable_patterns)]
    match pk {
        AsfaloadPublicKeys::Asfaload(_) => Ok(()),
        other => {
            panic!("expected Asfaload variant (SSH pub keys share ed25519 type), got {other:?}")
        }
    }
}

// Tests for AsfaloadEd25519SecretKey::from_file (ed25519-specific secret-key loader)
// ----------------------------------------------------------------------------------

#[test]
fn ed25519_sk_from_file_loads_asfaload() -> Result<()> {
    let (temp_dir, _pk, _sk) = get_asfaload_key_pair()?;
    let sk = crate::keys::asfaload::AsfaloadEd25519SecretKey::from_file(
        temp_dir.path().join("key"),
        "password",
    )?;
    let data = common::sha512_for_content(b"test".to_vec())?;
    let _sig = sk.sign(&data)?;
    Ok(())
}

#[test]
fn ed25519_sk_from_file_loads_openssh() -> Result<()> {
    let pem = build_encrypted_ssh_ed25519_pem("ssh-pw");
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("id_ed25519");
    std::fs::write(&path, &pem)?;

    let sk = crate::keys::asfaload::AsfaloadEd25519SecretKey::from_file(&path, "ssh-pw")?;
    let data = common::sha512_for_content(b"test".to_vec())?;
    let _sig = sk.sign(&data)?;
    Ok(())
}

#[test]
fn ed25519_sk_from_file_rejects_unknown_prefix() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path().join("garbage.key");
    std::fs::write(&path, "not-a-key\n")?;

    match crate::keys::asfaload::AsfaloadEd25519SecretKey::from_file(&path, "any-password") {
        Err(KeyError::FormatError(_msg)) => Ok(()),
        Err(other) => panic!("expected CreationFailed, got {other:?}"),
        Ok(_) => panic!("expected an error, got Ok"),
    }
}
