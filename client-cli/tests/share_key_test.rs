use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test_password_123";

// A throwaway ssh-ed25519 keypair generated with `ssh-keygen -t ed25519`.
// asfaload can read OpenSSH ed25519 keys but never writes them, so we embed a
// fixture rather than generate one at test time (no dependency on `ssh-keygen`).
const SSH_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM520sFlxFm2ZlGKI2OKYOBZ4t4aQlJ0PappXAEj3TnH test@asfaload";

// The canonical asfaload representation of SSH_PUBLIC_KEY: the same 32 ed25519
// key bytes, re-encoded with the `asfaload-pub:` prefix. share-key normalises
// every accepted public key to this form, so this is what the message must show.
const SSH_PUBLIC_KEY_AS_ASFALOAD: &str = "asfaload-pub:znbSwWXEWbZmUYojY4pg4Fni3hpCUnQ9qmlcASPdOcc";

const SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDOdtLBZcRZtmZRiiNjimDgWeLeGkJSdD2qaVwBI905xwAAAJAxp53YMaed
2AAAAAtzc2gtZWQyNTUxOQAAACDOdtLBZcRZtmZRiiNjimDgWeLeGkJSdD2qaVwBI905xw
AAAECBXH02sboBOruCqVLZIQ1LG/XKbCl8pJ2ZuJGMgv+yFc520sFlxFm2ZlGKI2OKYOBZ
4t4aQlJ0PappXAEj3TnHAAAADXRlc3RAYXNmYWxvYWQ=
-----END OPENSSH PRIVATE KEY-----
";

/// Generate an asfaload keypair in a temp dir and return (temp_dir, secret_key_path).
/// The public key lives at `<secret_key_path>.pub`.
fn generate_asfaload_keypair() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key");
    let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    kp.save(&key_path).unwrap();
    (temp_dir, key_path)
}

// -------------------------------------------------------------------
// Accepting public keys
// -------------------------------------------------------------------

#[test]
fn test_share_key_asfaload_public_key() {
    let (_dir, key_path) = generate_asfaload_keypair();
    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    // Read the public key so we can assert the message embeds it verbatim.
    let pub_key = fs::read_to_string(&pub_key_path).unwrap();
    let pub_key = pub_key.trim();
    assert!(pub_key.starts_with("asfaload-pub:"));

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&pub_key_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(pub_key.to_string()));
}

#[test]
fn test_share_key_ssh_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let pub_key_path = temp_dir.path().join("ssh_key.pub");
    fs::write(&pub_key_path, SSH_PUBLIC_KEY).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&pub_key_path);

    // The SSH key is accepted and normalised to its canonical asfaload form.
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("The public key is safe to share"))
        .stdout(predicate::str::contains(SSH_PUBLIC_KEY_AS_ASFALOAD));
}

// -------------------------------------------------------------------
// Rejecting private keys
// -------------------------------------------------------------------

#[test]
fn test_share_key_rejects_asfaload_private_key() {
    let (_dir, key_path) = generate_asfaload_keypair();

    // Pass the secret key file instead of the `.pub` file.
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&key_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error loading public key"));
}

#[test]
fn test_share_key_rejects_ssh_private_key() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("ssh_key");
    fs::write(&key_path, SSH_PRIVATE_KEY).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("share-key").arg("-k").arg(&key_path);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error loading public key"));
}
