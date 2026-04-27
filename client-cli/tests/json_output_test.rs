use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "test_password_123";

/// Helper: generate a keypair in a temp dir and return (temp_dir, key_path)
fn generate_test_keypair() -> (TempDir, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key");
    let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    kp.save(&key_path).unwrap();
    (temp_dir, key_path)
}

// -------------------------------------------------------------------
// new-keys
// -------------------------------------------------------------------

#[test]
fn test_new_keys_json_output() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-keys")
        .arg("--json")
        .arg("-n")
        .arg("mykey")
        .arg("-o")
        .arg(temp_dir.path())
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password");

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert!(json["public_key_path"].as_str().unwrap().ends_with(".pub"));
    assert!(json["secret_key_path"].as_str().unwrap().contains("mykey"));
}

#[test]
fn test_new_keys_human_output_unchanged() {
    let temp_dir = TempDir::new().unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("mykey")
        .arg("-o")
        .arg(temp_dir.path())
        .arg("-p")
        .arg(TEST_PASSWORD)
        .arg("--accept-weak-password");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Public key saved at"));
}

// -------------------------------------------------------------------
// new-signers-file
// -------------------------------------------------------------------

#[test]
fn test_new_signers_file_json_output() {
    let (_key_dir, key_path) = generate_test_keypair();
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-signers-file")
        .arg("--json")
        .arg("--artifact-signer-file")
        .arg(&pub_key_path)
        .arg("-A")
        .arg("1")
        .arg("-o")
        .arg(&output_file);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["artifact_signers_count"], 1);
    assert_eq!(json["artifact_threshold"], 1);
    assert_eq!(json["admin_keys_count"], 0);
    assert!(json["admin_threshold"].is_null());
    assert_eq!(json["master_keys_count"], 0);
    assert!(json["master_threshold"].is_null());
    assert!(!json["output_file"].as_str().unwrap().is_empty());
}

#[test]
fn test_new_signers_file_human_output_includes_revocation_keys() {
    let (_key_dir, key_path) = generate_test_keypair();
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("signers.json");

    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-signers-file")
        .arg("--artifact-signer-file")
        .arg(&pub_key_path)
        .arg("-A")
        .arg("1")
        .arg("--revocation-key-file")
        .arg(&pub_key_path)
        .arg("-R")
        .arg("1")
        .arg("-o")
        .arg(&output_file);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Artifact signers: 1 (threshold: 1)",
        ))
        .stdout(predicate::str::contains(
            "Revocation keys: 1 (threshold: 1)",
        ));
}

// -------------------------------------------------------------------
// Error as JSON
// -------------------------------------------------------------------

#[test]
fn test_error_output_as_json() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-keys")
        .arg("--json")
        .arg("-n")
        .arg("test")
        .arg("-o")
        .arg("/nonexistent/dir")
        .arg("-p")
        .arg("test_password")
        .arg("--accept-weak-password");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    let json: Value = serde_json::from_str(&stderr)
        .unwrap_or_else(|_| panic!("stderr should be valid JSON but is {}", stderr));

    assert!(json["error"].as_str().is_some());
    assert!(!json["error"].as_str().unwrap().is_empty());
}

#[test]
fn test_error_without_json_is_plain_text() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("new-keys")
        .arg("-n")
        .arg("test")
        .arg("-o")
        .arg("/nonexistent/dir")
        .arg("-p")
        .arg("test_password")
        .arg("--accept-weak-password");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    // Without --json, stderr should NOT be JSON
    assert!(serde_json::from_str::<Value>(&stderr).is_err());
}
