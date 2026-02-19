use features_lib::{
    AsfaloadKeyPairTrait, AsfaloadKeyPairs, AsfaloadPublicKeyTrait, AsfaloadPublicKeys,
    AsfaloadSecretKeyTrait, AsfaloadSecretKeys, AsfaloadSignatureTrait,
};
use predicates::prelude::*;
use serde_json::Value;
use std::io::Write;
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

// -------------------------------------------------------------------
// verify-sig
// -------------------------------------------------------------------

#[test]
fn test_verify_sig_json_output() {
    let temp_dir = TempDir::new().unwrap();

    // Create a file to sign
    let file_path = temp_dir.path().join("testfile.txt");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"test data for signing").unwrap();
    }

    // Generate keypair
    let key_path = temp_dir.path().join("signer_key");
    let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
    kp.save(&key_path).unwrap();

    // Sign the file
    let sig_path = temp_dir.path().join("testfile.sig");
    let secret_key = AsfaloadSecretKeys::from_file(&key_path, TEST_PASSWORD).unwrap();
    let hash = features_lib::sha512_for_file(&file_path).unwrap();
    let signature = secret_key.sign(&hash).unwrap();
    signature.to_file(&sig_path).unwrap();

    let pub_key_path = format!("{}.pub", key_path.to_string_lossy());

    // Verify with --json
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("verify-sig")
        .arg("--json")
        .arg("-f")
        .arg(&file_path)
        .arg("-x")
        .arg(&sig_path)
        .arg("-k")
        .arg(&pub_key_path);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["verified"], true);
}

// -------------------------------------------------------------------
// is-agg-complete
// -------------------------------------------------------------------

/// Helper to set up an aggregate signature scenario.
/// Returns (temp_dir, file_path, signatures_path, signers_path).
fn setup_aggregate_scenario(
    threshold: u32,
    sign_count: usize,
) -> (
    TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let temp_dir = TempDir::new().unwrap();

    // Create test file
    let file_path = temp_dir.path().join("artifact.bin");
    std::fs::write(&file_path, b"artifact content").unwrap();

    // Generate keypairs
    let mut pub_keys = Vec::new();
    let mut key_pairs = Vec::new();
    for i in 0..threshold as usize {
        let key_path = temp_dir.path().join(format!("key_{}", i));
        let kp = AsfaloadKeyPairs::new(TEST_PASSWORD).unwrap();
        kp.save(&key_path).unwrap();

        let pub_key_path = format!("{}.pub", key_path.to_string_lossy());
        let pk = AsfaloadPublicKeys::from_file(&pub_key_path).unwrap();
        pub_keys.push(pk);
        key_pairs.push(key_path);
    }

    // Create signers file
    let signers_config =
        features_lib::SignersConfig::with_keys(1, (pub_keys, threshold), None, None, None).unwrap();
    let signers_path = temp_dir.path().join("signers.json");
    let signers_json = signers_config.to_json().unwrap();
    std::fs::write(&signers_path, signers_json).unwrap();

    // Add signatures from sign_count keys (creates pending signatures file)
    let pending_sigs_path = std::path::PathBuf::from(format!(
        "{}.signatures.json.pending",
        file_path.to_string_lossy()
    ));
    let hash = features_lib::sha512_for_file(&file_path).unwrap();

    for key_path in key_pairs.iter().take(sign_count) {
        let sk = AsfaloadSecretKeys::from_file(key_path, TEST_PASSWORD).unwrap();
        let pk = AsfaloadPublicKeys::from_secret_key(&sk).unwrap();
        let sig = sk.sign(&hash).unwrap();
        sig.add_to_aggregate_for_file(&file_path, &pk).unwrap();
    }

    (temp_dir, file_path, pending_sigs_path, signers_path)
}

#[test]
fn test_is_agg_complete_json_complete() {
    let (_temp_dir, file_path, sigs_path, signers_path) = setup_aggregate_scenario(1, 1);

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("is-agg-complete")
        .arg("--json")
        .arg("-f")
        .arg(&file_path)
        .arg("-x")
        .arg(&sigs_path)
        .arg("-s")
        .arg(&signers_path);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["is_complete"], true);
}

#[test]
fn test_is_agg_complete_json_incomplete() {
    let (_temp_dir, file_path, sigs_path, signers_path) = setup_aggregate_scenario(2, 1);

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("is-agg-complete")
        .arg("--json")
        .arg("-f")
        .arg(&file_path)
        .arg("-x")
        .arg(&sigs_path)
        .arg("-s")
        .arg(&signers_path);

    let output = cmd.output().unwrap();
    // In JSON mode, incomplete returns exit code 0 (status in JSON field)
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["is_complete"], false);
}

// -------------------------------------------------------------------
// Error as JSON
// -------------------------------------------------------------------

#[test]
fn test_error_output_as_json() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("verify-sig")
        .arg("--json")
        .arg("-f")
        .arg("/nonexistent/file")
        .arg("-x")
        .arg("/nonexistent/sig")
        .arg("-k")
        .arg("/nonexistent/key");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    let json: Value = serde_json::from_str(&stderr).expect("stderr should be valid JSON");

    assert!(json["error"].as_str().is_some());
    assert!(!json["error"].as_str().unwrap().is_empty());
}

#[test]
fn test_error_without_json_is_plain_text() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("verify-sig")
        .arg("-f")
        .arg("/nonexistent/file")
        .arg("-x")
        .arg("/nonexistent/sig")
        .arg("-k")
        .arg("/nonexistent/key");

    let output = cmd.output().unwrap();
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    // Without --json, stderr should NOT be JSON
    assert!(serde_json::from_str::<Value>(&stderr).is_err());
}
