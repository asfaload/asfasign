use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
use predicates::prelude::*;
#[test]
fn test_register_release_cli_help() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("register-release").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Register a GitHub release"));
}

#[test]
fn test_register_release_requires_url() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("register-release");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_register_release_requires_secret_key() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("register-release")
        .arg("https://github.com/testowner/testrepo/releases/tag/v1.0.0");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_register_release_network_error_without_server() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_key.json");

    let secret_key = AsfaloadKeyPairs::new("test_password_123").unwrap();
    secret_key.save(&key_path).unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("register-release")
        .arg("https://github.com/testowner/testrepo/releases/tag/v1.0.0")
        .arg("-K")
        .arg(&key_path)
        .env("ASFALOAD_REGISTER_RELEASE_PASSWORD", "test_password_123");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("connection").or(predicate::str::contains("Connection")));
}
