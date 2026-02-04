//! Integration tests for download command

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_download_missing_url() {
    let mut cmd = Command::cargo_bin("client-cli").unwrap();
    cmd.arg("download");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_download_help() {
    let mut cmd = Command::cargo_bin("client-cli").unwrap();
    cmd.args(["download", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("FILE_URL"))
        .stdout(predicate::str::contains("output"))
        .stdout(predicate::str::contains("backend-url"));
}

// More comprehensive tests would require mocking the backend API
// For now, we test the CLI interface only
