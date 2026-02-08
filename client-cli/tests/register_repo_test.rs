use predicates::prelude::*;

#[test]
fn test_register_repo_missing_url_shows_error() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.arg("register-repo");
    cmd.assert().failure();
}

#[test]
fn test_register_repo_help_shows_usage() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("client-cli");
    cmd.args(["register-repo", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("SIGNERS_FILE_URL"))
        .stdout(predicate::str::contains("backend-url"));
}
