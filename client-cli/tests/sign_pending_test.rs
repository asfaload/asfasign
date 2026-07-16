use predicates::prelude::*;

const FIXTURE_PASSWORD: &str = "password";

fn fixture_key_path() -> std::path::PathBuf {
    test_helpers::fixtures_keys_dir().join("key_0")
}

fn pending_response_json(files: &[(&str, &str)]) -> String {
    let items: Vec<String> = files
        .iter()
        .map(|(path, digest)| format!(r#"{{"path":"{}","digest":"{}"}}"#, path, digest))
        .collect();
    format!(r#"{{"pending_files":[{}]}}"#, items.join(","))
}

// ---------------------------------------------------------------------------
// --help wiring
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_help_shows_digest_filter_option() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("digest-filter"));
}

// ---------------------------------------------------------------------------
// --digest-filter with no match: no pending signature error
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_digest_filter_no_match_fails_with_no_pending() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[(
            "releases/v1/file-a.tar.gz",
            "sha512:aaaa",
        )]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg("sha512:does-not-exist")
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No pending signature found"));
}

// ---------------------------------------------------------------------------
// --digest-filter leaves only the non-targeted file → NoPendingSignature,
// not "Not a tty", proving the filter ran before the TTY check.
// ---------------------------------------------------------------------------

#[test]
fn sign_pending_digest_filter_excludes_non_matching_digest() {
    let mut server = mockito::Server::new();
    let _m = server
        .mock("GET", "/v1/pending_signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(pending_response_json(&[
            ("releases/v1/file-a.tar.gz", "sha512:aaaa"),
            ("releases/v1/file-b.tar.gz", "sha512:bbbb"),
        ]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg("sha512:no-match")
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No pending signature found"))
        .stderr(predicate::str::contains("Not a tty").not());
}
