use predicates::prelude::*;
use sha2::{Digest, Sha512};

const FIXTURE_PASSWORD: &str = "password";

const DIGEST_A: &str = concat!(
    "sha512:",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
const DIGEST_B: &str = concat!(
    "sha512:",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
);
const DIGEST_NON_MATCHING: &str = concat!(
    "sha512:",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
);

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
            DIGEST_A,
        )]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_NON_MATCHING)
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
            ("releases/v1/file-a.tar.gz", DIGEST_A),
            ("releases/v1/file-b.tar.gz", DIGEST_B),
        ]))
        .create();

    let mut cmd = assert_cmd::cargo_bin_cmd!("asfaload-cli");
    cmd.arg("sign-pending")
        .arg("-K")
        .arg(fixture_key_path())
        .arg("-u")
        .arg(server.url())
        .arg("--digest-filter")
        .arg(DIGEST_NON_MATCHING)
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No pending signature found"))
        .stderr(predicate::str::contains("Not a tty").not());
}

#[test]
fn sign_pending_json_mode_no_bishop_art() {
    use base64::Engine;

    let content = b"test file content for json signing";
    let hash_bytes = Sha512::digest(content);
    let digest_str = format!("sha512:{}", hex::encode(hash_bytes));
    let b64_content = base64::engine::general_purpose::STANDARD.encode(content);
    let file_path = "releases/v1/file-json.tar.gz";

    let mut server = mockito::Server::new();

    let files_body = format!(r#"{{"files":{{"{}":{:?}}}}}"#, file_path, b64_content);
    let _m1 = server
        .mock("GET", format!("/v1/files-to-sign/{}", file_path).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&files_body)
        .create();

    let _m2 = server
        .mock("POST", "/v1/signatures")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"is_complete":false}"#)
        .create();

    let output = assert_cmd::cargo_bin_cmd!("asfaload-cli")
        .arg("sign-pending")
        .arg("-K")
        .arg(test_helpers::fixtures_keys_dir().join("key_0"))
        .arg("-u")
        .arg(server.url())
        .arg(file_path)
        .arg("--digest")
        .arg(&digest_str)
        .arg("--json")
        .env("ASFALOAD_SIGN_PENDING_PASSWORD", FIXTURE_PASSWORD)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("+---[SHA512 64]---+"),
        "JSON mode must not contain bishop art"
    );
}
