use anyhow::Result;
use common::fs::names::pending_signatures_path_for;
use constants::{METADATA_FILE, SIGNERS_DIR, SIGNERS_FILE};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, SignaturesFile,
    sha512_for_content,
};
use rest_api::server::run_server;
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_test_helpers::{
    build_test_config, get_random_port, init_git_repo, wait_for_commit, wait_for_server,
};
use rest_api_types::SubmitSignatureResponse;
use signers_file_types::SignersConfig;
use std::fs;
use tempfile::TempDir;
use tokio::task::JoinHandle;

struct TestSetup {
    _temp_dir: TempDir,
    repo_path: std::path::PathBuf,
    port: u16,
    server_handle: JoinHandle<Result<(), rest_api_types::errors::ApiError>>,
    artifact_path: String,
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        self.server_handle.abort();
    }
}

/// Sets up a git repo with signers config+metadata, creates an artifact,
/// submits a signature to complete the signing workflow, and waits for commit.
async fn setup_signed_artifact() -> Result<TestSetup> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    let test_keys = test_helpers::TestKeys::new(1);
    let public_key = test_keys.pub_key(0).unwrap();
    let secret_key = test_keys.sec_key(0).unwrap();

    // Create signers config: 1-of-1 for simple completion
    let signers_config =
        SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))?;
    let signers_dir = repo_path.join(SIGNERS_DIR);
    fs::create_dir_all(&signers_dir)?;
    fs::write(signers_dir.join(SIGNERS_FILE), signers_config.to_json()?)?;

    // Create metadata file
    let metadata = test_helpers::test_metadata();
    fs::write(
        signers_dir.join(METADATA_FILE),
        serde_json::to_string_pretty(&metadata)?,
    )?;

    // Create artifact file
    let artifact_rel = "releases/artifact.bin";
    let artifact_abs = repo_path.join(artifact_rel);
    fs::create_dir_all(artifact_abs.parent().unwrap())?;
    fs::write(&artifact_abs, "artifact content")?;

    // Create empty pending signatures file
    let pending_sig_path = pending_signatures_path_for(&artifact_abs)?;
    fs::write(
        &pending_sig_path,
        serde_json::to_string(&SignaturesFile::new())?,
    )?;

    // Start server
    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    // Submit signature to complete the signing workflow
    let content = fs::read(&artifact_abs)?;
    let hash = sha512_for_content(content)?;
    let sig = secret_key.sign(&hash)?;

    let submit_payload = serde_json::json!({
        "file_path": artifact_rel,
        "public_key": public_key.to_base64(),
        "signature": sig.to_base64(),
    });

    let submit_payload_str = submit_payload.to_string();
    let auth_info = AuthInfo::new(submit_payload_str);
    let auth_sig = AuthSignature::new(&auth_info, secret_key)?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/v1/signatures", port))
        .header(
            HEADER_TIMESTAMP,
            auth_sig.auth_info().timestamp().to_rfc3339(),
        )
        .header(HEADER_NONCE, auth_sig.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_sig.signature().to_base64())
        .header(HEADER_PUBLIC_KEY, public_key.to_base64())
        .json(&submit_payload)
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    let body: SubmitSignatureResponse = response.json().await?;
    assert!(body.is_complete, "Signature collection should be complete");

    // Wait for the server to commit
    let expected_msg = format!("completed signature collection for {}", artifact_rel);
    wait_for_commit(repo_path.clone(), &expected_msg, None).await?;

    Ok(TestSetup {
        _temp_dir: temp_dir,
        repo_path,
        port,
        server_handle,
        artifact_path: artifact_rel.to_string(),
    })
}
