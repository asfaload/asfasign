use anyhow::Result;
use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE, pending_signatures_path_for};
use features_lib::{AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, sha512_for_content, AsfaloadKeyPairs};
use rest_api::server::run_server;
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_test_helpers::{build_test_config, get_random_port, init_git_repo, wait_for_server};
use rest_api_types::{ListPendingResponse, SubmitSignatureResponse};
use signers_file_types::SignersConfig;
use std::fs;
use tempfile::TempDir;

/// End-to-end test for the complete pending workflow:
/// 1. Setup backend with signers config
/// 2. Create artifact with pending signatures file
/// 3. List pending signatures
/// 4. Submit first signature
/// 5. Verify signature status (incomplete)
/// 6. List pending again (empty for key1)
#[tokio::test]
async fn test_pending_workflow_end_to_end() -> Result<()> {
    // Setup backend
    let temp_dir = TempDir::new()?;
    let repo_path_buf = temp_dir.path().to_path_buf();

    // Initialize git repo
    init_git_repo(&repo_path_buf)?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path_buf, port);

    // Generate key pairs
    let key_pair1 = AsfaloadKeyPairs::new("pwd1")?;
    let key_pair2 = AsfaloadKeyPairs::new("pwd2")?;
    let secret_key1 = key_pair1.secret_key("pwd1")?;
    let secret_key2 = key_pair2.secret_key("pwd2")?;

    // Setup signers configuration: require 2 out of 2 signatures
    let signers_config = SignersConfig::with_artifact_signers_only(
        2,
        (vec![key_pair1.public_key().clone(), key_pair2.public_key().clone()], 2),
    )?;

    // Create signers directory and write config
    let signers_dir = repo_path_buf.join(SIGNERS_DIR);
    fs::create_dir_all(&signers_dir)?;
    fs::write(
        signers_dir.join(SIGNERS_FILE),
        signers_config.to_json()?,
    )?;

    // Create artifact file (simpler path for test)
    let file_path_str = "myartifact/release.txt";
    let artifact_path = repo_path_buf.join(file_path_str);
    fs::create_dir_all(artifact_path.parent().unwrap())?;
    fs::write(&artifact_path, "artifact content")?;

    // Create empty pending signatures file to indicate this file needs signatures
    let pending_sig_path = pending_signatures_path_for(&artifact_path)?;
    fs::write(&pending_sig_path, "{}")?;

    // Start server
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    // Create HTTP client
    let client = reqwest::Client::new();

    // ===== Test 1: key1 requests pending list =====
    let pending_request_payload = "";
    let auth_info1 = AuthInfo::new(pending_request_payload.to_string());
    let auth_signature1 = AuthSignature::new(&auth_info1, &secret_key1)?;

    let response1 = client
        .get(format!("http://127.0.0.1:{}/pending_signatures", port))
        .header(HEADER_TIMESTAMP, auth_signature1.auth_info().timestamp().to_rfc3339())
        .header(HEADER_NONCE, auth_signature1.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature1.signature().to_base64())
        .header("X-Public-Key", key_pair1.public_key().to_base64())
        .send()
        .await?;

    println!("Response status: {}", response1.status());
    assert_eq!(response1.status(), 200);

    let response1_body: ListPendingResponse = response1.json().await?;
    println!("Pending files for key1: {:?}", response1_body.file_paths);
    assert_eq!(response1_body.file_paths.len(), 1);
    assert_eq!(response1_body.file_paths[0], file_path_str);

    // ===== Test 2: key1 submits signature =====
    let content = fs::read(&artifact_path)?;
    let hash = sha512_for_content(content)?;
    let sig = secret_key1.sign(&hash)?;

    let submit_payload = serde_json::json!({
        "file_path": file_path_str,
        "public_key": key_pair1.public_key().to_base64(),
        "signature": sig.to_base64()
    });

    let submit_payload_str = submit_payload.to_string();
    let auth_info2 = AuthInfo::new(submit_payload_str.clone());
    let auth_signature2 = AuthSignature::new(&auth_info2, &secret_key1)?;

    let response2 = client
        .post(format!("http://127.0.0.1:{}/signatures", port))
        .header(HEADER_TIMESTAMP, auth_signature2.auth_info().timestamp().to_rfc3339())
        .header(HEADER_NONCE, auth_signature2.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature2.signature().to_base64())
        .header("X-Public-Key", key_pair1.public_key().to_base64())
        .json(&submit_payload)
        .send()
        .await?;

    println!("Submit signature status: {}", response2.status());
    assert_eq!(response2.status(), 200);

    let response2_body: SubmitSignatureResponse = response2.json().await?;
    println!("Is complete: {}", response2_body.is_complete);
    assert!(!response2_body.is_complete); // Need 2 sigs, only have 1

    // ===== Test 3: key1 requests pending list again =====
    // Should be empty now since key1 already signed
    let auth_info3 = AuthInfo::new("".to_string());
    let auth_signature3 = AuthSignature::new(&auth_info3, &secret_key1)?;

    let response3 = client
        .get(format!("http://127.0.0.1:{}/pending_signatures", port))
        .header(HEADER_TIMESTAMP, auth_signature3.auth_info().timestamp().to_rfc3339())
        .header(HEADER_NONCE, auth_signature3.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature3.signature().to_base64())
        .header("X-Public-Key", key_pair1.public_key().to_base64())
        .send()
        .await?;

    println!("Response 3 status: {}", response3.status());
    assert_eq!(response3.status(), 200);

    let response3_body: ListPendingResponse = response3.json().await?;
    println!("Pending files for key1 after signing: {:?}", response3_body.file_paths);
    assert!(response3_body.file_paths.is_empty());

    // ===== Test 4: Verify key2 still sees pending file =====
    let auth_info4 = AuthInfo::new("".to_string());
    let auth_signature4 = AuthSignature::new(&auth_info4, &secret_key2)?;

    let response4 = client
        .get(format!("http://127.0.0.1:{}/pending_signatures", port))
        .header(HEADER_TIMESTAMP, auth_signature4.auth_info().timestamp().to_rfc3339())
        .header(HEADER_NONCE, auth_signature4.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature4.signature().to_base64())
        .header("X-Public-Key", key_pair2.public_key().to_base64())
        .send()
        .await?;

    println!("Response 4 status: {}", response4.status());
    assert_eq!(response4.status(), 200);

    let response4_body: ListPendingResponse = response4.json().await?;
    println!("Pending files for key2: {:?}", response4_body.file_paths);
    assert_eq!(response4_body.file_paths.len(), 1);
    assert_eq!(response4_body.file_paths[0], file_path_str);

    // Clean up
    server_handle.abort();

    Ok(())
}
