use anyhow::Result;
use chrono::Utc;
use common::fs::names::{pending_signatures_path_for, signatures_path_for};
use constants::{METADATA_FILE, SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, SignaturesFile,
    TaggedSignature, sha512_for_content,
};
use rest_api::server::run_server;
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_test_helpers::{
    build_test_config, get_random_port, git_commit, init_git_repo, setup_signed_artifact,
    wait_for_commit, wait_for_server,
};
use rest_api_types::{GetSignersChainResponse, SubmitSignatureResponse};
use signers_file_types::{
    Forge, ForgeOrigin, HistoryEntry, HistoryFile, SignersConfig, SignersConfigMetadata,
};
use std::fs;
use tempfile::TempDir;

/// Test get_signers_chain for a signed artifact with no signers rotation.
/// The chain should contain exactly one entry: the active signers config.
#[tokio::test]
async fn test_get_signers_chain_no_history() -> Result<()> {
    let setup = setup_signed_artifact().await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_signers_chain/{}",
            setup.port, setup.artifact_path
        ))
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 200,
        "Expected 200 OK, got {}. Body: {}",
        status, body_text
    );

    let body: GetSignersChainResponse = serde_json::from_str(&body_text)?;

    // With no history (no signers rotation), the chain should have exactly 1 entry:
    // the active signers config at signing time
    assert_eq!(
        body.history.entries().len(),
        1,
        "Chain should have exactly 1 entry when no signers rotation occurred"
    );

    // Verify the entry contains a valid signers config
    let entry = &body.history.entries()[0];
    let signers_config = entry
        .signers_config()
        .expect("Entry should contain valid signers config");
    // Our test setup uses 1-of-1 threshold
    assert_eq!(signers_config.version(), 1);

    Ok(())
}

/// Test get_signers_chain returns an error for a nonexistent artifact path.
#[tokio::test]
async fn test_get_signers_chain_nonexistent_artifact() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_signers_chain/nonexistent/file.bin",
            port
        ))
        .send()
        .await?;

    assert_ne!(
        response.status(),
        200,
        "Should fail for nonexistent artifact"
    );

    server_handle.abort();
    Ok(())
}

/// Test get_signers_chain returns an error for an artifact that exists but was never signed.
#[tokio::test]
async fn test_get_signers_chain_unsigned_artifact() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    // Create an artifact file but don't sign it
    let artifact_rel = "releases/unsigned.bin";
    let artifact_abs = repo_path.join(artifact_rel);
    fs::create_dir_all(artifact_abs.parent().unwrap())?;
    fs::write(&artifact_abs, "unsigned content")?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_signers_chain/{}",
            port, artifact_rel
        ))
        .send()
        .await?;

    assert_ne!(response.status(), 200, "Should fail for unsigned artifact");

    server_handle.abort();
    Ok(())
}

/// Test get_signers_chain blocks path traversal attempts.
#[tokio::test]
async fn test_get_signers_chain_path_traversal() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_signers_chain/../../../etc/passwd",
            port
        ))
        .send()
        .await?;

    assert_ne!(response.status(), 200, "Path traversal should be blocked");

    server_handle.abort();
    Ok(())
}

/// Test get_signers_chain for a signed artifact when the signers config has been rotated.
/// The chain should contain 2 entries: 1 historical + 1 active.
/// Additionally validates that a post-signing signers rotation does NOT affect the chain
/// returned for the artifact (the chain is pinned to the signing time).
#[tokio::test]
async fn test_get_signers_chain_with_history() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    // We use 3 keys: key 0 is the "old" signer (in history), key 1 is the "current" signer,
    // key 2 is used for a post-signing rotation
    let test_keys = test_helpers::TestKeys::new(3);
    let old_public_key = test_keys.pub_key(0).unwrap();
    let old_secret_key = test_keys.sec_key(0).unwrap();
    let current_public_key = test_keys.pub_key(1).unwrap();
    let current_secret_key = test_keys.sec_key(1).unwrap();

    // --- Build the "old" signers config for the history entry ---
    let old_signers_config =
        SignersConfig::with_artifact_signers_only(1, (vec![old_public_key.clone()], 1))?;
    let old_signers_json = old_signers_config.to_json()?;
    let old_signers_hash = sha512_for_content(old_signers_json.as_bytes().to_vec())?;
    let old_signers_sig = old_secret_key.sign(&old_signers_hash)?;
    let mut old_signatures = SignaturesFile::new();
    old_signatures.entries.insert(
        old_public_key.to_base64(),
        TaggedSignature {
            format: old_public_key.key_format(),
            signature: old_signers_sig.to_base64(),
        },
    );
    let old_metadata = SignersConfigMetadata::from_forge(ForgeOrigin::new(
        Forge::Github,
        "https://example.com/old".to_string(),
        Utc::now(),
    ));

    // Create the history file with the old entry.
    // Use a time clearly in the past so the cutoff filter in signers_chain_for_artifact
    // always includes this entry (cutoff is the git commit time, which has second precision).
    let past_time = Utc::now() - chrono::Duration::hours(1);
    let mut history_file = HistoryFile::new();
    history_file.add_entry(HistoryEntry {
        obsoleted_at: past_time,
        signers_file: old_signers_json,
        signatures: old_signatures,
        metadata: old_metadata,
    });

    // --- Build the "current" signers config ---
    let current_signers_config =
        SignersConfig::with_artifact_signers_only(1, (vec![current_public_key.clone()], 1))?;
    let signers_dir = repo_path.join(SIGNERS_DIR);
    fs::create_dir_all(&signers_dir)?;
    fs::write(
        signers_dir.join(SIGNERS_FILE),
        current_signers_config.to_json()?,
    )?;

    // Create metadata file for the current signers config
    let metadata = test_helpers::test_metadata();
    fs::write(
        signers_dir.join(METADATA_FILE),
        serde_json::to_string_pretty(&metadata)?,
    )?;

    // Create signatures file for the current signers config
    let current_signers_content = fs::read(signers_dir.join(SIGNERS_FILE))?;
    let current_signers_hash = sha512_for_content(current_signers_content)?;
    let current_signers_sig = current_secret_key.sign(&current_signers_hash)?;
    let mut current_signatures = SignaturesFile::new();
    current_signatures.entries.insert(
        current_public_key.to_base64(),
        TaggedSignature {
            format: current_public_key.key_format(),
            signature: current_signers_sig.to_base64(),
        },
    );
    let signers_file_path = signers_dir.join(SIGNERS_FILE);
    let signers_sig_path = signatures_path_for(&signers_file_path)?;
    fs::write(
        &signers_sig_path,
        serde_json::to_string(&current_signatures)?,
    )?;

    // Write the history file at the repo root (sibling of SIGNERS_DIR)
    let history_file_path = repo_path.join(SIGNERS_HISTORY_FILE);
    history_file.save_to_file(&history_file_path)?;

    // Commit signers dir + history file together
    git_commit(
        &repo_path,
        &[SIGNERS_DIR, SIGNERS_HISTORY_FILE],
        "initial signers config with history",
    )?;

    // --- Create artifact and pending signatures ---
    let artifact_rel = "releases/artifact.bin";
    let artifact_abs = repo_path.join(artifact_rel);
    fs::create_dir_all(artifact_abs.parent().unwrap())?;
    fs::write(&artifact_abs, "artifact content")?;

    let pending_sig_path = pending_signatures_path_for(&artifact_abs)?;
    fs::write(
        &pending_sig_path,
        serde_json::to_string(&SignaturesFile::new())?,
    )?;

    // --- Start server and submit signature ---
    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    let content = fs::read(&artifact_abs)?;
    let hash = sha512_for_content(content)?;
    let sig = current_secret_key.sign(&hash)?;

    let submit_payload = serde_json::json!({
        "file_path": artifact_rel,
        "public_key": current_public_key.to_base64(),
        "signature": sig.to_base64(),
    });

    let submit_payload_str = submit_payload.to_string();
    let auth_info = AuthInfo::new(submit_payload_str);
    let auth_sig = AuthSignature::new(&auth_info, current_secret_key)?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{}/v1/signatures", port))
        .header(
            HEADER_TIMESTAMP,
            auth_sig.auth_info().timestamp().to_rfc3339(),
        )
        .header(HEADER_NONCE, auth_sig.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_sig.signature().to_base64())
        .header(HEADER_PUBLIC_KEY, current_public_key.to_base64())
        .json(&submit_payload)
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    let body: SubmitSignatureResponse = response.json().await?;
    assert!(body.is_complete, "Signature collection should be complete");

    // Wait for the server to commit
    let expected_msg = format!("completed signature collection for {}", artifact_rel);
    wait_for_commit(repo_path.clone(), &expected_msg, None).await?;

    // --- Call GET /v1/get_signers_chain/{artifact_path} ---
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_signers_chain/{}",
            port, artifact_rel
        ))
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 200,
        "Expected 200 OK, got {}. Body: {}",
        status, body_text
    );

    // --- Phase 1: First chain retrieval + save for comparison ---
    let chain_before_rotation = body_text.clone();
    let body: GetSignersChainResponse = serde_json::from_str(&body_text)?;

    // Validate chain has 2 entries
    assert_eq!(
        body.history.entries().len(),
        2,
        "Chain should have exactly 2 entries (1 historical + 1 active)"
    );

    // First entry: the old signers config (key 0)
    let historical_entry = &body.history.entries()[0];
    let historical_config = historical_entry
        .signers_config()
        .expect("Historical entry should contain valid signers config");
    let old_key_base64 = old_public_key.to_base64();
    assert!(
        historical_config
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == old_key_base64),
        "Historical entry should contain the old public key"
    );

    // Second entry: the current/active signers config (key 1)
    let active_entry = &body.history.entries()[1];
    let active_config = active_entry
        .signers_config()
        .expect("Active entry should contain valid signers config");
    let current_key_base64 = current_public_key.to_base64();
    assert!(
        active_config
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == current_key_base64),
        "Active entry should contain the current public key"
    );

    // --- Phase 2: Simulate a post-signing signers rotation ---
    // Create a new signers config with key 2
    let new_public_key = test_keys.pub_key(2).unwrap();
    let new_secret_key = test_keys.sec_key(2).unwrap();
    let new_signers_config =
        SignersConfig::with_artifact_signers_only(1, (vec![new_public_key.clone()], 1))?;

    // Move the current signers (key 1) into history
    let current_signers_json = current_signers_config.to_json()?;
    let rotation_time = Utc::now();
    // Load the existing history file and add the current config as a new entry
    let mut updated_history = HistoryFile::load_from_file(&history_file_path)?;
    updated_history.add_entry(HistoryEntry {
        obsoleted_at: rotation_time,
        signers_file: current_signers_json,
        signatures: current_signatures.clone(),
        metadata: metadata.clone(),
    });
    updated_history.save_to_file(&history_file_path)?;

    // Write the new signers config
    fs::write(
        signers_dir.join(SIGNERS_FILE),
        new_signers_config.to_json()?,
    )?;

    // Create signatures for new signers config
    let new_signers_content = fs::read(signers_dir.join(SIGNERS_FILE))?;
    let new_signers_hash = sha512_for_content(new_signers_content)?;
    let new_signers_sig = new_secret_key.sign(&new_signers_hash)?;
    let mut new_signatures = SignaturesFile::new();
    new_signatures.entries.insert(
        new_public_key.to_base64(),
        TaggedSignature {
            format: new_public_key.key_format(),
            signature: new_signers_sig.to_base64(),
        },
    );
    fs::write(&signers_sig_path, serde_json::to_string(&new_signatures)?)?;

    // Update metadata
    let new_metadata = test_helpers::test_metadata();
    fs::write(
        signers_dir.join(METADATA_FILE),
        serde_json::to_string_pretty(&new_metadata)?,
    )?;

    // Commit the rotation
    git_commit(
        &repo_path,
        &[SIGNERS_DIR, SIGNERS_HISTORY_FILE],
        "signers rotation: key 1 -> key 2",
    )?;

    // --- Phase 3: Verify the chain is unchanged after post-signing rotation ---
    let response_after = client
        .get(format!(
            "http://127.0.0.1:{}/v1/get_signers_chain/{}",
            port, artifact_rel
        ))
        .send()
        .await?;

    let status_after = response_after.status();
    let body_text_after = response_after.text().await?;
    assert_eq!(
        status_after, 200,
        "Expected 200 OK after rotation, got {}. Body: {}",
        status_after, body_text_after
    );

    let body_after: GetSignersChainResponse = serde_json::from_str(&body_text_after)?;

    // Chain should STILL have exactly 2 entries -- the post-signing rotation must NOT appear
    assert_eq!(
        body_after.history.entries().len(),
        2,
        "Chain should still have 2 entries after post-signing rotation (rotation should be excluded)"
    );

    // First entry should still be the old config (key 0)
    let historical_after = &body_after.history.entries()[0];
    let historical_config_after = historical_after
        .signers_config()
        .expect("Historical entry should still be valid after rotation");
    assert!(
        historical_config_after
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == old_key_base64),
        "Historical entry should still contain the old public key (key 0) after rotation"
    );

    // Second entry should still be the pre-rotation active config (key 1), NOT key 2
    let active_after = &body_after.history.entries()[1];
    let active_config_after = active_after
        .signers_config()
        .expect("Active entry should still be valid after rotation");
    assert!(
        active_config_after
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == current_key_base64),
        "Active entry should still contain key 1 (not the post-rotation key 2)"
    );
    let new_key_base64 = new_public_key.to_base64();
    assert!(
        !active_config_after
            .artifact_signers()
            .iter()
            .flat_map(|g| g.signers.iter())
            .any(|s| s.data.pubkey.to_base64() == new_key_base64),
        "Post-rotation key 2 should NOT appear in the chain"
    );

    // Also verify the serialized chain is identical
    assert_eq!(
        chain_before_rotation, body_text_after,
        "Chain JSON should be byte-identical before and after post-signing rotation"
    );

    server_handle.abort();
    Ok(())
}
