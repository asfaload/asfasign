use anyhow::Result;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, sha512_for_content,
};
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_test_helpers::TestSetupBuilder;
use rest_api_types::{ListPendingResponse, SubmitSignatureResponse};
use std::fs;

/// End-to-end test for the complete pending workflow:
/// 1. Setup backend with signers config
/// 2. Create artifact with pending signatures file
/// 3. List pending signatures
/// 4. Submit first signature
/// 5. Verify signature status (incomplete)
/// 6. List pending again (empty for key1)
#[tokio::test]
async fn test_pending_workflow_end_to_end() -> Result<()> {
    // Setup backend using the builder
    let setup = TestSetupBuilder::new()
        .with_keys(2)
        .with_threshold(2)
        .with_artifact("myartifact/release.txt")
        .build()
        .await?;

    let port = setup.port();
    let test_keys = setup.test_keys();
    let file_path_str = setup.artifact_path();
    let secret_key1 = test_keys.sec_key(0).unwrap();
    let secret_key2 = test_keys.sec_key(1).unwrap();

    // Create HTTP client
    let client = reqwest::Client::new();

    // ===== Test 1: key1 requests pending list =====
    let pending_request_payload = "";
    let auth_info1 = AuthInfo::new(pending_request_payload.to_string());
    let auth_signature1 = AuthSignature::new(&auth_info1, secret_key1)?;

    let response1 = client
        .get(format!("http://127.0.0.1:{}/v1/pending_signatures", port))
        .header(
            HEADER_TIMESTAMP,
            auth_signature1.auth_info().timestamp().to_rfc3339(),
        )
        .header(HEADER_NONCE, auth_signature1.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature1.signature().to_base64())
        .header(HEADER_PUBLIC_KEY, test_keys.pub_key(0).unwrap().to_base64())
        .send()
        .await?;

    println!("Response status: {}", response1.status());
    assert_eq!(response1.status(), 200);

    let response1_body: ListPendingResponse = response1.json().await?;
    println!("Pending files for key1: {:?}", response1_body.file_paths);
    assert_eq!(response1_body.file_paths.len(), 1);
    assert_eq!(response1_body.file_paths[0], file_path_str);

    // ===== Test 2: key1 submits signature =====
    let artifact_path = setup.repo_path().join(file_path_str);
    let content = fs::read(&artifact_path)?;
    let hash = sha512_for_content(content)?;
    let sig = secret_key1.sign(&hash)?;

    let submit_payload = serde_json::json!({
        "file_path": file_path_str,
        "public_key": test_keys.pub_key(0).unwrap().to_base64(),
        "signature": sig.to_base64()
    });

    let submit_payload_str = submit_payload.to_string();
    let auth_info2 = AuthInfo::new(submit_payload_str.clone());
    let auth_signature2 = AuthSignature::new(&auth_info2, secret_key1)?;

    let response2 = client
        .post(format!("http://127.0.0.1:{}/v1/signatures", port))
        .header(
            HEADER_TIMESTAMP,
            auth_signature2.auth_info().timestamp().to_rfc3339(),
        )
        .header(HEADER_NONCE, auth_signature2.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature2.signature().to_base64())
        .header(HEADER_PUBLIC_KEY, test_keys.pub_key(0).unwrap().to_base64())
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
    let auth_signature3 = AuthSignature::new(&auth_info3, secret_key1)?;

    let response3 = client
        .get(format!("http://127.0.0.1:{}/v1/pending_signatures", port))
        .header(
            HEADER_TIMESTAMP,
            auth_signature3.auth_info().timestamp().to_rfc3339(),
        )
        .header(HEADER_NONCE, auth_signature3.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature3.signature().to_base64())
        .header(HEADER_PUBLIC_KEY, test_keys.pub_key(0).unwrap().to_base64())
        .send()
        .await?;

    println!("Response 3 status: {}", response3.status());
    assert_eq!(response3.status(), 200);

    let response3_body: ListPendingResponse = response3.json().await?;
    println!(
        "Pending files for key1 after signing: {:?}",
        response3_body.file_paths
    );
    assert!(response3_body.file_paths.is_empty());

    // ===== Test 4: Verify key2 still sees pending file =====
    let auth_info4 = AuthInfo::new("".to_string());
    let auth_signature4 = AuthSignature::new(&auth_info4, secret_key2)?;

    let response4 = client
        .get(format!("http://127.0.0.1:{}/v1/pending_signatures", port))
        .header(
            HEADER_TIMESTAMP,
            auth_signature4.auth_info().timestamp().to_rfc3339(),
        )
        .header(HEADER_NONCE, auth_signature4.auth_info().nonce())
        .header(HEADER_SIGNATURE, auth_signature4.signature().to_base64())
        .header(HEADER_PUBLIC_KEY, test_keys.pub_key(1).unwrap().to_base64())
        .send()
        .await?;

    println!("Response 4 status: {}", response4.status());
    assert_eq!(response4.status(), 200);

    let response4_body: ListPendingResponse = response4.json().await?;
    println!("Pending files for key2: {:?}", response4_body.file_paths);
    assert_eq!(response4_body.file_paths.len(), 1);
    assert_eq!(response4_body.file_paths[0], file_path_str);

    Ok(())
}
