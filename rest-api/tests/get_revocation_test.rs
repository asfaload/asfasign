use anyhow::Result;
use chrono::Utc;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, SignaturesFile,
    sha512_for_content, sha512_for_file,
};
use rest_api_test_helpers::{TestSetupBuilder, send_authenticated_request_with_key};
use rest_api_types::RevokeFileResponse;
use rest_api_types::models::GetRevocationResponse;
use serde_json::json;

// The endpoint receives an artifact *download* URL and resolves it to the
// index file's repository path via the forge-url layer. For the FileServer
// forge, `https://example.com/releases/release.txt` maps to the index file
// `<scheme>/<host>/<port>/<dir>/asfaload.index.json`. The signed file in the
// test repo is therefore that index path, and the revocation hangs off it.
const ARTIFACT_URL: &str = "https://example.com/releases/release.txt";
const INDEX_REPO_PATH: &str = "https/example.com/443/releases/asfaload.index.json";

fn get_revocation_body() -> serde_json::Value {
    json!({ "artifact_url": ARTIFACT_URL, "forge_kind": "fileserver" })
}

/// A revoked artifact returns 200 with the revocation payload, and the
/// `revocation_signatures` field carries the actual signatures envelope.
#[tokio::test]
async fn test_get_revocation_returns_200_with_revocation_signatures() -> Result<()> {
    let setup = TestSetupBuilder::new()
        .with_artifact(INDEX_REPO_PATH)
        .build_and_sign()
        .await?;

    // Revoke the index file (single signer, threshold 1).
    let index_file = setup.repo_path().join(setup.artifact_path());
    let subject_digest = sha512_for_file(&index_file)?;
    let public_key = setup.test_keys().pub_key(0).unwrap();
    let secret_key = setup.test_keys().sec_key(0).unwrap();

    let revocation = signers_file_types::revocation::RevocationInfo {
        timestamp: Utc::now(),
        subject_digest,
        initiator: public_key.clone(),
    };
    let revocation_json = serde_json::to_string_pretty(&revocation)?;
    let revocation_hash = sha512_for_content(revocation_json.as_bytes().to_vec())?;
    let revoke_signature = secret_key.sign(&revocation_hash)?;

    let revoke_payload = json!({
        "file_path": INDEX_REPO_PATH,
        "revocation_json": revocation_json,
        "signature": revoke_signature.to_base64(),
        "public_key": public_key.to_base64(),
    });

    let client = reqwest::Client::new();
    let revoke_resp =
        send_authenticated_request_with_key(&client, setup.port(), secret_key, &revoke_payload)
            .await;
    assert_eq!(revoke_resp.status(), 200);
    let revoke_body: RevokeFileResponse = revoke_resp.json().await?;
    assert!(revoke_body.success);

    // Fetch the revocation via the new endpoint, using the artifact download URL.
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/v1/get_revocation",
            setup.port()
        ))
        .json(&get_revocation_body())
        .send()
        .await?;
    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 200,
        "Expected 200 OK, got {}. Body: {}",
        status, body_text
    );

    let body: GetRevocationResponse = serde_json::from_str(&body_text)?;

    // The revocation JSON round-trips byte-for-byte.
    assert_eq!(body.revocation_json, revocation_json);

    // `revocation_signatures` is the opaque raw signatures JSON. It must parse
    // and contain the initiator's entry. With the doubled-suffix path bug the
    // handler would never reach this point (the git read would fail first).
    let parsed_signatures: SignaturesFile = serde_json::from_str(&body.revocation_signatures)?;
    assert!(
        parsed_signatures
            .entries
            .contains_key(&public_key.to_base64()),
        "revocation_signatures should contain the initiator's entry"
    );

    // The chain head is the active config at revocation time (no rotation).
    assert_eq!(
        body.signers_chain.entries().len(),
        1,
        "Chain should have exactly one entry when no signers rotation has happened"
    );

    Ok(())
}

/// When no revocation exists for the artifact, the endpoint returns the
/// handler's own 404 (not axum's default route-miss 404).
#[tokio::test]
async fn test_get_revocation_returns_404_when_no_revocation_exists() -> Result<()> {
    let setup = TestSetupBuilder::new()
        .with_artifact(INDEX_REPO_PATH)
        .build_and_sign()
        .await?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/v1/get_revocation",
            setup.port()
        ))
        .json(&get_revocation_body())
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 404,
        "Expected 404 Not Found, got {}. Body: {}",
        status, body_text
    );
    // Discriminate the handler's 404 from axum's default route-miss 404: the
    // handler returns ApiError::FileNotFound carrying "No revocation for: ...".
    assert!(
        body_text.contains("No revocation for"),
        "Response body should contain handler phrase \"No revocation for\", got: {}",
        body_text
    );
    Ok(())
}
