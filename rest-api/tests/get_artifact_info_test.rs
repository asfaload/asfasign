use anyhow::Result;
use features_lib::{AsfaloadPublicKeyTrait, SignaturesFile};
use rest_api_test_helpers::TestSetupBuilder;
use rest_api_types::models::GetArtifactInfoResponse;
use serde_json::json;

// The endpoint receives an artifact *download* URL and resolves it to the
// index file's repository path via the forge-url layer. For the FileServer
// forge, `https://example.com/releases/release.txt` maps to the index file
// `<scheme>/<host>/<port>/<dir>/asfaload.index.json`. The signed file in the
// test repo is therefore that index path.
const ARTIFACT_URL: &str = "https://example.com/releases/release.txt";
const INDEX_REPO_PATH: &str = "https/example.com/443/releases/asfaload.index.json";
// A download URL whose index is not registered/signed in the repo.
const UNREGISTERED_URL: &str = "https://example.com/unregistered/file.txt";

const INDEX_CONTENT: &str = r#"{"version":"1.0","artifacts":[]}"#;

fn get_artifact_info_body(artifact_url: &str) -> serde_json::Value {
    json!({ "artifact_url": artifact_url, "forge_kind": "fileserver" })
}

/// A signed artifact returns 200 with the index JSON, its raw signatures
/// envelope, and the signers chain anchored at the signature commit.
#[tokio::test]
async fn test_get_artifact_info_returns_200_with_index_and_signatures() -> Result<()> {
    let setup = TestSetupBuilder::new()
        .with_artifact(INDEX_REPO_PATH)
        .with_artifact_content(INDEX_CONTENT)
        .build_and_sign()
        .await?;

    let public_key = setup.test_keys().pub_key(0).unwrap();

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/v1/get_artifact_info",
            setup.port()
        ))
        .json(&get_artifact_info_body(ARTIFACT_URL))
        .send()
        .await?;
    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 200,
        "Expected 200 OK, got {}. Body: {}",
        status, body_text
    );

    let body: GetArtifactInfoResponse = serde_json::from_str(&body_text)?;

    // The index JSON round-trips byte-for-byte.
    assert_eq!(body.index_json, INDEX_CONTENT);

    // `index_signatures_raw` is the opaque raw signatures JSON. It must parse
    // and contain the signer's entry.
    let parsed_signatures: SignaturesFile = serde_json::from_str(&body.index_signatures_raw)?;
    assert!(
        parsed_signatures
            .entries
            .contains_key(&public_key.to_base64()),
        "index_signatures_raw should contain the signer's entry"
    );

    // The chain head is the active config at signature time (no rotation).
    assert_eq!(
        body.signers_chain.entries().len(),
        1,
        "Chain should have exactly one entry when no signers rotation has happened"
    );

    Ok(())
}

/// An artifact whose index is not registered/signed returns 400: the chain
/// cannot be traced back to a signers source.
#[tokio::test]
async fn test_get_artifact_info_returns_400_when_artifact_not_registered() -> Result<()> {
    let setup = TestSetupBuilder::new()
        .with_artifact(INDEX_REPO_PATH)
        .with_artifact_content(INDEX_CONTENT)
        .build_and_sign()
        .await?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/v1/get_artifact_info",
            setup.port()
        ))
        .json(&get_artifact_info_body(UNREGISTERED_URL))
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    assert_eq!(
        status, 400,
        "Expected 400 Bad Request, got {}. Body: {}",
        status, body_text
    );
    assert!(
        body_text.contains("Could not identify signers source"),
        "Response body should contain handler phrase \"Could not identify signers source\", got: {}",
        body_text
    );
    Ok(())
}
