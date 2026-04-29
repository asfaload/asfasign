use crate::{AsfaloadLibResult, ClientLibError};
use rest_api_types::GetSignersChainResponse;

/// Result of a successful signers chain validation.
#[derive(Debug)]
pub struct SignersChainResult {
    /// Number of entries in the validated chain.
    pub entries_count: usize,
}

/// Fetch the signers chain for a signed artifact from the backend.
///
/// Makes an unauthenticated GET request to `/v1/get_signers_chain/{artifact_path}`.
async fn get_signers_chain(
    client: &reqwest::Client,
    backend_url: &str,
    artifact_path: &str,
) -> AsfaloadLibResult<GetSignersChainResponse> {
    let url = format!("{}/v1/get_signers_chain/{}", backend_url, artifact_path);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ClientLibError::SignersChainFetchError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "(failed to read response body)".to_string());
        return Err(ClientLibError::SignersChainFetchError(format!(
            "{}: {}",
            status, body
        )));
    }

    response
        .json::<GetSignersChainResponse>()
        .await
        .map_err(|e| ClientLibError::SignersChainFetchError(e.to_string()))
}

/// Validate the signers chain for a signed artifact.
///
/// Fetches the chain from the backend API, runs cryptographic validation
/// across the entire history (including the first-entry all-signers rule)
/// via `validate_chain`, and finally checks the first entry's
/// trust-anchor (forge content match).
pub async fn verify_signers_chain(
    backend_url: &str,
    artifact_path: &str,
) -> AsfaloadLibResult<SignersChainResult> {
    let http_client = reqwest::Client::new();

    let chain_response = get_signers_chain(&http_client, backend_url, artifact_path).await?;

    let chain = chain_response.chain;

    if chain.entries().is_empty() {
        return Err(ClientLibError::SignersChainEmpty);
    }

    // Cryptographic validation of the entire chain (incl. first-entry all-signers).
    if !features_lib::validate_chain(&chain) {
        return Err(ClientLibError::SignersChainFirstEntryInvalid(
            "signers chain validation failed".into(),
        ));
    }

    // Trust-anchor check: first entry's forge content must match.
    let first = chain
        .first_entry()
        .ok_or(ClientLibError::SignersChainFirstEntryMismatch)?;
    validate_trust_anchor(&http_client, &first).await?;

    Ok(SignersChainResult {
        entries_count: chain.entries().len(),
    })
}

/// Validate that a history entry's signers_file matches the content
/// served by the forge URL recorded in its metadata.
///
/// Signature validity is assumed to have already been checked by
/// `validate_chain`. This function only performs the forge fetch and
/// content comparison.
pub(crate) async fn validate_trust_anchor(
    client: &reqwest::Client,
    entry: &features_lib::SignersChainEntry,
) -> AsfaloadLibResult<()> {
    let metadata = entry
        .metadata()
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    let forge_url = match metadata.origin() {
        features_lib::SignersConfigOrigin::Forge(forge) => forge.retrieval_url(),
    };

    let response = client
        .get(forge_url)
        .send()
        .await
        .map_err(|e| ClientLibError::SignersChainForgeFetchError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(ClientLibError::SignersChainForgeFetchError(format!(
            "HTTP {}",
            response.status()
        )));
    }

    let forge_content = response
        .text()
        .await
        .map_err(|e| ClientLibError::SignersChainForgeFetchError(e.to_string()))?;

    if forge_content != entry.signers_file() {
        return Err(ClientLibError::SignersChainFirstEntryMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use features_lib::SignersConfig;
    use test_helpers::TestKeys;
    use test_helpers::history_helpers::make_history_entry;

    #[tokio::test]
    async fn verify_signers_chain_returns_error_when_api_unreachable() {
        // Use a port that nothing listens on
        let result = verify_signers_chain("http://127.0.0.1:1", "some/path").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::SignersChainFetchError(_) => {}
            other => panic!("Expected SignersChainFetchError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn verify_signers_chain_returns_error_on_empty_chain() {
        let mut server = mockito::Server::new_async().await;
        let response_body = serde_json::json!({ "history": { "entries": [] } });

        let _mock = server
            .mock("GET", "/v1/get_signers_chain/test/path")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&response_body).unwrap())
            .create_async()
            .await;

        let result = verify_signers_chain(&server.url(), "test/path").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::SignersChainEmpty => {}
            other => panic!("Expected SignersChainEmpty, got: {:?}", other),
        }
    }

    // -- Tests for validate_trust_anchor --

    #[tokio::test]
    async fn validate_trust_anchor_passes_when_forge_content_matches() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body(entry.signers_file.clone())
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_returns_500() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(500)
            .with_body("server error")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainForgeFetchError(_))
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_returns_404() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(404)
            .with_body("not found")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainForgeFetchError(_))
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_content_differs() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body("completely different content")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainFirstEntryMismatch)
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_whitespace_diff() {
        let mut server = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry = make_history_entry(&config, &keys, &[0], &server.url(), timestamp).unwrap();

        let body = format!("{}\n", entry.signers_file);
        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainFirstEntryMismatch)
        ));
    }

    #[tokio::test]
    async fn validate_trust_anchor_fails_when_forge_unreachable() {
        let keys = TestKeys::new(1);
        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();
        let entry =
            make_history_entry(&config, &keys, &[0], "http://127.0.0.1:1", timestamp).unwrap();

        let client = reqwest::Client::new();
        let result =
            validate_trust_anchor(&client, &features_lib::SignersChainEntry::History(entry)).await;
        assert!(matches!(
            result,
            Err(ClientLibError::SignersChainForgeFetchError(_))
        ));
    }
}
