use crate::{AsfaloadLibResult, ClientLibError};

/// Result of a successful signers chain validation.
#[derive(Debug)]
pub struct SignersChainResult {
    /// Number of entries in the validated chain.
    pub entries_count: usize,
}

/// Validate the signers chain for a signed artifact.
///
/// Fetches the chain from the backend API, validates the first entry
/// against its forge source (content match + all signers signed), then
/// validates all chain transitions using `validate_history`.
///
/// This function creates its own HTTP clients internally.
pub async fn verify_signers_chain(
    backend_url: &str,
    artifact_path: &str,
) -> AsfaloadLibResult<SignersChainResult> {
    let admin_client = admin_lib::v1::Client::new(backend_url);
    let http_client = reqwest::Client::new();

    // Step 1: Fetch the chain
    let chain_response = admin_client
        .get_signers_chain(artifact_path)
        .await
        .map_err(|e| ClientLibError::SignersChainFetchError(e.to_string()))?;

    let history = chain_response.history;

    // Step 2: Check non-empty
    if history.entries().is_empty() {
        return Err(ClientLibError::SignersChainEmpty);
    }

    // Step 3: Validate first entry
    validate_first_entry(&http_client, history.entries().first().unwrap()).await?;

    // Step 4: Validate chain transitions (if more than 1 entry)
    if history.entries().len() > 1 && !features_lib::validate_history(&history) {
        return Err(ClientLibError::SignersChainTransitionInvalid);
    }

    Ok(SignersChainResult {
        entries_count: history.entries().len(),
    })
}

/// Validate the first entry in the signers chain.
///
/// 1. Fetch the signers file from its original forge URL (in metadata)
/// 2. Compare content with what's stored in the history entry
/// 3. Verify all signers in the config signed it (InitialSignersFile rule)
async fn validate_first_entry(
    client: &reqwest::Client,
    entry: &features_lib::HistoryEntry,
) -> AsfaloadLibResult<()> {
    // Extract forge URL from metadata
    let forge_url = match entry.metadata.origin() {
        features_lib::SignersConfigOrigin::Forge(forge) => forge.url(),
    };

    // Fetch from forge
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

    // Compare content
    if forge_content != entry.signers_file {
        return Err(ClientLibError::SignersChainFirstEntryMismatch);
    }

    // Parse signers config using the entry's built-in method
    let signers_config = entry
        .signers_config()
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    // Compute hash of the raw content (this is what was signed)
    let file_hash = features_lib::sha512_for_content(entry.signers_file.as_bytes().to_vec())?;

    // Parse tagged signatures
    let signatures = features_lib::aggregate_signature_helpers::parse_tagged_signatures(
        &entry.signatures.entries,
    )
    .map_err(|e| ClientLibError::SignaturesParseError(e.to_string()))?;

    // Verify all signers signed
    if !features_lib::aggregate_signature_helpers::check_all_signers(
        &signatures,
        &signers_config,
        &file_hash,
    ) {
        return Err(ClientLibError::SignersChainFirstEntrySignatureInvalid);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
