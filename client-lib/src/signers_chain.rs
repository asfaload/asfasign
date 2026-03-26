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
/// Fetches the chain from the backend API, validates the first entry
/// against its forge source (content match + all signers signed), then
/// validates all chain transitions using `validate_history`.
///
/// This function creates its own HTTP clients internally.
pub async fn verify_signers_chain(
    backend_url: &str,
    artifact_path: &str,
) -> AsfaloadLibResult<SignersChainResult> {
    let http_client = reqwest::Client::new();

    // Fetch the chain
    let chain_response = get_signers_chain(&http_client, backend_url, artifact_path).await?;

    let history = chain_response.history;

    // Check non-empty
    if history.entries().is_empty() {
        return Err(ClientLibError::SignersChainEmpty);
    }

    // Validate chain transitions (if more than 1 entry)
    if history.entries().len() > 1 && !features_lib::validate_history(&history) {
        return Err(ClientLibError::SignersChainTransitionInvalid);
    }

    // Validate first entry
    validate_first_entry(&http_client, history.entries().first().unwrap()).await?;

    Ok(SignersChainResult {
        entries_count: history.entries().len(),
    })
}

/// Validate the first entry in the signers chain.
///
/// 1. Fetch the signers file from its original forge URL (in metadata)
/// 2. Compare content with what's stored in the history entry
/// 3. Verify all signers in the config signed it (InitialSignersFile rule)
pub(crate) async fn validate_first_entry(
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

    // -- Scenario-based tests for validate_first_entry --

    use features_lib::{
        AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, Forge, ForgeOrigin,
        HistoryEntry, SignaturesFile, SignersConfig, SignersConfigMetadata, TaggedSignature,
    };
    use test_helpers::TestKeys;
    use test_helpers::history_helpers::make_history_entry;

    #[derive(Debug)]
    enum Expected {
        Ok,
        Err(ExpectedError),
    }

    #[derive(Debug)]
    enum ExpectedError {
        SignersChainForgeFetchError,
        SignersChainFirstEntryMismatch,
        SignersConfigParse,
        SignaturesParseError,
        SignersChainFirstEntrySignatureInvalid,
    }

    struct Scenario {
        name: &'static str,
        entry: HistoryEntry,
        forge_status: u16,
        forge_body: String,
        expected: Expected,
    }

    fn assert_expected(name: &str, result: AsfaloadLibResult<()>, expected: &Expected) {
        match expected {
            Expected::Ok => {
                assert!(
                    result.is_ok(),
                    "Scenario '{}': expected Ok, got {:?}",
                    name,
                    result.unwrap_err()
                );
            }
            Expected::Err(expected_err) => {
                assert!(result.is_err(), "Scenario '{}': expected Err, got Ok", name);
                let err = result.unwrap_err();
                match expected_err {
                    ExpectedError::SignersChainForgeFetchError => {
                        assert!(
                            matches!(err, ClientLibError::SignersChainForgeFetchError(_)),
                            "Scenario '{}': expected SignersChainForgeFetchError, got {:?}",
                            name,
                            err
                        );
                    }
                    ExpectedError::SignersChainFirstEntryMismatch => {
                        assert!(
                            matches!(err, ClientLibError::SignersChainFirstEntryMismatch),
                            "Scenario '{}': expected SignersChainFirstEntryMismatch, got {:?}",
                            name,
                            err
                        );
                    }
                    ExpectedError::SignersConfigParse => {
                        assert!(
                            matches!(err, ClientLibError::SignersConfigParse(_)),
                            "Scenario '{}': expected SignersConfigParse, got {:?}",
                            name,
                            err
                        );
                    }
                    ExpectedError::SignaturesParseError => {
                        assert!(
                            matches!(err, ClientLibError::SignaturesParseError(_)),
                            "Scenario '{}': expected SignaturesParseError, got {:?}",
                            name,
                            err
                        );
                    }
                    ExpectedError::SignersChainFirstEntrySignatureInvalid => {
                        assert!(
                            matches!(err, ClientLibError::SignersChainFirstEntrySignatureInvalid),
                            "Scenario '{}': expected SignersChainFirstEntrySignatureInvalid, got {:?}",
                            name,
                            err
                        );
                    }
                }
            }
        }
    }

    fn scenarios(forge_url: &str) -> Vec<Scenario> {
        let keys_1 = TestKeys::new(1);
        let keys_2 = TestKeys::new(2);
        let keys_3 = TestKeys::new(3);
        // keys_5: used for full config with admin + master + revocation keys
        let keys_5 = TestKeys::new(5);
        let timestamp = "2024-01-01T00:00:00Z".parse().unwrap();

        // -- Config with 1 signer (key 0), threshold 1 --
        let config_1 = SignersConfig::with_artifact_signers_only(
            1,
            (vec![keys_1.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        // -- Config with 2 signers (keys 0,1), threshold 2 --
        let config_2 = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    keys_2.pub_key(0).unwrap().clone(),
                    keys_2.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )
        .unwrap();

        // -- Valid entries --
        let valid_entry_1 =
            make_history_entry(&config_1, &keys_1, &[0], forge_url, timestamp).unwrap();

        let valid_entry_2 =
            make_history_entry(&config_2, &keys_2, &[0, 1], forge_url, timestamp).unwrap();

        // -- Entry with invalid signers_file JSON --
        let invalid_json_entry = HistoryEntry {
            obsoleted_at: timestamp,
            signers_file: "not valid json".to_string(),
            signatures: SignaturesFile::new(),
            metadata: SignersConfigMetadata::from_forge(ForgeOrigin::new(
                Forge::Github,
                forge_url.to_string(),
                chrono::Utc::now(),
            )),
        };

        // -- Entry with bad base64 in signature --
        let mut bad_sig_entry = valid_entry_1.clone();
        bad_sig_entry.signatures = SignaturesFile::new();
        bad_sig_entry.signatures.entries.insert(
            keys_1.pub_key(0).unwrap().to_base64(),
            TaggedSignature {
                format: keys_1.pub_key(0).unwrap().key_format(),
                signature: "!!!not-base64!!!".to_string(),
            },
        );

        // -- Entry signed by only 1 of 2 required signers --
        let partial_sig_entry =
            make_history_entry(&config_2, &keys_2, &[0], forge_url, timestamp).unwrap();

        // -- Entry with empty signatures --
        let mut no_sig_entry = valid_entry_1.clone();
        no_sig_entry.signatures = SignaturesFile::new();

        // -- Entry signed by wrong key --
        // config_2 expects keys 0,1 from keys_2, but we sign with key 2 from keys_3
        // which is not in config_2's signer list. This tests that check_all_signers
        // rejects signatures from keys not listed in the config.
        let wrong_key_entry =
            make_history_entry(&config_2, &keys_3, &[2], forge_url, timestamp).unwrap();

        // -- Entry for whitespace diff test (compact JSON) --
        let compact_json = serde_json::to_string(&config_1).unwrap();
        let compact_hash =
            features_lib::sha512_for_content(compact_json.as_bytes().to_vec()).unwrap();
        let mut compact_sig = SignaturesFile::new();
        let sig = keys_1.sec_key(0).unwrap().sign(&compact_hash).unwrap();
        compact_sig.entries.insert(
            keys_1.pub_key(0).unwrap().to_base64(),
            TaggedSignature {
                format: keys_1.pub_key(0).unwrap().key_format(),
                signature: sig.to_base64(),
            },
        );
        let compact_entry = HistoryEntry {
            obsoleted_at: timestamp,
            signers_file: compact_json,
            signatures: compact_sig,
            metadata: SignersConfigMetadata::from_forge(ForgeOrigin::new(
                Forge::Github,
                forge_url.to_string(),
                chrono::Utc::now(),
            )),
        };

        // -- Entry with empty signers_file --
        let empty_entry = HistoryEntry {
            obsoleted_at: timestamp,
            signers_file: String::new(),
            signatures: SignaturesFile::new(),
            metadata: SignersConfigMetadata::from_forge(ForgeOrigin::new(
                Forge::Github,
                forge_url.to_string(),
                chrono::Utc::now(),
            )),
        };

        // -- Full config: artifact_signers(key0, thresh=1) + admin(key1, thresh=1)
        //    + master(key2, thresh=1) + revocation(key3, thresh=1)
        //    key4 is an extra key used for the "missing admin sig" scenario.
        let config_full = SignersConfig::with_keys(
            1,
            (vec![keys_5.pub_key(0).unwrap().clone()], 1), // artifact
            Some((vec![keys_5.pub_key(1).unwrap().clone()], 1)), // admin
            Some((vec![keys_5.pub_key(2).unwrap().clone()], 1)), // master
            Some((vec![keys_5.pub_key(3).unwrap().clone()], 1)), // revocation
        )
        .unwrap();

        // Valid full config entry: signed by all keys that all_signer_keys() returns.
        // NOTE: all_signer_keys() currently does NOT include revocation_keys — this is
        // a known bug (tracked separately). When fixed, this scenario must be updated
        // to also sign with key 3 (revocation key).
        let valid_full_entry =
            make_history_entry(&config_full, &keys_5, &[0, 1, 2], forge_url, timestamp).unwrap();

        // Missing admin key signature: signed by artifact(0) + master(2) but NOT admin(1).
        // NOTE: When the revocation_keys bug is fixed, signer_indices should include key 3.
        let missing_admin_entry =
            make_history_entry(&config_full, &keys_5, &[0, 2], forge_url, timestamp).unwrap();

        vec![
            // 1. Valid single signer
            Scenario {
                name: "valid_single_signer",
                forge_body: valid_entry_1.signers_file.clone(),
                forge_status: 200,
                entry: valid_entry_1.clone(),
                expected: Expected::Ok,
            },
            // 2. Valid multiple signers
            Scenario {
                name: "valid_multiple_signers",
                forge_body: valid_entry_2.signers_file.clone(),
                forge_status: 200,
                entry: valid_entry_2,
                expected: Expected::Ok,
            },
            // 3. Forge returns 500
            Scenario {
                name: "forge_returns_500",
                forge_body: String::new(),
                forge_status: 500,
                entry: valid_entry_1.clone(),
                expected: Expected::Err(ExpectedError::SignersChainForgeFetchError),
            },
            // 4. Forge returns 404
            Scenario {
                name: "forge_returns_404",
                forge_body: String::new(),
                forge_status: 404,
                entry: valid_entry_1.clone(),
                expected: Expected::Err(ExpectedError::SignersChainForgeFetchError),
            },
            // 5. Forge content mismatch
            Scenario {
                name: "forge_content_mismatch",
                forge_body: r#"{"completely": "different content"}"#.to_string(),
                forge_status: 200,
                entry: valid_entry_1.clone(),
                expected: Expected::Err(ExpectedError::SignersChainFirstEntryMismatch),
            },
            // 6. Invalid signers config JSON
            Scenario {
                name: "invalid_signers_config_json",
                forge_body: "not valid json".to_string(),
                forge_status: 200,
                entry: invalid_json_entry,
                expected: Expected::Err(ExpectedError::SignersConfigParse),
            },
            // 7. Invalid signature base64
            Scenario {
                name: "invalid_signature_base64",
                forge_body: bad_sig_entry.signers_file.clone(),
                forge_status: 200,
                entry: bad_sig_entry,
                expected: Expected::Err(ExpectedError::SignaturesParseError),
            },
            // 8. Missing one signer signature (2 required, only 1 signed)
            Scenario {
                name: "missing_one_signer_signature",
                forge_body: partial_sig_entry.signers_file.clone(),
                forge_status: 200,
                entry: partial_sig_entry,
                expected: Expected::Err(ExpectedError::SignersChainFirstEntrySignatureInvalid),
            },
            // 9. No signatures at all
            Scenario {
                name: "no_signatures_at_all",
                forge_body: no_sig_entry.signers_file.clone(),
                forge_status: 200,
                entry: no_sig_entry,
                expected: Expected::Err(ExpectedError::SignersChainFirstEntrySignatureInvalid),
            },
            // 10. Signature from wrong key
            Scenario {
                name: "signature_from_wrong_key",
                forge_body: wrong_key_entry.signers_file.clone(),
                forge_status: 200,
                entry: wrong_key_entry,
                expected: Expected::Err(ExpectedError::SignersChainFirstEntrySignatureInvalid),
            },
            // 11. Forge content whitespace diff (compact vs pretty-printed)
            Scenario {
                name: "forge_content_whitespace_diff",
                forge_body: serde_json::to_string_pretty(&config_1).unwrap(),
                forge_status: 200,
                entry: compact_entry,
                expected: Expected::Err(ExpectedError::SignersChainFirstEntryMismatch),
            },
            // 12. Empty signers file
            Scenario {
                name: "empty_signers_file",
                forge_body: String::new(),
                forge_status: 200,
                entry: empty_entry,
                expected: Expected::Err(ExpectedError::SignersConfigParse),
            },
            // 13. Valid with admin + master + revocation keys (all required signers signed)
            // NOTE: When revocation_keys bug in all_signer_keys() is fixed,
            // this test should still pass (entry is signed by all keys including revocation).
            // Update valid_full_entry construction to also sign with key 3.
            Scenario {
                name: "valid_with_full_key_config",
                forge_body: valid_full_entry.signers_file.clone(),
                forge_status: 200,
                entry: valid_full_entry,
                expected: Expected::Ok,
            },
            // 14. Missing admin key signature in full config
            // NOTE: When revocation_keys bug is fixed, this will still fail
            // (admin key is still missing), but update missing_admin_entry
            // construction to also sign with key 3.
            Scenario {
                name: "missing_admin_key_signature",
                forge_body: missing_admin_entry.signers_file.clone(),
                forge_status: 200,
                entry: missing_admin_entry,
                expected: Expected::Err(ExpectedError::SignersChainFirstEntrySignatureInvalid),
            },
        ]
    }

    #[tokio::test]
    async fn validate_first_entry_scenarios() {
        let mut server = mockito::Server::new_async().await;
        let forge_url = format!("{}/forge/signers", server.url());
        let client = reqwest::Client::new();

        for scenario in scenarios(&forge_url) {
            // Reset mocks between scenarios
            server.reset();

            let _mock = server
                .mock("GET", "/forge/signers")
                .with_status(scenario.forge_status as usize)
                .with_header("content-type", "text/plain")
                .with_body(&scenario.forge_body)
                .create_async()
                .await;

            let result = validate_first_entry(&client, &scenario.entry).await;
            assert_expected(scenario.name, result, &scenario.expected);
        }
    }
}
