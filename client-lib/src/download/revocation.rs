use crate::ClientLibError;
use crate::signers_chain::validate_fetched_chain;
use crate::types::DownloadCallbacks;
use crate::verification::collect_valid_signatures;
use features_lib::{
    AsfaloadPublicKeyTrait, RevocationInfo, aggregate_signature_helpers::check_groups, can_revoke,
    sha512_for_content,
};
use reqwest::Client;
use rest_api_types::models::{GetRevocationRequest, GetRevocationResponse};

use super::{Forges, ForgesPathMethods, get_forge};

/// Explicit, trust-anchored revocation check.
///
/// Returns `Ok(())` when the backend reports no revocation (404). On 200,
/// validates the embedded chain (realm + trust anchor), checks `can_revoke`
/// against the chain head, and verifies the revocation signature against the
/// chain-head signers config. The revocation must be fully signed: every
/// `revocation_keys()` group of the chain-head config must meet its threshold.
/// A verified revocation emits the callback and returns a `FileRevoked` error.
/// Any failure of those checks is an error — we never silently treat a bad
/// revocation payload as "not revoked".
pub(crate) async fn check_revocation(
    client: &Client,
    backend_url: &str,
    req: GetRevocationRequest,
    callbacks: &DownloadCallbacks,
) -> Result<(), ClientLibError> {
    let url = format!("{}/v1/get_revocation", backend_url);
    let response = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| ClientLibError::RevocationFetchError(e.to_string()))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "(failed to read response body)".to_string());
        return Err(ClientLibError::RevocationFetchError(format!(
            "{}: {}",
            status, body
        )));
    }
    let resp = response
        .json::<GetRevocationResponse>()
        .await
        .map_err(|e| ClientLibError::RevocationParse(e.to_string()))?;

    // Validate the chain (same realm + trust-anchor checks as the artifact
    // flow). Its head is the trusted signers config for the checks below.
    // The realm path is derived from the request's URL and forge kind, so it
    // always matches the artifact the backend was asked about.
    let forge = match req.forge_kind.as_deref() {
        Some(ft) => Forges::from_type_str(ft)?,
        None => get_forge(&req.artifact_url)?,
    };
    let index_file_path = forge.construct_index_file_path(&req.artifact_url)?;
    let chain_result = validate_fetched_chain(resp.signers_chain, &index_file_path)
        .await
        .map_err(|e| ClientLibError::RevocationChainInvalid(e.to_string()))?;
    let signers_config = chain_result.current_signers_config;

    let revocation = RevocationInfo::from_json(&resp.revocation_json)
        .map_err(|e| ClientLibError::RevocationParse(e.to_string()))?;

    // Authorize the initiator against the chain-head signers config.
    if !can_revoke(&revocation.initiator, &signers_config) {
        return Err(ClientLibError::RevocationUnauthorized);
    }

    // Verify the revocation signatures over the raw revocation JSON bytes.
    let hash = sha512_for_content(resp.revocation_json.into_bytes())?;
    let (valid_signatures, _invalid_count) =
        collect_valid_signatures(resp.revocation_signatures.as_bytes(), &hash)
            .map_err(|e| ClientLibError::RevocationInvalid(e.to_string()))?;

    // The initiator must have produced a valid signature.
    if !valid_signatures.contains_key(&revocation.initiator) {
        return Err(ClientLibError::RevocationInvalid(
            "Initiator's signature not found in revocation signatures".to_string(),
        ));
    }

    // The revocation must be fully signed: every revocation-keys group of
    // the trust-rooted chain-head config must meet its threshold. This is
    // the same completeness rule the backend applies before finalising a
    // revocation (check_groups over revocation_keys), so a backend serving
    // a partially-signed revocation as final is rejected here.
    let revocation_groups = signers_config.revocation_keys();
    if !check_groups(revocation_groups, &valid_signatures, &hash) {
        return Err(ClientLibError::RevocationThresholdNotMet {
            found: valid_signatures.len(),
        });
    }

    let timestamp = revocation.timestamp.to_rfc3339();
    let initiator = revocation.initiator.to_base64();
    callbacks.emit_revocation_detected(&timestamp, &initiator);
    Err(ClientLibError::FileRevoked {
        timestamp,
        initiator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use features_lib::{
        AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, CurrentSignersInfo, KeyFormat,
        SignaturesFile, SignersChain, SignersConfig, TaggedSignature, sha512_for_content,
    };
    use test_helpers::TestKeys;
    use test_helpers::history_helpers::make_history_entry;

    /// Request for an artifact hosted on `backend_url`, in the realm of the
    /// `acme/tool` project. The realm path used for chain validation is
    /// derived from this URL.
    fn test_request(backend_url: &str) -> GetRevocationRequest {
        GetRevocationRequest {
            artifact_url: reqwest::Url::parse(&format!(
                "{}/acme/tool/releases/v1/file.bin",
                backend_url
            ))
            .unwrap(),
            forge_kind: None,
        }
    }

    /// Build a `GetRevocationResponse` whose chain-head config contains
    /// `config_signers` with the given `threshold`, rooted at `anchor_url`
    /// (the forge URL the trust-anchor fetch will hit). The revocation is
    /// initiated by `initiator_index` and signed by `revocation_signers`.
    fn build_revocation_response_with(
        keys: &TestKeys,
        config_signers: &[usize],
        threshold: u32,
        initiator_index: usize,
        revocation_signers: &[usize],
        anchor_url: &str,
    ) -> (GetRevocationResponse, String, String) {
        let config_keys = config_signers
            .iter()
            .map(|i| keys.pub_key(*i).unwrap().clone())
            .collect::<Vec<_>>();
        let config =
            SignersConfig::with_artifact_signers_only(1, (config_keys, threshold)).unwrap();
        let timestamp = chrono::Utc::now();
        let entry =
            make_history_entry(&config, keys, config_signers, anchor_url, timestamp).unwrap();

        let current = CurrentSignersInfo {
            signers_file: entry.signers_file.clone(),
            signatures: entry.signatures.clone(),
            metadata: entry.metadata.clone(),
            metadata_signatures: entry.metadata_signatures.clone(),
        };
        let mut chain = SignersChain::default();
        chain.set_current_info(current);

        let initiator = keys.pub_key(initiator_index).unwrap().clone();
        let revocation_info = RevocationInfo {
            timestamp,
            subject_digest: sha512_for_content(b"revoked artifact content".to_vec()).unwrap(),
            initiator: initiator.clone(),
        };
        let revocation_json = serde_json::to_string(&revocation_info).unwrap();

        let revocation_hash = sha512_for_content(revocation_json.as_bytes().to_vec()).unwrap();
        let mut signatures_file = SignaturesFile::new();
        for i in revocation_signers {
            let signature = keys.sec_key(*i).unwrap().sign(&revocation_hash).unwrap();
            signatures_file.entries.insert(
                keys.pub_key(*i).unwrap().to_base64(),
                TaggedSignature {
                    format: KeyFormat::Asfaload,
                    signature: signature.to_base64(),
                },
            );
        }

        (
            GetRevocationResponse {
                revocation_json,
                revocation_signatures: serde_json::to_string(&signatures_file).unwrap(),
                signers_chain: chain,
            },
            initiator.to_base64(),
            timestamp.to_rfc3339(),
        )
    }

    /// Build a valid `GetRevocationResponse` whose chain is rooted at
    /// `anchor_url` (the forge URL the trust-anchor fetch will hit), signed
    /// by the given key index.
    fn build_revocation_response(
        keys: &TestKeys,
        signer_index: usize,
        anchor_url: &str,
    ) -> (GetRevocationResponse, String, String) {
        build_revocation_response_with(
            keys,
            &[signer_index],
            1,
            signer_index,
            &[signer_index],
            anchor_url,
        )
    }

    #[tokio::test]
    async fn check_revocation_returns_ok_on_404() {
        let mut backend = mockito::Server::new_async().await;
        let _m = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(404)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn check_revocation_errors_on_backend_failure() {
        let mut backend = mockito::Server::new_async().await;
        let _m = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(500)
            .with_body("server error")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationFetchError(_)) => {}
            other => panic!("expected RevocationFetchError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_errors_on_malformed_revocation_json() {
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let (mut payload, _, _) = build_revocation_response(&keys, 0, &anchor_url);
        payload.revocation_json = "not json at all".to_string();

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(
                payload
                    .signers_chain
                    .current_signers_info()
                    .unwrap()
                    .signers_file
                    .clone(),
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationParse(_)) => {}
            other => panic!("expected RevocationParse, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_returns_file_revoked_on_valid_payload() {
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let (payload, initiator, timestamp) = build_revocation_response(&keys, 0, &anchor_url);

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(
                payload
                    .signers_chain
                    .current_signers_info()
                    .unwrap()
                    .signers_file
                    .clone(),
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::FileRevoked {
                timestamp: t,
                initiator: i,
            }) => {
                assert_eq!(t, timestamp);
                assert_eq!(i, initiator);
            }
            other => panic!("expected FileRevoked, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_rejects_chain_outside_realm() {
        // Anchor URL points to a DIFFERENT project on the same host. The realm
        // check must reject before reaching can_revoke / signature verification.
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let anchor_url = format!(
            "{}/attacker/evil/asfaload.signers/signers.json",
            backend.url()
        );
        let (payload, _, _) = build_revocation_response(&keys, 0, &anchor_url);

        let _m = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationChainInvalid(_)) => {}
            other => panic!("expected RevocationChainInvalid, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_rejects_when_trust_anchor_content_mismatches() {
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let (payload, _, _) = build_revocation_response(&keys, 0, &anchor_url);

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        // Anchor host serves DIFFERENT content than the chain's signers_file.
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body("completely different content")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationChainInvalid(_)) => {}
            other => panic!("expected RevocationChainInvalid, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_rejects_when_initiator_not_in_chain_head_signers() {
        // Two-key setup: chain head has key 0, but the revocation is signed
        // and initiated by key 1 (not in the chain). `can_revoke` must reject.
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(2);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());

        // Build the chain with key 0; then replace the revocation payload's
        // initiator + signature with key 1's.
        let (mut payload, _, _) = build_revocation_response(&keys, 0, &anchor_url);
        let key1 = keys.pub_key(1).unwrap().clone();
        let revocation_info = RevocationInfo {
            timestamp: chrono::Utc::now(),
            subject_digest: sha512_for_content(b"revoked artifact content".to_vec()).unwrap(),
            initiator: key1.clone(),
        };
        payload.revocation_json = serde_json::to_string(&revocation_info).unwrap();
        let hash = sha512_for_content(payload.revocation_json.as_bytes().to_vec()).unwrap();
        let signature = keys.sec_key(1).unwrap().sign(&hash).unwrap();
        let mut signatures_file = SignaturesFile::new();
        signatures_file.entries.insert(
            key1.to_base64(),
            TaggedSignature {
                format: KeyFormat::Asfaload,
                signature: signature.to_base64(),
            },
        );
        payload.revocation_signatures = serde_json::to_string(&signatures_file).unwrap();

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(
                payload
                    .signers_chain
                    .current_signers_info()
                    .unwrap()
                    .signers_file
                    .clone(),
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationUnauthorized) => {}
            other => panic!("expected RevocationUnauthorized, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_rejects_when_threshold_not_met() {
        // Chain-head config requires 2 signatures from {key0, key1} to
        // revoke, but the payload carries only the initiator's signature.
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(2);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let (payload, _, _) =
            build_revocation_response_with(&keys, &[0, 1], 2, 0, &[0], &anchor_url);

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(
                payload
                    .signers_chain
                    .current_signers_info()
                    .unwrap()
                    .signers_file
                    .clone(),
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationThresholdNotMet { .. }) => {}
            other => panic!("expected RevocationThresholdNotMet, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_returns_file_revoked_when_threshold_met_by_multiple_signers() {
        // Same 2-of-2 config, but both keys signed: the revocation is fully
        // signed and must be reported as FileRevoked.
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(2);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let (payload, initiator, timestamp) =
            build_revocation_response_with(&keys, &[0, 1], 2, 0, &[0, 1], &anchor_url);

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(
                payload
                    .signers_chain
                    .current_signers_info()
                    .unwrap()
                    .signers_file
                    .clone(),
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::FileRevoked {
                timestamp: t,
                initiator: i,
            }) => {
                assert_eq!(t, timestamp);
                assert_eq!(i, initiator);
            }
            other => panic!("expected FileRevoked, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_revocation_rejects_when_signature_does_not_verify() {
        let mut backend = mockito::Server::new_async().await;
        let keys = TestKeys::new(1);
        let anchor_url = format!("{}/acme/tool/asfaload.signers/signers.json", backend.url());
        let (mut payload, _, _) = build_revocation_response(&keys, 0, &anchor_url);

        // Tamper with the revocation_json AFTER the signature was computed:
        // trailing whitespace keeps it parseable but changes the signed bytes,
        // so the signature no longer verifies.
        payload.revocation_json.push(' ');

        let _revocation_mock = backend
            .mock("POST", "/v1/get_revocation")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&payload).unwrap())
            .create_async()
            .await;
        let _anchor_mock = backend
            .mock("GET", "/acme/tool/asfaload.signers/signers.json")
            .with_status(200)
            .with_body(
                payload
                    .signers_chain
                    .current_signers_info()
                    .unwrap()
                    .signers_file
                    .clone(),
            )
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = check_revocation(
            &client,
            &backend.url(),
            test_request(&backend.url()),
            &DownloadCallbacks::default(),
        )
        .await;
        match result {
            Err(ClientLibError::RevocationInvalid(_)) => {}
            other => panic!("expected RevocationInvalid, got: {:?}", other),
        }
    }
}
