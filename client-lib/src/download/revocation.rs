use crate::ClientLibError;
use crate::backend::download_file;
use crate::types::DownloadCallbacks;
use features_lib::constants::{INDEX_FILE, REVOCATION_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys,
    aggregate_signature_helpers::get_individual_signatures_from_bytes, can_revoke,
    parse_signers_config, sha512_for_content,
};
use reqwest::{Client, Url};
use tokio::try_join;

use super::ForgeTrait;

/// Probe for revocation files and verify the revocation.
///
/// If revocation is verified, returns a `FileRevoked` error with details.
/// If revocation cannot be verified (missing files, bad signature, etc.),
/// returns the original error unchanged.
pub(crate) async fn check_revocation(
    client: &Client,
    url: &Url,
    forge: &impl ForgeTrait,
    backend_url: &str,
    callbacks: &DownloadCallbacks,
    original_error: ClientLibError,
) -> ClientLibError {
    match try_verify_revocation(client, url, forge, backend_url).await {
        Ok((timestamp, initiator)) => {
            callbacks.emit_revocation_detected(&timestamp, &initiator);
            ClientLibError::FileRevoked {
                timestamp,
                initiator,
            }
        }
        Err(_) => original_error,
    }
}

/// Attempt to download and verify revocation files.
///
/// Returns `(timestamp, initiator)` on success, or any error on failure
/// (which will cause fallback to the original error).
async fn try_verify_revocation(
    client: &Client,
    url: &Url,
    forge: &impl ForgeTrait,
    backend_url: &str,
) -> Result<(String, String), ClientLibError> {
    // Construct revocation file names from INDEX_FILE + constants
    let revocation_filename = format!("{}.{}", INDEX_FILE, REVOCATION_SUFFIX);
    let revocation_sig_filename =
        format!("{}.{}.{}", INDEX_FILE, REVOCATION_SUFFIX, SIGNATURES_SUFFIX);
    let revocation_signers_filename =
        format!("{}.{}.{}", INDEX_FILE, REVOCATION_SUFFIX, SIGNERS_SUFFIX);

    // Construct URLs via forge
    let no_callbacks = DownloadCallbacks::default();

    let revocation_path = forge.construct_file_repo_path(url, &revocation_filename)?;
    let revocation_sig_path = forge.construct_file_repo_path(url, &revocation_sig_filename)?;
    let revocation_signers_path =
        forge.construct_file_repo_path(url, &revocation_signers_filename)?;

    let revocation_url = format!("{}/v1/files/{}", backend_url, revocation_path);
    let revocation_sig_url = format!("{}/v1/files/{}", backend_url, revocation_sig_path);
    let revocation_signers_url = format!("{}/v1/files/{}", backend_url, revocation_signers_path);

    // Download all three files
    let (revocation_content, revocation_sig_content, signers_content) = try_join!(
        download_file(client, &revocation_url, &no_callbacks),
        download_file(client, &revocation_sig_url, &no_callbacks),
        download_file(client, &revocation_signers_url, &no_callbacks)
    )?;
    // Parse signers config
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)?;

    // Parse revocation JSON to extract timestamp and initiator
    let revocation_value: serde_json::Value = serde_json::from_slice(&revocation_content)?;
    let timestamp = revocation_value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .ok_or(ClientLibError::RevocationParse(
            "Missing timestamp in revocation file".to_string(),
        ))?
        .to_string();
    let initiator_str = revocation_value
        .get("initiator")
        .and_then(|v| v.as_str())
        .ok_or(ClientLibError::RevocationParse(
            "Missing initiator in revocation file".to_string(),
        ))?
        .to_string();

    // Parse initiator public key
    let initiator_pubkey = AsfaloadPublicKeys::from_base64(&initiator_str)
        .map_err(|e| ClientLibError::GenericError(e.to_string()))?;

    // Check authorization
    if !can_revoke(&initiator_pubkey, &signers_config) {
        return Err(ClientLibError::Unauthorized(
            "Initiator is not authorized to revoke".into(),
        ));
    }

    // Parse revocation signatures
    let signatures = get_individual_signatures_from_bytes(revocation_sig_content)?;

    // Look up initiator's signature
    let signature = signatures
        .get(&initiator_pubkey)
        .ok_or(ClientLibError::RevocationInvalid(
            "Initiator's signature not found in revocation signatures".to_string(),
        ))?;

    // Compute SHA512 hash of revocation content and verify
    let hash = sha512_for_content(revocation_content)?;
    initiator_pubkey
        .verify(signature, &hash)
        .map_err(|e| ClientLibError::RevocationInvalid(e.to_string()))?;

    Ok((timestamp, initiator_str))
}
