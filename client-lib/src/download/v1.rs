use crate::artifact_info::get_artifact_info;
use crate::backend::download_file_to_temp;
use crate::download::revocation::check_revocation;
use crate::signers_chain::validate_fetched_chain;
use crate::types::DownloadCallbacks;
use crate::verification::{get_file_hash_info, verify_file_hash, verify_signatures};
use crate::{AsfaloadLibResult, ClientLibError, DownloadResult};
use features_lib::{AsfaloadIndex, sha512_for_content};
use reqwest::{Client, Url};
use rest_api_types::models::GetArtifactInfoRequest;
use std::path::PathBuf;

use super::{Forges, ForgesPathMethods, get_forge};

struct DownloadedData {
    temp_file: tempfile::NamedTempFile,
    bytes_downloaded: u64,
    computed_hash: crate::types::ComputedHash,
}

struct FinalizeContext<'a> {
    expected_hash: &'a crate::types::ComputedHash,
    output: Option<&'a PathBuf>,
    filename: &'a str,
    valid_count: usize,
    invalid_count: usize,
    callbacks: &'a DownloadCallbacks,
}

/// Complete the download: verify hash, persist temp file, emit callbacks.
fn finalize_download(
    data: DownloadedData,
    context: &FinalizeContext,
) -> AsfaloadLibResult<DownloadResult> {
    context
        .callbacks
        .emit_file_download_completed(data.bytes_downloaded);

    verify_file_hash(context.expected_hash, &data.computed_hash)?;
    context
        .callbacks
        .emit_file_hash_verified(data.computed_hash.algorithm());

    let output_path = context
        .output
        .cloned()
        .unwrap_or_else(|| PathBuf::from(context.filename));
    data.temp_file.persist(&output_path).map_err(|e| {
        ClientLibError::PersistError(format!(
            "Failed to move temp file to {:?}: {}",
            output_path, e
        ))
    })?;

    context.callbacks.emit_file_saved(&output_path);

    let result = DownloadResult {
        file_path: output_path,
        bytes_downloaded: data.bytes_downloaded,
        signatures_verified: context.valid_count,
        signatures_invalid: context.invalid_count,
        computed_hash: data.computed_hash,
    };

    context.callbacks.emit_completed(&result);
    Ok(result)
}

/// Handle the download command
pub async fn download_file_with_verification(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
    forge_type: Option<&str>,
    callbacks: &DownloadCallbacks,
) -> AsfaloadLibResult<DownloadResult> {
    callbacks.emit_starting(file_url);

    let client = Client::new();

    let url = Url::parse(file_url).map_err(|e| ClientLibError::InvalidUrl(e.to_string()))?;

    let get_artifact_info_request = GetArtifactInfoRequest {
        artifact_url: url.clone(),
        forge_kind: forge_type.map(String::from),
    };
    let response = get_artifact_info(&client, backend_url, get_artifact_info_request).await?;

    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or_else(|| {
            ClientLibError::InvalidUrl("Could not extract filename from URL".to_string())
        })?;

    let forge = match forge_type {
        Some(ft) => Forges::from_type_str(ft)?,
        None => get_forge(&url)?,
    };
    let index_file_path = forge.construct_index_file_path(&url)?;

    let index: AsfaloadIndex = serde_json::from_str(&response.index_json)?;
    let index_content = response.index_json.into_bytes();
    callbacks.emit_index_downloaded(index_content.len());

    let signatures_content = serde_json::to_vec(&response.index_signatures)?;
    callbacks.emit_signatures_downloaded(signatures_content.len());

    // Revocation is probed explicitly below via `check_revocation`, run
    // alongside the chain validation and binary download. Two known
    // limitations remain: the revocation signers file it fetches is not
    // trust-rooted against the validated chain-head config, and revocation is
    // not yet bundled into the get_artifact_info response.

    let file_hash = sha512_for_content(index_content)?;

    // Get expected hash from index (validates algorithm is supported)
    let expected_hash = get_file_hash_info(&index, filename)?;

    callbacks.emit_file_download_started(filename, None);

    // Validate the signers chain from the response, probe for revocation, and
    // download the artifact binary in parallel. Signatures are verified against
    // the chain-head config.
    let algorithm = expected_hash.algorithm();
    let download_future = download_file_to_temp(&client, file_url, &algorithm, callbacks);
    let chain_future = validate_fetched_chain(response.signers_chain, &index_file_path);
    // `check_revocation` is shaped as an error-path fallback: it returns the
    // error passed to it when nothing is revoked, and `FileRevoked` when it is.
    // We hand it a placeholder error and act only on `FileRevoked` below.
    let revocation_future = check_revocation(
        &client,
        &url,
        &forge,
        backend_url,
        callbacks,
        ClientLibError::GenericError("not revoked".into()),
    );

    let (download_result, chain_result, revocation_outcome) =
        tokio::join!(download_future, chain_future, revocation_future);

    // A revoked artifact must fail the download regardless of chain or
    // signature state.
    if let ClientLibError::FileRevoked { .. } = revocation_outcome {
        return Err(revocation_outcome);
    }

    let signers_config = match chain_result {
        Ok(chain) => {
            callbacks.emit_signers_chain_verified(chain.entries_count);
            chain.current_signers_config
        }
        Err(e) => {
            callbacks.emit_signers_chain_failed(&e.to_string());
            return Err(e);
        }
    };

    let (valid_count, invalid_count) =
        verify_signatures(signatures_content, &signers_config, &file_hash)?;
    callbacks.emit_signatures_verified(valid_count, invalid_count);

    let (temp_file, bytes_downloaded, computed_hash) = download_result?;

    let context = FinalizeContext {
        expected_hash: &expected_hash,
        output,
        filename,
        valid_count,
        invalid_count,
        callbacks,
    };

    finalize_download(
        DownloadedData {
            temp_file,
            bytes_downloaded,
            computed_hash,
        },
        &context,
    )
}
