use crate::backend::{download_file, download_file_to_temp};
use crate::signers_chain::verify_signers_chain;
use crate::types::DownloadCallbacks;
use crate::verification::{get_file_hash_info, verify_file_hash, verify_signatures};
use crate::{AsfaloadLibResult, ClientLibError, DownloadResult};
use features_lib::{
    AsfaloadIndex, constants::INDEX_FILE, local_signers_path_for, parse_signers_config,
    sha512_for_content, signatures_path_for,
};
use reqwest::{Client, Url};
use std::path::PathBuf;

use super::{ForgeTrait, Forges, get_forge};

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
    full_check: bool,
    callbacks: &DownloadCallbacks,
) -> AsfaloadLibResult<DownloadResult> {
    callbacks.emit_starting(file_url);

    let client = Client::new();

    let url = Url::parse(file_url).map_err(|e| ClientLibError::InvalidUrl(e.to_string()))?;

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

    let signers_filename = local_signers_path_for(INDEX_FILE)?;
    let signers_file_path =
        forge.construct_file_repo_path(&url, &signers_filename.to_string_lossy())?;
    let signers_url = format!("{}/v1/files/{}", backend_url, signers_file_path);
    let signers_content =
        download_file(&client, &signers_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_signers_downloaded(signers_content.len());
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    let index_url = format!("{}/v1/files/{}", backend_url, index_file_path);
    let index_content = download_file(&client, &index_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_index_downloaded(index_content.len());
    let index: AsfaloadIndex = serde_json::from_slice(&index_content)?;

    let signatures_filename = signatures_path_for(INDEX_FILE)?;
    let signatures_file_path =
        forge.construct_file_repo_path(&url, &signatures_filename.to_string_lossy())?;
    let signatures_url = format!("{}/v1/files/{}", backend_url, signatures_file_path);
    let signatures_content =
        match download_file(&client, &signatures_url, &DownloadCallbacks::default()).await {
            Ok(content) => content,
            Err(e @ ClientLibError::HttpError { status: 404, .. }) => {
                return Err(super::revocation::check_revocation(
                    &client,
                    &url,
                    &forge,
                    backend_url,
                    callbacks,
                    e,
                )
                .await);
            }
            Err(e) => return Err(e),
        };
    callbacks.emit_signatures_downloaded(signatures_content.len());

    let file_hash = sha512_for_content(index_content)?;

    let (valid_count, invalid_count) =
        verify_signatures(signatures_content, &signers_config, &file_hash)?;

    callbacks.emit_signatures_verified(valid_count, invalid_count);

    // Get expected hash from index (validates algorithm is supported)
    let expected_hash = get_file_hash_info(&index, filename)?;

    callbacks.emit_file_download_started(filename, None);

    let download_result = if full_check {
        // The signed entity is the index file (not the individual artifact binary).
        // The index_file_path is already computed above and is the correct path for
        // the signers chain endpoint (it has a .signers.json copy in the git repo).

        // Run file download and chain validation in parallel
        let algorithm = expected_hash.algorithm();
        let download_future = download_file_to_temp(&client, file_url, &algorithm, callbacks);
        let chain_future = verify_signers_chain(backend_url, &index_file_path);

        let (download_result, chain_result) = tokio::join!(download_future, chain_future);

        // Check chain validation result and emit callbacks
        match &chain_result {
            Ok(chain) => {
                callbacks.emit_signers_chain_verified(chain.entries_count);
            }
            Err(e) => {
                callbacks.emit_signers_chain_failed(&e.to_string());
            }
        }
        chain_result?;

        download_result
    } else {
        download_file_to_temp(&client, file_url, &expected_hash.algorithm(), callbacks).await
    };

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
