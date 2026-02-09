use crate::backend::{download_file, download_file_to_temp};
use crate::types::DownloadCallbacks;
use crate::verification::{get_file_hash_info, verify_file_hash, verify_signatures};
use crate::{AsfaloadLibResult, ClientLibError, DownloadResult};
use features_lib::{
    AsfaloadIndex,
    constants::{INDEX_FILE, SIGNATURES_SUFFIX},
    parse_signers_config, sha512_for_content,
};
use reqwest::{Client, Url};
use std::path::PathBuf;

use super::{ForgeTrait, get_forge};

/// Handle the download command
pub async fn download_file_with_verification(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
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

    let forge = get_forge(&url)?;
    let index_file_path = forge.construct_index_file_path(&url)?;

    let signers_url = format!("{}/v1/get-signers/{}", backend_url, index_file_path);
    let signers_content =
        download_file(&client, &signers_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_signers_downloaded(signers_content.len());
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    let index_url = format!("{}/v1/files/{}", backend_url, index_file_path);
    let index_content = download_file(&client, &index_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_index_downloaded(index_content.len());
    let index: AsfaloadIndex = serde_json::from_slice(&index_content)?;

    let signatures_file_path =
        forge.construct_file_repo_path(&url, &format!("{}.{}", INDEX_FILE, SIGNATURES_SUFFIX))?;
    let signatures_url = format!("{}/v1/files/{}", backend_url, signatures_file_path);
    let signatures_content =
        download_file(&client, &signatures_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_signatures_downloaded(signatures_content.len());

    let file_hash = sha512_for_content(index_content)?;

    let (valid_count, invalid_count) =
        verify_signatures(signatures_content, &signers_config, &file_hash)?;

    callbacks.emit_signatures_verified(valid_count, invalid_count);

    // Get expected hash from index (validates algorithm is supported)
    let expected_hash = get_file_hash_info(&index, filename)?;

    callbacks.emit_file_download_started(filename, None);

    // Download file to temp location with incremental hash computation
    let (temp_file, bytes_downloaded, computed_hash) =
        download_file_to_temp(&client, file_url, &expected_hash.algorithm(), callbacks).await?;

    callbacks.emit_file_download_completed(bytes_downloaded);

    // Verify hash (algorithm + value)
    verify_file_hash(&expected_hash, &computed_hash)?;

    callbacks.emit_file_hash_verified(computed_hash.algorithm());

    // Move temp file to final destination (only happens if hash verification succeeded)
    let output_path = output.cloned().unwrap_or_else(|| PathBuf::from(filename));
    temp_file.persist(&output_path).map_err(|e| {
        ClientLibError::PersistError(format!(
            "Failed to move temp file to {:?}: {}",
            output_path, e
        ))
    })?;

    callbacks.emit_file_saved(&output_path);

    let result = DownloadResult {
        file_path: output_path,
        bytes_downloaded,
        signatures_verified: valid_count,
        signatures_invalid: invalid_count,
        computed_hash,
    };

    callbacks.emit_completed(&result);

    Ok(result)
}
