use crate::backend::{download_file, download_file_to_temp};
use crate::types::DownloadCallbacks;
use crate::verification::{get_file_hash_info, verify_file_hash, verify_signatures};
use crate::{AsfaloadLibResult, ClientLibError, DownloadResult};
use features_lib::{
    AsfaloadIndex,
    constants::{INDEX_FILE, SIGNATURES_SUFFIX},
    parse_signers_config, sha512_for_content,
};
use reqwest::Url;
use std::path::PathBuf;

/// Handle the download command
pub async fn download_file_with_verification(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
    callbacks: &DownloadCallbacks,
) -> AsfaloadLibResult<DownloadResult> {
    callbacks.emit_starting(file_url);

    let url = Url::parse(file_url).map_err(|e| ClientLibError::InvalidUrl(e.to_string()))?;

    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or_else(|| {
            ClientLibError::InvalidUrl("Could not extract filename from URL".to_string())
        })?;

    let index_file_path = construct_index_file_path(&url)?;

    let signers_url = format!("{}/get-signers/{}", backend_url, index_file_path);
    let signers_content = download_file(&signers_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_signers_downloaded(signers_content.len());
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    let index_url = format!("{}/files/{}", backend_url, index_file_path);
    let index_content = download_file(&index_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_index_downloaded(index_content.len());
    let index: AsfaloadIndex = serde_json::from_slice(&index_content)?;

    let signatures_file_path =
        construct_file_repo_path(&url, &format!("{}.{}", INDEX_FILE, SIGNATURES_SUFFIX))?;
    let signatures_url = format!("{}/files/{}", backend_url, signatures_file_path);
    let signatures_content = download_file(&signatures_url, &DownloadCallbacks::default()).await?;
    callbacks.emit_signatures_downloaded(signatures_content.len());

    let file_hash = sha512_for_content(index_content)?;

    let (valid_count, invalid_count) =
        verify_signatures(signatures_content, &signers_config, &file_hash)?;

    callbacks.emit_signatures_verified(valid_count, invalid_count);

    // Get hash algorithm before downloading so we can compute hash incrementally
    let (hash_algorithm, _expected_hash) = get_file_hash_info(&index, filename)?;

    callbacks.emit_file_download_started(filename, None);

    // Download file to temp location
    let callbacks_for_download = callbacks;
    let (temp_file, bytes_downloaded, computed_hash) =
        download_file_to_temp(file_url, &hash_algorithm, callbacks_for_download).await?;

    callbacks.emit_file_download_completed(bytes_downloaded);

    // Verify hash
    verify_file_hash(&index, filename, &computed_hash)?;

    callbacks.emit_file_hash_verified(hash_algorithm.clone());

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
        hash_algorithm,
    };

    callbacks.emit_completed(&result);

    Ok(result)
}

fn construct_index_file_path(file_url: &Url) -> AsfaloadLibResult<String> {
    construct_file_repo_path(file_url, INDEX_FILE)
}

fn construct_file_repo_path(file_url: &Url, filename: &str) -> AsfaloadLibResult<String> {
    let host = file_url
        .host_str()
        .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
    let path = file_url.path();

    let path = path.strip_prefix('/').unwrap_or(path);

    let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

    let translated_path = translate_download_to_release_path(host, dir_path)?;

    Ok(format!("{}/{}/{}", host, translated_path, filename))
}

enum Forges {
    Github,
}

impl Forges {
    pub fn from_host(host: &str) -> AsfaloadLibResult<Self> {
        if host.contains("github.com") {
            Ok(Self::Github)
        } else {
            Err(ClientLibError::UnsupportedForge(host.to_string()))
        }
    }
}

fn translate_download_to_release_path(host: &str, path: &str) -> AsfaloadLibResult<String> {
    let forge = Forges::from_host(host)?;
    match forge {
        Forges::Github => Ok(translate_github_release_path(path)),
    }
}

fn translate_github_release_path(path: &str) -> String {
    path.replace("/releases/download/", "/releases/tag/")
}
