use crate::backend::download_file;
use crate::verification::{verify_file_hash, verify_signatures};
use crate::{ClientLibError, DownloadEvent, DownloadResult};
use features_lib::{
    AsfaloadIndex,
    constants::{INDEX_FILE, SIGNATURES_SUFFIX},
    parse_signers_config, sha512_for_content,
};
use reqwest::Url;
use std::path::PathBuf;

/// Handle the download command
pub async fn download_file_with_verification<F>(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
    mut on_event: F,
) -> crate::Result<DownloadResult>
where
    F: FnMut(DownloadEvent) + Send,
{
    on_event(DownloadEvent::Starting {
        file_url: file_url.to_string(),
    });

    let url = Url::parse(file_url).map_err(|e| ClientLibError::InvalidUrl(e.to_string()))?;

    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or_else(|| {
            ClientLibError::InvalidUrl("Could not extract filename from URL".to_string())
        })?;

    let index_file_path = construct_index_file_path(&url)?;

    let signers_url = format!("{}/get-signers/{}", backend_url, index_file_path);
    let signers_content = download_file(&signers_url, |_| {}).await?;
    on_event(DownloadEvent::SignersDownloaded {
        bytes: signers_content.len(),
    });
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    let index_url = format!("{}/files/{}", backend_url, index_file_path);
    let index_content = download_file(&index_url, |_| {}).await?;
    on_event(DownloadEvent::IndexDownloaded {
        bytes: index_content.len(),
    });
    let index: AsfaloadIndex = serde_json::from_slice(&index_content)?;

    let signatures_file_path =
        construct_file_repo_path(&url, &format!("{}.{}", INDEX_FILE, SIGNATURES_SUFFIX))?;
    let signatures_url = format!("{}/files/{}", backend_url, signatures_file_path);
    let signatures_content = download_file(&signatures_url, |_| {}).await?;
    on_event(DownloadEvent::SignaturesDownloaded {
        bytes: signatures_content.len(),
    });

    let file_hash = sha512_for_content(index_content)?;

    let (valid_count, invalid_count) =
        verify_signatures(signatures_content, &signers_config, &file_hash)?;

    on_event(DownloadEvent::SignaturesVerified {
        valid_count,
        invalid_count,
    });

    on_event(DownloadEvent::FileDownloadStarted {
        filename: filename.to_string(),
        total_bytes: None,
    });
    let file_content = download_file(file_url, &mut on_event).await?;

    let bytes_downloaded = file_content.len() as u64;
    on_event(DownloadEvent::FileDownloadCompleted { bytes_downloaded });

    let hash_algorithm = verify_file_hash(&index, filename, file_content.as_slice())?;

    on_event(DownloadEvent::FileHashVerified {
        algorithm: hash_algorithm.clone(),
    });

    let output_path = output.cloned().unwrap_or_else(|| PathBuf::from(filename));
    tokio::fs::write(&output_path, file_content).await?;

    on_event(DownloadEvent::FileSaved {
        path: output_path.clone(),
    });

    let result = DownloadResult {
        file_path: output_path,
        bytes_downloaded,
        signatures_verified: valid_count,
        signatures_invalid: invalid_count,
        hash_algorithm,
    };

    on_event(DownloadEvent::Completed(result.clone()));

    Ok(result)
}

fn construct_index_file_path(file_url: &Url) -> crate::Result<String> {
    construct_file_repo_path(file_url, INDEX_FILE)
}

fn construct_file_repo_path(file_url: &Url, filename: &str) -> crate::Result<String> {
    let host = file_url
        .host_str()
        .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
    let path = file_url.path();

    let path = path.strip_prefix('/').unwrap_or(path);

    let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

    let translated_path = translate_download_to_release_path(host, dir_path);

    Ok(format!("{}/{}/{}", host, translated_path, filename))
}

enum Forges {
    Github,
}

impl Forges {
    pub fn from_host(host: &str) -> crate::Result<Self> {
        if host.contains("github.com") {
            Ok(Self::Github)
        } else {
            Err(ClientLibError::UnsupportedForge(host.to_string()))
        }
    }
}

fn translate_download_to_release_path(host: &str, path: &str) -> String {
    let forge =
        Forges::from_host(host).unwrap_or_else(|_| panic!("Host not supported as forge: {}", host));
    match forge {
        Forges::Github => translate_github_release_path(path),
    }
}

fn translate_github_release_path(path: &str) -> String {
    path.replace("/releases/download/", "/releases/tag/")
}
