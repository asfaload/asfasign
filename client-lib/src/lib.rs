mod backend;
mod error;
mod types;
mod verification;
pub use error::{ClientLibError, Result};
pub use types::{DownloadEvent, DownloadResult};

use std::path::PathBuf;

use features_lib::constants::{INDEX_FILE, SIGNATURES_SUFFIX};
use features_lib::{
    AsfaloadIndex,
    parse_signers_config, sha512_for_content,
};

use backend::download_file;
use verification::{verify_file_hash, verify_signatures};

/// Handle the download command
pub async fn download_file_with_verification<F>(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
    mut on_event: F,
) -> Result<DownloadResult>
where
    F: FnMut(DownloadEvent) + Send,
{
    on_event(DownloadEvent::Starting {
        file_url: file_url.to_string(),
    });

    // Parse the URL to extract components
    let url = reqwest::Url::parse(file_url)
        .map_err(|e| ClientLibError::InvalidUrl(e.to_string()))?;

    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or_else(|| ClientLibError::InvalidUrl("Could not extract filename from URL".to_string()))?;

    // Construct the index file path for the get-signers endpoint
    // This is the path relative to the git repo root
    let index_file_path = construct_index_file_path(&url)?;

    //  Download signers file using the get-signers endpoint.
    //  The backend will look for the signers file that applies
    let signers_url = format!("{}/get-signers/{}", backend_url, index_file_path);
    let signers_content = download_file(&signers_url).await?;
    on_event(DownloadEvent::SignersDownloaded { bytes: signers_content.len() });
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    // Download asfaload.index.json using /files/ endpoint as we have the exact location
    // on the backend
    let index_file_path = construct_file_repo_path(&url, INDEX_FILE)?;
    let index_url = format!("{}/files/{}", backend_url, index_file_path);
    let index_content = download_file(&index_url).await?;
    on_event(DownloadEvent::IndexDownloaded { bytes: index_content.len() });
    let index: AsfaloadIndex = serde_json::from_slice(&index_content)?;

    // For signatures of the index we also can derive the location from the index location
    let signatures_file_path =
        construct_file_repo_path(&url, &format!("{}.{}", INDEX_FILE, SIGNATURES_SUFFIX))?;
    let signatures_url = format!("{}/files/{}", backend_url, signatures_file_path);
    let signatures_content = download_file(&signatures_url).await?;
    on_event(DownloadEvent::SignaturesDownloaded { bytes: signatures_content.len() });

    // Verify signatures of the index file
    let file_hash = sha512_for_content(index_content)?;

    let (valid_count, invalid_count) =
        verify_signatures(signatures_content, &signers_config, &file_hash)?;

    on_event(DownloadEvent::SignaturesVerified { valid_count, invalid_count });

    // Download actual file
    on_event(DownloadEvent::FileDownloadStarted {
        filename: filename.to_string(),
        total_bytes: None,
    });
    let file_content = download_file(file_url).await?;

    let bytes_downloaded = file_content.len() as u64;
    on_event(DownloadEvent::FileDownloadCompleted { bytes_downloaded });

    // Verify file hash
    let hash_algorithm = verify_file_hash(&index, filename, file_content.as_slice())?;

    on_event(DownloadEvent::FileHashVerified {
        algorithm: hash_algorithm.clone(),
    });

    // Save file
    let output_path = output.cloned().unwrap_or_else(|| PathBuf::from(filename));
    tokio::fs::write(&output_path, file_content).await?;

    on_event(DownloadEvent::FileSaved { path: output_path.clone() });

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

/// Construct the index file path for the get-signers endpoint
/// This returns the path to the index file relative to the git repo root
fn construct_index_file_path(file_url: &reqwest::Url) -> Result<String> {
    construct_file_repo_path(file_url, INDEX_FILE)
}

/// Construct a file path for the /files/ endpoint
/// This returns the path to a file relative to the git repo root
fn construct_file_repo_path(file_url: &reqwest::Url, filename: &str) -> Result<String> {
    // Extract host and path from file URL
    let host = file_url
        .host_str()
        .ok_or_else(|| ClientLibError::InvalidUrl("URL has no host".to_string()))?;
    let path = file_url.path();

    // Remove leading slash from path if present
    let path = path.strip_prefix('/').unwrap_or(path);

    // Remove the original filename from path to get directory
    let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

    // Translate GitHub release path: download -> tag
    let translated_path = translate_download_to_release_path(host, dir_path);

    Ok(format!("{}/{}/{}", host, translated_path, filename))
}

enum Forges {
    Github,
}
 impl Forges {
    pub fn from_host(host: &str) -> Result<Self> {
        if host.contains("github.com") {
            Ok(Self::Github)
        } else {
            Err(ClientLibError::UnsupportedForge(host.to_string()))
        }
    }
}
/// When we download a file from a release, we use the download URL,
/// which may be a variation of the release URL that was registered.
/// Eg On github, the download url has the segments "/releases/download"
/// while the release url has the segments "/releases/tag".
/// This function translates the paths from the download url that
/// we have, to the path of the release that was registered
fn translate_download_to_release_path(host: &str, path: &str) -> String {
    let forge =
        Forges::from_host(host).unwrap_or_else(|_| panic!("Host not supported as forge: {}", host));
    match forge {
        Forges::Github => translate_github_release_path(path),
    }
}
/// Translate GitHub release paths from /download/ to /tag/
/// GitHub uses /releases/download/ for actual files but /releases/tag/ for metadata
fn translate_github_release_path(path: &str) -> String {
    // Replace /releases/download/ with /releases/tag/
    path.replace("/releases/download/", "/releases/tag/")
}
