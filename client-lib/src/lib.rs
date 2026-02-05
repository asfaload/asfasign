mod error;
mod types;
pub use error::{ClientLibError, Result};
pub use types::{DownloadEvent, DownloadResult};

use std::collections::HashMap;
use std::path::PathBuf;

use features_lib::constants::{INDEX_FILE, SIGNATURES_SUFFIX};
use features_lib::{
    AsfaloadHashes, AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSignatures,
    HashAlgorithm, SignersConfig,
    aggregate_signature_helpers::{check_groups, get_individual_signatures_from_bytes},
    parse_signers_config, sha512_for_content,
};
use reqwest::Client;
use sha2::{Digest, Sha256};

/// Handle the download command
pub async fn download_file_with_verification(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
) -> Result<()> {
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
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| ClientLibError::SignersConfigParse(e.to_string()))?;

    // Download asfaload.index.json using /files/ endpoint as we have the exact location
    // on the backend
    let index_file_path = construct_file_repo_path(&url, INDEX_FILE)?;
    let index_url = format!("{}/files/{}", backend_url, index_file_path);
    let index_content = download_file(&index_url).await?;
    let index: AsfaloadIndex = serde_json::from_slice(&index_content)?;

    // For signatures of the index we also can derive the location from the index location
    let signatures_file_path =
        construct_file_repo_path(&url, &format!("{}.{}", INDEX_FILE, SIGNATURES_SUFFIX))?;
    let signatures_url = format!("{}/files/{}", backend_url, signatures_file_path);
    let signatures_content = download_file(&signatures_url).await?;

    // Verify signatures of the index file
    let file_hash = sha512_for_content(index_content)?;

    verify_signatures(signatures_content, &signers_config, &file_hash)?;

    println!("✓ Signatures verified successfully");

    //  Download actual file
    println!("Downloading {}...", filename);
    let file_content = download_file(file_url).await?;

    // Verify file hash
    verify_file_hash(&index, filename, file_content.as_slice())?;

    // Save file
    let output_path = output.cloned().unwrap_or_else(|| PathBuf::from(filename));
    tokio::fs::write(&output_path, file_content).await?;

    println!("✓ File saved to: {}", output_path.display());

    Ok(())
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

/// Download file content from URL
async fn download_file(url: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(ClientLibError::HttpError {
            status: response.status().as_u16(),
            url: url.to_string(),
        });
    }

    let content = response.bytes().await?;

    Ok(content.to_vec())
}

/// Verify signatures meet threshold requirements
fn verify_signatures(
    signatures_content: Vec<u8>,
    signers_config: &SignersConfig,
    data: &AsfaloadHashes,
) -> Result<()> {
    let artifact_groups = signers_config.artifact_signers();
    if artifact_groups.is_empty() {
        return Err(ClientLibError::MissingArtifactSigners);
    }

    let mut typed_signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> = HashMap::new();

    let parsed_signatures = get_individual_signatures_from_bytes(signatures_content)
        .map_err(|e| ClientLibError::SignaturesParseError(e.to_string()))?;

    for (pubkey, signature) in parsed_signatures {
        let pubkey_b64 = pubkey.to_base64();

        if pubkey.verify(&signature, data).is_err() {
            eprintln!("Warning: Invalid signature from key {}", pubkey_b64);
            continue;
        }

        typed_signatures.insert(pubkey, signature);
    }

    let is_complete = check_groups(artifact_groups, &typed_signatures, data);

    if !is_complete {
        return Err(ClientLibError::SignatureThresholdNotMet {
            required: artifact_groups.len(),
            found: typed_signatures.len(),
        });
    }

    let valid_count = typed_signatures.len();
    println!("✓ Verified {} valid signature(s)", valid_count);

    Ok(())
}

/// Compute SHA-256 hash for content
fn sha256_for_content<T: std::borrow::Borrow<[u8]>>(content_in: T) -> Result<String> {
    let content = content_in.borrow();
    if content.is_empty() {
        Err(ClientLibError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        )))
    } else {
        let result = Sha256::digest(content);
        Ok(hex::encode(result))
    }
}

/// Verify downloaded file hash matches index
fn verify_file_hash<T: std::borrow::Borrow<[u8]>>(
    index: &AsfaloadIndex,
    filename: &str,
    file_content_in: T,
) -> Result<()> {
    let file_content = file_content_in.borrow();
    let file_entry = index
        .published_files
        .iter()
        .find(|f| f.file_name == filename)
        .ok_or_else(|| ClientLibError::FileNotInIndex(filename.to_string()))?;

    let expected_hash_str = &file_entry.hash;

    // Compute hash based on the algorithm specified in the index
    let computed_hash = match file_entry.algo {
        HashAlgorithm::Sha256 => sha256_for_content(file_content)?,
        HashAlgorithm::Sha512 => {
            let hash = sha512_for_content(file_content)?;
            match hash {
                AsfaloadHashes::Sha512(bytes) => hex::encode(bytes),
            }
        }
        HashAlgorithm::Sha1 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Sha1))
        }
        HashAlgorithm::Md5 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Md5))
        }
    };

    if expected_hash_str.to_lowercase() != computed_hash.to_lowercase() {
        return Err(ClientLibError::HashMismatch {
            expected: expected_hash_str.clone(),
            computed: computed_hash.clone(),
        });
    }

    println!(
        "✓ File hash verified ({})",
        match file_entry.algo {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Sha1 => "SHA-1",
            HashAlgorithm::Md5 => "MD5",
        }
    );

    Ok(())
}
