use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use features_lib::constants::{INDEX_FILE, SIGNATURES_SUFFIX};
use features_lib::{
    AsfaloadHashes, AsfaloadIndex, HashAlgorithm, SignersConfig,
    aggregate_signature_helpers::{check_groups, get_individual_signatures_from_bytes},
    parse_signers_config, sha512_for_content,
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::types::{AsfaloadPublicKeys, AsfaloadSignatures};

/// Handle the download command
pub async fn download_file_with_verification(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
) -> Result<()> {
    // Parse the URL to extract components
    let url = reqwest::Url::parse(file_url).context("Failed to parse file URL")?;

    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .context("Could not extract filename from URL")?;

    // Construct the index file path for the get-signers endpoint
    // This is the path relative to the git repo root
    let index_file_path = construct_index_file_path(&url)?;

    //  Download signers file using the get-signers endpoint.
    //  The backend will look for the signers file that applies
    let signers_url = format!("{}/get-signers/{}", backend_url, index_file_path);
    let signers_content = download_file(&signers_url)
        .await
        .context("Failed to download signers file")?;
    let signers_config = parse_signers_config(std::str::from_utf8(&signers_content)?)
        .map_err(|e| anyhow::anyhow!("Failed to parse signers config: {}", e))?;

    // Download asfaload.index.json using /files/ endpoint as we have the exact location
    // on the backend
    let index_file_path = construct_file_repo_path(&url, INDEX_FILE)?;
    let index_url = format!("{}/files/{}", backend_url, index_file_path);
    let index_content = download_file(&index_url)
        .await
        .context("Failed to download index file")?;
    let index: AsfaloadIndex =
        serde_json::from_slice(&index_content).context("Failed to parse index file")?;

    // For signatures of the index we also can derive the location from the index location
    let signatures_file_path =
        construct_file_repo_path(&url, &format!("{}.{}", INDEX_FILE, SIGNATURES_SUFFIX))?;
    let signatures_url = format!("{}/files/{}", backend_url, signatures_file_path);
    let signatures_content = download_file(&signatures_url)
        .await
        .context("Failed to download signatures file")?;

    // Verify signatures of the index file
    let file_hash =
        sha512_for_content(index_content).context("Failed to compute hash of index file")?;

    verify_signatures(signatures_content, &signers_config, &file_hash)
        .context("Signature verification failed")?;

    println!("✓ Signatures verified successfully");

    //  Download actual file
    println!("Downloading {}...", filename);
    let file_content = download_file(file_url)
        .await
        .context("Failed to download file")?;

    // Verify file hash
    verify_file_hash(&index, filename, file_content.as_slice())?;

    // Save file
    let output_path = output.cloned().unwrap_or_else(|| PathBuf::from(filename));
    tokio::fs::write(&output_path, file_content)
        .await
        .context("Failed to write output file")?;

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
    let host = file_url.host_str().context("URL has no host")?;
    let path = file_url.path();

    // Remove leading slash from path if present
    let path = path.strip_prefix('/').unwrap_or(path);

    // Remove the original filename from path to get directory
    let dir_path = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

    // Translate GitHub release path: download -> tag
    let translated_path = translate_github_release_path(dir_path);

    Ok(format!("{}/{}/{}", host, translated_path, filename))
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
    let response = client
        .get(url)
        .send()
        .await
        .context("HTTP request failed")?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {}: {}", response.status(), url);
    }

    let content = response
        .bytes()
        .await
        .context("Failed to read response body")?;

    Ok(content.to_vec())
}

/// Verify signatures meet threshold requirements
fn verify_signatures(
    signatures_content: Vec<u8>,
    signers_config: &SignersConfig,
    data: &AsfaloadHashes,
) -> Result<()> {
    let mut typed_signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> = HashMap::new();

    let parsed_signatures = get_individual_signatures_from_bytes(signatures_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse signatures: {}", e))?;

    for (pubkey, signature) in parsed_signatures {
        let pubkey_b64 = pubkey.to_base64();

        if pubkey.verify(&signature, data).is_err() {
            eprintln!("Warning: Invalid signature from key {}", pubkey_b64);
            continue;
        }

        typed_signatures.insert(pubkey, signature);
    }

    let artifact_groups = signers_config.artifact_signers();
    if artifact_groups.is_empty() {
        anyhow::bail!("No artifact_signers group defined in signers config");
    }

    let is_complete = check_groups(artifact_groups, &typed_signatures, data);

    if !is_complete {
        anyhow::bail!(
            "Signature verification failed: insufficient valid signatures from artifact_signers"
        );
    }

    let valid_count = typed_signatures.len();
    println!("✓ Verified {} valid signature(s)", valid_count);

    Ok(())
}

/// Compute SHA-256 hash for content
fn sha256_for_content<T: std::borrow::Borrow<[u8]>>(
    content_in: T,
) -> Result<String, std::io::Error> {
    let content = content_in.borrow();
    if content.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        ))
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
        .context(format!("File {} not found in index", filename))?;

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
            anyhow::bail!("SHA-1 use is discouraged, not implemented")
        }
        HashAlgorithm::Md5 => {
            anyhow::bail!("MD5 use is discouraged, not implemented")
        }
    };

    if expected_hash_str.to_lowercase() != computed_hash.to_lowercase() {
        anyhow::bail!(
            "Hash mismatch: expected {}, got {}",
            expected_hash_str,
            computed_hash
        );
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
