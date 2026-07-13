use std::collections::HashMap;

use crate::error::Result;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    AsfaloadSignatures, sha512_for_content,
};
use rest_api_types::{SubmitSignatureResponse, models::ClientPendingFile};

/// Handle the sign-pending command.
///
/// Translates a file path from list-pending into a signed submission to the backend.
/// This is a one-step command for the user that:
/// 1. Fetches all files that need signing from backend
/// 2. Computes hash and signs each file with user's key
/// 3. Submits all signatures to backend in one request
///
/// # Arguments
/// * `file_path` - Path to the file (as returned by list-pending)
/// * `backend_url` - Backend API URL
/// * `secret_key_path` - Path to the user's secret key file
/// * `password` - Password to unlock secret key
///
/// # Workflow
/// * Load secret key and derive public key
/// * Fetch all files to sign from backend
/// * Compute SHA512 hash and sign each file
/// * Submit all signatures to backend
/// * Display result (whether signature is now complete)
pub async fn handle_sign_pending_command(
    pending_file: ClientPendingFile,
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<SubmitSignatureResponse> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    handle_sign_pending_sec_key(pending_file, backend_url, &secret_key, json).await
}

pub async fn handle_sign_pending_sec_key(
    pending_file: ClientPendingFile,
    backend_url: &str,
    secret_key: &AsfaloadSecretKeys,
    json: bool,
) -> Result<SubmitSignatureResponse> {
    let public_key = AsfaloadPublicKeys::from_secret_key(secret_key)?;
    // Create REST client
    let client = admin_lib::v1::Client::new(backend_url);

    // Fetch all files that need signing
    let files_to_sign = client
        .fetch_files_to_sign(&pending_file.path(), secret_key)
        .await?;

    // Sign each file
    let mut signatures: HashMap<String, AsfaloadSignatures> = HashMap::new();
    for (path, content) in &files_to_sign {
        // content is &Vec<u8>, as_slice() give a &[u8] and avoids cloning
        let hash = sha512_for_content(content.as_slice())?;
        // Only verify the digest for the primary file; associated files (e.g. metadata)
        // are signed without digest pre-verification since pending_file.digest() covers
        // only the primary file.
        if *path == pending_file.path() && hash.to_string() != pending_file.digest() {
            return Err(crate::error::ClientCliError::ServerDigestError(
                hash.to_string(),
                pending_file.digest(),
            ));
        }
        let signature = secret_key.sign(&hash)?;
        signatures.insert(path.clone(), signature);
    }

    // Submit all signatures to backend
    let response = client
        .submit_signatures(pending_file, &public_key, &signatures, secret_key)
        .await?;

    // Display result
    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.is_complete {
        println!(
            "Success! Your signature has been included and the aggregate signature is now complete. No further signature will be included in this aggregate signature."
        );
    } else {
        println!(
            "Success! Your signature has been included, but the aggregate signature is not yet complete. Other signers must still provide their signatures."
        );
    }

    Ok(response)
}
