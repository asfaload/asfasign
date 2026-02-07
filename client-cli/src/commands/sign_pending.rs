use crate::error::Result;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    sha512_for_content,
};

/// Handle the sign-pending command.
///
/// Translates a file path from list-pending into a signed submission to the backend.
/// This is a one-step command for the user that:
/// 1. Fetches the file content from backend
/// 2. Computes hash and signs with user's key
/// 3. Submits the signature to backend
///
/// # Arguments
/// * `file_path` - Path to the file (as returned by list-pending)
/// * `backend_url` - Backend API URL
/// * `secret_key_path` - Path to the user's secret key file
/// * `password` -  Password to unlock secret key
///
/// # Workflow
/// * Load secret key and derive public key
/// * Fetch file content from backend
/// * Compute SHA512 hash
/// * Sign the hash
/// * Submit signature to backend
/// * Display result (whether signature is now complete)
pub async fn handle_sign_pending_command(
    file_path: &str,
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    let public_key = AsfaloadPublicKeys::from_secret_key(&secret_key)?;

    // Fetch file from backend
    let file_content = crate::rest_client::fetch_file(backend_url, file_path).await?;

    // Compute hash
    let hash = sha512_for_content(file_content)?;

    // Sign the hash
    let signature = secret_key.sign(&hash)?;

    // Submit to backend
    let response = crate::rest_client::submit_signature(
        backend_url,
        file_path,
        &public_key,
        &signature,
        &secret_key,
    )
    .await?;

    // Display result
    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.is_complete {
        println!("Success! Signature submitted (complete)");
    } else {
        println!("Success! Signature submitted");
    }

    Ok(())
}
