use crate::error::Result;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    sha512_for_content,
};
use rest_api_types::RevokeFileResponse;

/// Handle the revoke command.
///
/// Builds a revocation document, signs it, and submits to the backend.
///
/// # Workflow
/// 1. Load secret key and derive public key
/// 2. Fetch the file content from backend
/// 3. Compute sha512 of the fetched content
/// 4. Build RevocationFile JSON (timestamp, subject_digest, initiator)
/// 5. Sign the sha512 of the revocation JSON
/// 6. Submit to backend via POST /v1/revoke
/// 7. Display result
pub async fn handle_revoke_command(
    backend_url: &str,
    file_path: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<RevokeFileResponse> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    let public_key = AsfaloadPublicKeys::from_secret_key(&secret_key)?;

    // Create REST client
    let client = admin_lib::v1::Client::new(backend_url);

    // Fetch file content from backend to compute its digest
    let file_content = client.fetch_file(file_path).await?;

    // Compute sha512 of the file content
    let subject_digest = sha512_for_content(file_content)?;

    // Build the revocation document
    let revocation = signers_file_types::revocation::RevocationFile {
        timestamp: chrono::Utc::now(),
        subject_digest,
        initiator: public_key.clone(),
    };
    let revocation_json = serde_json::to_string_pretty(&revocation)?;

    // Sign the sha512 of the revocation JSON
    let revocation_hash = sha512_for_content(revocation_json.as_bytes().to_vec())?;
    let signature = secret_key.sign(&revocation_hash)?;

    // Submit revocation to backend
    let response = client
        .revoke_file(
            file_path,
            &revocation_json,
            &signature,
            &public_key,
            &secret_key,
        )
        .await?;

    // Display result
    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Success! File revoked: {}", file_path);
    } else {
        println!("Revocation failed: {}", response.message);
    }

    Ok(response)
}
