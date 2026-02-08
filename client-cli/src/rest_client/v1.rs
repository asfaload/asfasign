use crate::error::{ClientCliError, Result};
use crate::utils::create_auth_headers;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatureTrait,
};
use reqwest::Client;
use rest_api_types::{
    ListPendingResponse, RegisterReleaseResponse, SubmitSignatureRequest, SubmitSignatureResponse,
};

/// List pending signature files from the backend.
///
/// Makes an authenticated GET request to /v1/pending_signatures endpoint.
///
/// # Arguments
///
/// * `backend_url` - Base URL of the backend API
/// * `secret_key` - Your secret key for signing the request
///
/// # Returns
///
/// List of file paths that need your signature
///
/// # Errors
///
/// Returns error if:
/// - Authentication fails
/// - Backend returns non-200 status
/// - Response is malformed
pub async fn get_pending_signatures(
    backend_url: &str,
    secret_key: AsfaloadSecretKeys,
) -> Result<ListPendingResponse> {
    let url = format!("{}/v1/pending_signatures", backend_url);

    // Create auth headers (using empty payload for GET request)
    let headers = create_auth_headers("", secret_key)?;

    let client = Client::new();
    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| ClientCliError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(ClientCliError::RequestFailed(format!(
            "{}: {}",
            response.status(),
            response.text().await.unwrap_or("".to_string())
        )));
    }

    let response_body: ListPendingResponse = response.json().await.map_err(|e| {
        ClientCliError::ResponseParseError(format!("Failed to parse response: {}", e))
    })?;

    Ok(response_body)
}

/// Fetch file content from the backend.
///
/// This is a helper for the sign-pending workflow. The client needs to
/// fetch the actual file content to compute its hash and sign it.
///
/// # Arguments
///
/// * `backend_url` - Base URL of the backend API
/// * `file_path` - Relative path to the file (as returned by list-pending)
///
/// # Returns
///
/// The file content as bytes
///
/// # Errors
///
/// Returns error if:
/// - Backend returns non-200 status
/// - Network error occurs
pub async fn fetch_file(backend_url: &str, file_path: &str) -> Result<Vec<u8>> {
    let url = format!("{}/v1/files/{}", backend_url, file_path);

    let client = Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ClientCliError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(ClientCliError::RequestFailed(format!(
            "GET {}: {} - {}",
            url, status, error_text
        )));
    }

    let content = response.bytes().await.map_err(|e| {
        ClientCliError::ResponseParseError(format!("Failed to read response: {}", e))
    })?;

    Ok(content.to_vec())
}

/// Submit a signature for a file to the backend.
///
/// Makes an authenticated POST request to /v1/signatures endpoint with the signature data.
///
/// # Arguments
///
/// * `backend_url` - Base URL of the backend API
/// * `file_path` - Relative path to the file being signed
/// * `public_key` - The signer's public key
/// * `signature` - The signature data
/// * `secret_key` - The secret key for authentication
///
/// # Returns
///
/// Submission response indicating whether the aggregate signature is now complete
///
/// # Errors
///
/// Returns error if:
/// - Authentication fails
/// - Backend returns non-200 status
/// - Response is malformed
pub async fn submit_signature(
    backend_url: &str,
    file_path: &str,
    public_key: &AsfaloadPublicKeys,
    signature: &features_lib::AsfaloadSignatures,
    secret_key: &AsfaloadSecretKeys,
) -> Result<SubmitSignatureResponse> {
    let url = format!("{}/v1/signatures", backend_url);

    // Build the request
    let request = SubmitSignatureRequest {
        file_path: file_path.to_string(),
        public_key: public_key.to_base64(),
        signature: signature.to_base64(),
    };

    // Create auth headers
    let request_json = serde_json::to_string(&request)
        .map_err(|e| ClientCliError::InvalidInput(format!("Failed to serialize request: {}", e)))?;
    let headers = create_auth_headers(&request_json, secret_key.clone())?;

    let client = Client::new();
    let response = client
        .post(&url)
        .headers(headers)
        .json(&request)
        .send()
        .await
        .map_err(|e| ClientCliError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(ClientCliError::RequestFailed(format!(
            "{}: {}",
            status, error_text
        )));
    }

    let response_body: SubmitSignatureResponse = response.json().await.map_err(|e| {
        ClientCliError::ResponseParseError(format!("Failed to parse response: {}", e))
    })?;

    Ok(response_body)
}

/// Register a GitHub release with the backend.
///
/// Makes an authenticated POST request to /v1/release endpoint.
///
/// # Arguments
///
/// * `backend_url` - Base URL of the backend API
/// * `release_url` - URL of the GitHub release to register
/// * `secret_key` - The secret key for signing the request
///
/// # Returns
///
/// Registration response with success status and index file path
///
/// # Errors
///
/// Returns error if:
/// - Authentication fails
/// - Backend returns non-200 status
/// - Response is malformed
pub async fn register_release(
    backend_url: &str,
    release_url: &str,
    secret_key: AsfaloadSecretKeys,
) -> Result<RegisterReleaseResponse> {
    let url = format!("{}/v1/release", backend_url);

    let payload = serde_json::json!({
        "release_url": release_url
    });

    let payload_string = payload.to_string();
    let headers = create_auth_headers(&payload_string, secret_key)?;

    let client = Client::new();
    let response = client
        .post(&url)
        .headers(headers)
        .json(&payload)
        .send()
        .await
        .map_err(|e| ClientCliError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = match response.text().await {
            Ok(text) => text,
            Err(e) => format!("(could not read response body: {})", e),
        };
        return Err(ClientCliError::RequestFailed(format!(
            "{}: {}",
            status, error_text
        )));
    }

    let response_body: RegisterReleaseResponse = response.json().await.map_err(|e| {
        ClientCliError::ResponseParseError(format!("Failed to parse response: {}", e))
    })?;

    Ok(response_body)
}
