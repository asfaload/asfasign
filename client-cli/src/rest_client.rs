use crate::error::Result;
use crate::utils::create_auth_headers;
use features_lib::{
    rest_api::{ListPendingResponse, RegisterReleaseResponse, SubmitSignatureRequest, SubmitSignatureResponse},
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatureTrait,
};
use reqwest::Client;
use serde_json::Value;

/// A client for interacting with the REST API with authentication
pub struct RestClient {
    client: Client,
    base_url: String,
}

impl RestClient {
    /// Create a new REST client
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the REST API server
    ///
    pub fn new(base_url: String) -> Self {
        RestClient {
            client: Client::new(),
            base_url,
        }
    }

    /// Send an authenticated POST request to the API
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint (e.g., "add-file")
    /// * `payload` - The JSON payload to send
    /// * `secret_key` - The secret key for authentication
    ///
    /// # Returns
    ///
    /// The response from the API
    ///
    pub async fn post_authenticated(
        &self,
        endpoint: &str,
        payload: &Value,
        secret_key: AsfaloadSecretKeys,
    ) -> Result<Value> {
        use rest_api_auth::AuthError;

        // Convert payload to string
        let payload_string = payload.to_string();

        // Create authentication headers
        let headers = create_auth_headers(&payload_string, secret_key)?;

        // Send the request
        let response = self
            .client
            .post(format!("{}/{}", self.base_url, endpoint))
            .headers(headers)
            .json(payload)
            .send()
            .await
            .map_err(|e| AuthError::IoError(std::io::Error::other(e.to_string())))?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(AuthError::IoError(std::io::Error::other(format!(
                "API request failed with status: {}",
                response.status()
            )))
            .into());
        }

        // Parse and return the response
        let response_json = response.json::<Value>().await.map_err(|e| {
            AuthError::AuthDataPreparationError(format!("Failed to parse response: {}", e))
        })?;

        Ok(response_json)
    }
}

/// List pending signature files from the backend.
///
/// Makes an authenticated GET request to /pending_signatures endpoint.
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
    use rest_api_auth::AuthError;

    let url = format!("{}/pending_signatures", backend_url);

    // Create auth headers (using empty payload for GET request)
    let headers = create_auth_headers("", secret_key)?;

    let client = Client::new();
    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| AuthError::AuthDataPreparationError(format!("Network error: {}", e)))?;

    if !response.status().is_success() {
        return Err(AuthError::AuthDataPreparationError(format!(
            "GET {}: {}",
            url,
            response.status()
        ))
        .into());
    }

    let response_body: ListPendingResponse = response.json().await.map_err(|e| {
        AuthError::AuthDataPreparationError(format!("Failed to parse response: {}", e))
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
    use rest_api_auth::AuthError;

    let url = format!("{}/files/{}", backend_url, file_path);

    let client = Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AuthError::AuthDataPreparationError(format!("Network error: {}", e)))?;

    if !response.status().is_success() {
        return Err(AuthError::AuthDataPreparationError(format!(
            "GET {}: {}",
            url,
            response.status()
        ))
        .into());
    }

    let content = response.bytes().await.map_err(|e| {
        AuthError::AuthDataPreparationError(format!("Failed to read response: {}", e))
    })?;

    Ok(content.to_vec())
}

/// Submit a signature for a file to the backend.
///
/// Makes an authenticated POST request to /signatures endpoint with the signature data.
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
    use rest_api_auth::AuthError;

    let url = format!("{}/signatures", backend_url);

    // Build the request
    let request = SubmitSignatureRequest {
        file_path: file_path.to_string(),
        public_key: public_key.to_base64(),
        signature: signature.to_base64(),
    };

    // Create auth headers
    let request_json = serde_json::to_string(&request).map_err(|e| {
        AuthError::AuthDataPreparationError(format!("Failed to serialize request: {}", e))
    })?;
    let headers = create_auth_headers(&request_json, secret_key.clone())?;

    let client = Client::new();
    let response = client
        .post(&url)
        .headers(headers)
        .json(&request)
        .send()
        .await
        .map_err(|e| AuthError::AuthDataPreparationError(format!("Network error: {}", e)))?;

    if !response.status().is_success() {
        return Err(AuthError::AuthDataPreparationError(format!(
            "POST {}: {}",
            url,
            response.status()
        ))
        .into());
    }

    let response_body: SubmitSignatureResponse = response.json().await.map_err(|e| {
        AuthError::AuthDataPreparationError(format!("Failed to parse response: {}", e))
    })?;

    Ok(response_body)
}

/// Register a GitHub release with the backend.
///
/// Makes an authenticated POST request to /release endpoint.
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
    use rest_api_auth::AuthError;

    let url = format!("{}/release", backend_url);

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
        .map_err(|e| AuthError::AuthDataPreparationError(format!("Network error: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = match response.text().await {
            Ok(text) => text,
            Err(e) => format!("(could not read response body: {})", e),
        };
        return Err(AuthError::AuthDataPreparationError(format!(
            "POST {}: {} - {}",
            url, status, error_text
        ))
        .into());
    }

    let response_body: RegisterReleaseResponse = response.json().await.map_err(|e| {
        AuthError::AuthDataPreparationError(format!("Failed to parse response: {}", e))
    })?;

    Ok(response_body)
}
