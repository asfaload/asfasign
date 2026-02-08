mod v1;

use crate::error::{ClientCliError, Result};
use crate::utils::create_auth_headers;
use features_lib::AsfaloadSecretKeys;
use reqwest::Client;
use serde_json::Value;

// Re-export v1 endpoint functions as the current API surface
pub use v1::{fetch_file, get_pending_signatures, register_release, submit_signature};

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
    /// * `endpoint` - The API endpoint (e.g., "v1/add-file")
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
            .map_err(|e| ClientCliError::NetworkError(e.to_string()))?;

        // Check if the request was successful
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

        // Parse and return the response
        let response_json = response.json::<Value>().await.map_err(|e| {
            ClientCliError::ResponseParseError(format!("Failed to parse response: {}", e))
        })?;

        Ok(response_json)
    }
}
