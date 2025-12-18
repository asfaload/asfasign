use crate::error::Result;
use crate::utils::create_auth_headers;
use features_lib::{SecretKey, SecretKeyTrait};
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
    pub async fn post_authenticated<M>(
        &self,
        endpoint: &str,
        payload: &Value,
        secret_key: SecretKey<M>,
    ) -> Result<Value>
    where
        SecretKey<M>: SecretKeyTrait<SecretKey = M>,
        M: Clone,
    {
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
            .map_err(|e| crate::error::ClientCliError::AuthError(e.to_string()))?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(crate::error::ClientCliError::AuthError(format!(
                "API request failed with status: {}",
                response.status()
            )));
        }

        // Parse and return the response
        let response_json = response
            .json::<Value>()
            .await
            .map_err(|e| crate::error::ClientCliError::AuthError(e.to_string()))?;

        Ok(response_json)
    }
}

