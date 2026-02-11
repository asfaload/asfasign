use crate::auth::create_auth_headers;
use crate::error::{AdminLibError, AdminLibResult};
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatureTrait,
    AsfaloadSignatures,
};
use reqwest::header::CONTENT_TYPE;
use rest_api_types::{
    ListPendingResponse, RegisterReleaseResponse, RegisterRepoRequest, RegisterRepoResponse,
    SubmitSignatureRequest, SubmitSignatureResponse,
};
use serde::de::DeserializeOwned;

/// A client for interacting with the v1 REST API.
///
/// Holds a single `reqwest::Client` for connection pooling and reuse
/// across multiple endpoint calls.
pub struct Client {
    client: reqwest::Client,
    base_url: String,
}

/// Typed payload for register-release requests.
#[derive(serde::Serialize)]
struct RegisterReleasePayload {
    release_url: String,
}

impl Client {
    /// Create a new REST client.
    pub fn new(base_url: impl Into<String>) -> Self {
        Client {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Check response status. On failure, read error body and return `RequestFailed`.
    async fn check_response_status(
        response: reqwest::Response,
    ) -> AdminLibResult<reqwest::Response> {
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "(failed to read response body)".to_string());
            return Err(AdminLibError::RequestFailed(format!(
                "{}: {}",
                status, error_text
            )));
        }
        Ok(response)
    }

    /// Parse JSON response body into a typed value.
    async fn parse_json_response<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> AdminLibResult<T> {
        // Do it in two steps so we can return both a reqwest error
        // and a serde_json error. It is possible to do it in one step
        // (let r = response.json::<T>().await?;) but in that case
        // we always return a reqwest error.
        let text = response.text().await?;
        let r = serde_json::from_str::<T>(&text)?;
        Ok(r)
    }

    /// List pending signature files from the backend.
    ///
    /// Makes an authenticated GET request to `/v1/pending_signatures`.
    pub async fn get_pending_signatures(
        &self,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<ListPendingResponse> {
        let url = format!("{}/v1/pending_signatures", self.base_url);
        let headers = create_auth_headers("", secret_key)?;

        let response = self.client.get(&url).headers(headers).send().await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Fetch file content from the backend.
    ///
    /// Makes an unauthenticated GET request to `/v1/files/{file_path}`.
    pub async fn fetch_file(&self, file_path: &str) -> AdminLibResult<Vec<u8>> {
        let url = format!("{}/v1/files/{}", self.base_url, file_path);

        let response = self.client.get(&url).send().await?;

        let response = Self::check_response_status(response).await?;

        let content = response.bytes().await?;

        Ok(content.to_vec())
    }

    /// Submit a signature for a file to the backend.
    ///
    /// Makes an authenticated POST request to `/v1/signatures`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn submit_signature(
        &self,
        file_path: &str,
        public_key: &AsfaloadPublicKeys,
        signature: &AsfaloadSignatures,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<SubmitSignatureResponse> {
        let url = format!("{}/v1/signatures", self.base_url);

        let request = SubmitSignatureRequest {
            file_path: file_path.to_string(),
            public_key: public_key.to_base64(),
            signature: signature.to_base64(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Register a GitHub release with the backend.
    ///
    /// Makes an authenticated POST request to `/v1/release`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn register_release(
        &self,
        release_url: &str,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<RegisterReleaseResponse> {
        let url = format!("{}/v1/release", self.base_url);

        let payload = RegisterReleasePayload {
            release_url: release_url.to_string(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&payload)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Register a repository with the backend.
    ///
    /// Makes an authenticated POST request to `/v1/register_repo`.
    /// Serializes the payload once and uses the same string for both
    /// auth headers and the request body (avoids signature mismatch).
    pub async fn register_repo(
        &self,
        signers_file_url: &str,
        signature: &AsfaloadSignatures,
        public_key: &AsfaloadPublicKeys,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<RegisterRepoResponse> {
        let url = format!("{}/v1/register_repo", self.base_url);

        let request = RegisterRepoRequest {
            signers_file_url: signers_file_url.to_string(),
            signature: signature.to_base64(),
            public_key: public_key.to_base64(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Propose a signers file update to the backend.
    ///
    /// Makes an authenticated POST request to `/v1/update_signers`.
    /// Reuses `RegisterRepoRequest` since the payload is identical
    /// (signers_file_url, signature, public_key).
    pub async fn update_signers(
        &self,
        signers_file_url: &str,
        signature: &AsfaloadSignatures,
        public_key: &AsfaloadPublicKeys,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<RegisterRepoResponse> {
        let url = format!("{}/v1/update_signers", self.base_url);

        let request = RegisterRepoRequest {
            signers_file_url: signers_file_url.to_string(),
            signature: signature.to_base64(),
            public_key: public_key.to_base64(),
        };

        // Serialize once: same bytes for auth and body
        let payload_string = serde_json::to_string(&request)?;
        let headers = create_auth_headers(&payload_string, secret_key)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(payload_string)
            .send()
            .await?;

        let response = Self::check_response_status(response).await?;
        Self::parse_json_response(response).await
    }

    /// Fetch content from an external URL.
    ///
    /// Makes a GET request to an arbitrary URL, reusing the internal HTTP client.
    /// Uses `text()` instead of `bytes()` to match the server's content handling,
    /// ensuring consistent hash computation (avoids BOM/encoding mismatches).
    pub async fn fetch_external_url(&self, url: &str) -> AdminLibResult<Vec<u8>> {
        let response = self.client.get(url).send().await?;

        let response = Self::check_response_status(response).await?;

        let content = response.text().await?;

        Ok(content.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_response_status_passes_through_on_success() {
        let response = http::Response::builder().status(200).body("ok").unwrap();
        let reqwest_response = reqwest::Response::from(response);

        let result = Client::check_response_status(reqwest_response).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_response_status_returns_error_on_4xx() {
        let response = http::Response::builder()
            .status(404)
            .body("Not Found")
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        let result = Client::check_response_status(reqwest_response).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            AdminLibError::RequestFailed(msg) => {
                assert!(msg.contains("404"), "Error should contain status code");
                assert!(msg.contains("Not Found"), "Error should contain body text");
            }
            other => panic!("Expected RequestFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_response_status_returns_error_on_5xx() {
        let response = http::Response::builder()
            .status(500)
            .body("Internal Server Error")
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        let result = Client::check_response_status(reqwest_response).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            AdminLibError::RequestFailed(msg) => {
                assert!(msg.contains("500"));
                assert!(msg.contains("Internal Server Error"));
            }
            other => panic!("Expected RequestFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn parse_json_response_deserializes_valid_json() {
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(r#"{"value": 42}"#)
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct TestPayload {
            value: u32,
        }

        let result: AdminLibResult<TestPayload> =
            Client::parse_json_response(reqwest_response).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TestPayload { value: 42 });
    }

    #[tokio::test]
    async fn fetch_external_url_returns_body_bytes() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/test-file.json")
            .with_status(200)
            .with_body(b"hello world")
            .create_async()
            .await;

        let client = Client::new(&server.url());
        let result = client
            .fetch_external_url(&format!("{}/test-file.json", server.url()))
            .await;

        mock.assert_async().await;
        let bytes = result.unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[tokio::test]
    async fn fetch_external_url_returns_error_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/missing")
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = Client::new(&server.url());
        let result = client
            .fetch_external_url(&format!("{}/missing", server.url()))
            .await;

        mock.assert_async().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AdminLibError::RequestFailed(msg) => {
                assert!(msg.contains("404"));
            }
            other => panic!("Expected RequestFailed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn parse_json_response_returns_error_on_invalid_json() {
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body("not valid json")
            .unwrap();
        let reqwest_response = reqwest::Response::from(response);

        #[derive(serde::Deserialize, Debug)]
        struct TestPayload {
            #[allow(dead_code)]
            value: u32,
        }

        let result: AdminLibResult<TestPayload> =
            Client::parse_json_response(reqwest_response).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            AdminLibError::JsonError(_) => {}
            other => panic!("Expected JsonError, got: {:?}", other),
        }
    }
}
