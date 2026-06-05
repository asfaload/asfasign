// Tests for the ping endpoint: connectivity plus authentication diagnostics.
// Follows the auth_tests.rs pattern: success and error cases share one test
// to avoid duplicating server setup.
#[cfg(all(test, not(feature = "test-utils")))]
pub mod ping_tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use axum::http::StatusCode;
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::{
        TestAuthHeaders, build_test_config, create_auth_headers_with_key, get_random_port,
        init_git_repo, url_for, wait_for_server,
    };
    use serde_json::Value;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    /// Send a GET to /v1/ping with the given auth headers, allowing individual
    /// headers to be overwritten to trigger specific failures.
    async fn send_ping(
        client: &reqwest::Client,
        port: u16,
        headers: &TestAuthHeaders,
        overwrite: HashMap<String, String>,
    ) -> Result<reqwest::Response> {
        let response = client
            .get(url_for("ping", port))
            .header(
                HEADER_TIMESTAMP,
                overwrite
                    .get(HEADER_TIMESTAMP)
                    .unwrap_or(&headers.timestamp),
            )
            .header(
                HEADER_NONCE,
                overwrite.get(HEADER_NONCE).unwrap_or(&headers.nonce),
            )
            .header(
                HEADER_SIGNATURE,
                overwrite
                    .get(HEADER_SIGNATURE)
                    .unwrap_or(&headers.signature),
            )
            .header(
                HEADER_PUBLIC_KEY,
                overwrite
                    .get(HEADER_PUBLIC_KEY)
                    .unwrap_or(&headers.public_key),
            )
            .send()
            .await?;
        Ok(response)
    }

    #[tokio::test]
    async fn test_ping_endpoint() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let port = get_random_port().await?;
        let config = build_test_config(&repo_path_buf, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();
        let test_keys = TestKeys::new(1);
        let secret_key = test_keys.sec_key(0).unwrap();

        // Unauthenticated ping
        // --------------------
        let response = client.get(url_for("ping", port)).send().await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["message"], "pong");
        assert_eq!(body["auth"]["status"], "unauthenticated");

        // Authenticated ping with valid signature
        // ---------------------------------------
        let auth_headers = create_auth_headers_with_key(secret_key, "").await;
        let response = send_ping(&client, port, &auth_headers, HashMap::new()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["message"], "pong");
        assert_eq!(body["auth"]["status"], "success");
        assert_eq!(body["auth"]["public_key"], auth_headers.public_key.as_str());

        // Replayed nonce: sending the exact same headers again must be diagnosed
        // ----------------------------------------------------------------------
        let response = send_ping(&client, port, &auth_headers, HashMap::new()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["auth"]["status"], "failed");
        assert_eq!(body["auth"]["public_key"], auth_headers.public_key.as_str());
        assert_eq!(
            body["auth"]["reason"],
            "Replay attack detected: nonce already used"
        );

        // Invalid signature
        // -----------------
        let auth_headers = create_auth_headers_with_key(secret_key, "").await;
        let mut overwrite: HashMap<String, String> = HashMap::new();
        overwrite.insert(
            HEADER_SIGNATURE.to_string(),
            "invalid_signature".to_string(),
        );
        let response = send_ping(&client, port, &auth_headers, overwrite).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["auth"]["status"], "failed");
        assert_eq!(body["auth"]["public_key"], auth_headers.public_key.as_str());
        assert_eq!(
            body["auth"]["reason"],
            "Authentication failed: Signature error"
        );

        // Stale timestamp
        // ---------------
        let auth_headers = create_auth_headers_with_key(secret_key, "").await;
        let old_timestamp = chrono::Utc::now() - chrono::Duration::minutes(10);
        let mut overwrite: HashMap<String, String> = HashMap::new();
        overwrite.insert(HEADER_TIMESTAMP.to_string(), old_timestamp.to_rfc3339());
        let response = send_ping(&client, port, &auth_headers, overwrite).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["auth"]["status"], "failed");
        let reason = body["auth"]["reason"].as_str().unwrap();
        assert!(
            reason.starts_with("Timestamp validation failed"),
            "unexpected reason: {reason}"
        );

        // Partial headers: only the public key header present
        // ---------------------------------------------------
        let auth_headers = create_auth_headers_with_key(secret_key, "").await;
        let response = client
            .get(url_for("ping", port))
            .header(HEADER_PUBLIC_KEY, &auth_headers.public_key)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["auth"]["status"], "failed");
        assert_eq!(body["auth"]["public_key"], auth_headers.public_key.as_str());
        assert_eq!(body["auth"]["reason"], "Missing authentication headers");

        // Invalid base64 public key: no key can be reported back
        // ------------------------------------------------------
        let auth_headers = create_auth_headers_with_key(secret_key, "").await;
        let mut overwrite: HashMap<String, String> = HashMap::new();
        overwrite.insert(
            HEADER_PUBLIC_KEY.to_string(),
            "not-a-valid-key!".to_string(),
        );
        let response = send_ping(&client, port, &auth_headers, overwrite).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await?;
        assert_eq!(body["auth"]["status"], "failed");
        assert_eq!(body["auth"]["public_key"], Value::Null);
        let reason = body["auth"]["reason"].as_str().unwrap();
        assert!(
            reason.starts_with("Authentication failed"),
            "unexpected reason: {reason}"
        );

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }
}
