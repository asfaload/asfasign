// Comprehensive authentication tests
#[cfg(test)]
pub mod auth_tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use axum::http::StatusCode;
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};
    use rest_api::{auth_middleware::MAX_BODY_SIZE, server::run_server};
    use rest_api_auth::{HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::{
        build_test_config, get_random_port, init_git_repo, send_add_file_request_with_key,
        send_add_file_request_with_key_and_overwrite, send_repeated_add_file_request,
        wait_for_server,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    // We test success and error cases in one test. Doing it in different tests duplicates
    // the server setup, keypair generation, etc.
    #[tokio::test]
    async fn test_api_authentication() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let port = get_random_port().await?;
        let config = build_test_config(&repo_path_buf, port);

        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Create authentication headers
        let payload = json!({
            "file_path": "test_file.txt",
            "content": "This should succeed with proper authentication"
        });

        // Generate a test key pair
        let test_password = "test_password";
        let key_pair = AsfaloadKeyPairs::new(test_password).unwrap();
        let secret_key = key_pair.secret_key(test_password).unwrap();

        let response = send_add_file_request_with_key(&client, port, &secret_key, &payload).await;

        // Check the response status - should be 200 OK
        let status = response.status();
        if status != StatusCode::OK {
            let response_text = response.text().await?;
            panic!(
                "Expected response code Ok, go {}. Response was:\n{}",
                status, response_text
            )
        }

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["success"], true);
        assert_eq!(response_body["message"], "File added successfully");

        // Invalid signature
        // -----------------

        let mut overwrite: HashMap<String, String> = HashMap::new();
        overwrite.insert(
            HEADER_SIGNATURE.to_string(),
            "invalid_signature".to_string(),
        );
        let response = send_add_file_request_with_key_and_overwrite(
            &client,
            port,
            &secret_key,
            &payload,
            overwrite,
        )
        .await;

        // Check the response status - should be 401 Unauthorized
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            response_body["error"],
            "Authentication failed: Signature error"
        );

        // Invalid timestamp
        // -----------------

        let old_timestamp = chrono::Utc::now() - chrono::Duration::minutes(10);
        let mut overwrite: HashMap<String, String> = HashMap::new();
        overwrite.insert(HEADER_TIMESTAMP.to_string(), old_timestamp.to_rfc3339());
        let response = send_add_file_request_with_key_and_overwrite(
            &client,
            port,
            &secret_key,
            &payload,
            overwrite,
        )
        .await;

        // Check the response status - should be 401 Unauthorized
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        // Do not call to_string() on the Value as the generated string includes the quotes,
        // and the starts_with test fails.
        let error_msg = response_body["error"].as_str().unwrap();
        let expected = "Timestamp validation failed";
        if !error_msg.starts_with(expected) {
            panic!("Expected error to start with \"{expected}\", but is {error_msg}");
        }

        // Invalid nonce
        // -------------
        //
        let mut overwrite: HashMap<String, String> = HashMap::new();
        overwrite.insert(HEADER_NONCE.to_string(), "invalid_nonce".to_string());
        let response = send_add_file_request_with_key_and_overwrite(
            &client,
            port,
            &secret_key,
            &payload,
            overwrite,
        )
        .await;

        // Check the response status - should be 401 Unauthorized
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            response_body["error"],
            "Authentication failed: Invalid nonce format"
        );

        // Nonce reuse
        // -----------
        // Reuse the same nonce to simulate replay
        let response = send_repeated_add_file_request(&client, port, &payload).await;
        // Check the response status - should be 401 Unauthorized
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            response_body["error"],
            "Replay attack detected: nonce already used"
        );

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_file_size_limits() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let port = get_random_port().await?;
        let config = build_test_config(&repo_path_buf, port);

        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Generate a test key pair
        let test_password = "test_password";
        let key_pair = AsfaloadKeyPairs::new(test_password).unwrap();
        let secret_key = key_pair.secret_key(test_password).unwrap();

        // Test 1: Normal sized file (should succeed)
        let normal_content = "This is a normal sized file content".to_string();
        let payload = json!({
            "file_path": "normal_file.txt",
            "content": normal_content
        });
        let response = send_add_file_request_with_key(&client, port, &secret_key, &payload).await;

        assert_eq!(response.status(), StatusCode::OK);
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["success"], true);

        // Test 2: Oversized file (should fail)
        let oversized_content = "x".repeat(MAX_BODY_SIZE + 1);
        let payload = json!({
            "file_path": "oversized_file.txt",
            "content": oversized_content
        });

        let response = send_add_file_request_with_key(&client, port, &secret_key, &payload).await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            response_body["error"],
            "Request too big: length limit exceeded"
        );

        // Test 3: Accepted size should be successful
        let file_path = "max_size_file.txt";
        let overhead = json!({
            "file_path": file_path,
            "content": ""
        })
        .to_string()
        .len();
        let max_content = "x".repeat(MAX_BODY_SIZE - overhead);
        let payload = json!({
            "file_path": file_path,
            "content": max_content
        });
        let response = send_add_file_request_with_key(&client, port, &secret_key, &payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["success"], true);

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }
}
