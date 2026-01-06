#[cfg(test)]
pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs, AsfaloadSignatureTrait};
    use rest_api::server::run_server;
    use rest_api_auth::{
        AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE,
        HEADER_TIMESTAMP,
    };
    use rest_api_test_helpers::{
        build_test_config, file_exists_in_repo, get_latest_commit, get_random_port, init_git_repo,
        parse_log_lines, read_file_content, url_for, wait_for_commit,
        wait_for_log_entry_with_request_id, wait_for_server,
    };
    use serde_json::{Value, json};
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;
    use tokio::time::Duration;
    use tracing_appender::non_blocking::WorkerGuard;
    use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

    struct TestAuthHeaders {
        timestamp: String,
        nonce: String,
        signature: String,
        public_key: String,
    }

    /// Helper function to create authentication headers for a given payload
    async fn create_auth_headers(payload: &str) -> TestAuthHeaders {
        // Generate a test key pair
        let test_password = "test_password";
        let key_pair = AsfaloadKeyPairs::new(test_password).unwrap();
        let secret_key = key_pair.secret_key(test_password).unwrap();

        // Create authentication info and signature
        let auth_info = AuthInfo::new(payload.to_string());
        let auth_signature = AuthSignature::new(&auth_info, &secret_key).unwrap();

        TestAuthHeaders {
            timestamp: auth_signature.auth_info().timestamp().to_rfc3339(),
            nonce: auth_signature.auth_info().nonce(),
            signature: auth_signature.signature().to_base64(),
            public_key: auth_signature.public_key(),
        }
    }

    // Test case: Successfully add a file to the repository
    #[tokio::test]
    async fn test_add_file_success() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();
        let test_repo_path_buf = repo_path_buf.clone();

        let port = get_random_port().await?;
        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let config = build_test_config(&repo_path_buf, port);

        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Define the file to add
        let file_path = "test_file.txt";
        let content = "This is a test file for integration testing.";
        let commit_message = format!("added file at /{}", file_path);

        // Create authentication headers
        let payload = json!({
            "file_path": file_path,
            "content": content
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload_string).await;

        // Send the request to add the file with authentication headers
        let response = client
            .post(url_for("add-file", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status
        assert_eq!(response.status(), StatusCode::OK);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["success"], true);
        assert_eq!(response_body["message"], "File added successfully");
        assert_eq!(response_body["file_path"], file_path);

        // Give the server time to process the git commit
        wait_for_commit(test_repo_path_buf.clone(), &commit_message, None).await?;

        // Verify the file was created on disk
        assert!(
            file_exists_in_repo(&test_repo_path_buf, file_path),
            "File was not created on disk"
        );

        // Verify the file content
        let file_content =
            read_file_content(&test_repo_path_buf, file_path).expect("Failed to read file content");
        assert_eq!(file_content, content, "File content doesn't match");

        // Verify the commit message
        let commit_msg =
            get_latest_commit(&test_repo_path_buf).expect("Failed to get latest commit");
        assert!(
            commit_msg.contains(&commit_message),
            "Commit message doesn't match"
        );

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // Test case: Add file with empty path (should fail)
    #[tokio::test]
    async fn test_add_file_empty_path() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;
        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let config = build_test_config(&repo_path_buf, port);
        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Create authentication headers
        let payload = json!({
            "file_path": "",
            "content": "This should fail"
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload_string).await;

        // Send the request with an empty file path and authentication headers
        let response = client
            .post(url_for("add-file", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            response_body["error"],
            "Invalid file path: File path cannot be empty"
        );

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // Test case: Add file to a subdirectory
    #[tokio::test]
    async fn test_add_file_to_subdirectory() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();
        let test_repo_path_buf = repo_path_buf.clone();

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

        // Define the file to add in a subdirectory
        let file_path = "subdir/nested_file.txt";
        let content = "This file is in a subdirectory.";
        let commit_message = format!("added file at /{}", file_path);

        // Create authentication headers
        let payload = json!({
            "file_path": file_path,
            "content": content
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload_string).await;

        // Send the request to add the file with authentication headers
        let response = client
            .post(url_for("add-file", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status
        let status = response.status();

        if status != StatusCode::OK {
            let response_text = response.text().await?;
            panic!(
                "Expected response code Ok, got {}. Response was:\n{}",
                status, response_text
            )
        }

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["success"], true);
        assert_eq!(response_body["message"], "File added successfully");
        assert_eq!(response_body["file_path"], file_path);

        wait_for_commit(test_repo_path_buf.clone(), &commit_message, None).await?;

        // Verify the file was created on disk
        assert!(
            file_exists_in_repo(&test_repo_path_buf, file_path),
            "File was not created on disk"
        );

        // Verify the subdirectory was created
        assert!(
            test_repo_path_buf.join("subdir").exists(),
            "Subdirectory was not created"
        );

        // Verify the file content
        let file_content =
            read_file_content(&test_repo_path_buf, file_path).expect("Failed to read file content");
        assert_eq!(file_content, content, "File content doesn't match");
        // Verify the commit message
        let commit_msg =
            get_latest_commit(&test_repo_path_buf).expect("Failed to get latest commit");
        assert!(
            commit_msg.contains(&commit_message),
            "Commit message doesn't match"
        );

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // Test case: Error in git operation
    #[tokio::test]
    async fn test_add_file_with_git_error() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;
        // Don't initialize git repository - this should cause the commit to fail
        // make_git_commit_fail(repo_path_buf.clone()).await?;

        let config = build_test_config(&repo_path_buf, port);
        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Create authentication headers
        let payload = json!({
            "file_path": "my-new-file",
            "content": "This should fail"
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload_string).await;

        // Send the request with authentication headers
        let response = client
            .post(url_for("add-file", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert!(
            response_body["error"]
                .as_str()
                .unwrap()
                .contains("could not find repository at")
        );

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // Test case: Authentication required for API endpoints
    #[tokio::test]
    async fn test_authentication_required() -> Result<()> {
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

        // Try to send a request without authentication headers
        let response = client
            .post(url_for("add-file", port))
            .json(&json!({
                "file_path": "test_file.txt",
                "content": "This should fail due to missing authentication"
            }))
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status - should be 401 Unauthorized
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Parse the response body
        let response_body: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(response_body["error"], "Missing authentication headers");

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // Test case: Verify request ID header is present in response
    #[tokio::test]
    async fn test_request_id_tracing() -> Result<()> {
        // Create a temporary directory for the git repository
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let repo_path_buf = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;
        // Initialize git repository
        init_git_repo(&repo_path_buf).expect("Failed to initialize git repo");

        let config = build_test_config(&repo_path_buf, port);

        // Start the server in the background
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        // Create a client to send requests
        let client = reqwest::Client::new();

        // Define the file to add
        let file_path = "test_request_id.txt";
        let content = "Testing request ID tracing";

        // Create authentication headers
        let payload = json!({
            "file_path": file_path,
            "content": content
        });
        let payload_string = payload.to_string();
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload_string).await;

        // Send the request to add the file with authentication headers
        let response = client
            .post(url_for("add-file", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send request");

        // Check the response status
        assert_eq!(response.status(), StatusCode::OK);

        // Verify request ID header is present in response
        let request_id = response
            .headers()
            .get("x-request-id")
            .expect("x-request-id header should be present in response")
            .to_str()
            .expect("x-request-id header should be valid UTF-8");

        // Verify request ID is not empty
        assert!(!request_id.is_empty(), "x-request-id should not be empty");

        // Clean up - abort the server task
        server_handle.abort();
        Ok(())
    }

    // ============================================================================
    // Structured Logging Tests
    // ============================================================================

    fn setup_file_logging(
        temp_dir: &Path,
    ) -> Result<(
        WorkerGuard,
        std::path::PathBuf,
        tracing::subscriber::DefaultGuard,
    )> {
        let log_path = temp_dir.join("test.log");
        let appender = tracing_appender::rolling::never(temp_dir, "test.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(appender);

        let subscriber = Registry::default()
            .with(EnvFilter::new("info"))
            .with(fmt::layer().json().with_writer(non_blocking));

        let default_guard = tracing::subscriber::set_default(subscriber);

        Ok((guard, log_path, default_guard))
    }

    // Note: This test validates the basic setup of our logging (json format, timestamp,...).
    // It was generated by AI, and if it proves unnecessary can be removed.
    #[tokio::test]
    async fn test_structured_logging_json_format() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;

        tracing::info!(test_event = "json_validation", "Test info message");
        tracing::warn!(test_event = "json_validation", "Test warning message");
        tracing::error!(test_event = "json_validation", "Test error message");

        drop(_guard);

        let content = fs::read_to_string(&log_path)?;
        let log_lines = parse_log_lines(&content)?;

        assert_eq!(log_lines.len(), 3, "Should have 3 log entries");

        for entry in log_lines {
            assert!(entry.is_object(), "Each line must be a JSON object");
            assert!(entry.get("timestamp").is_some(), "Must have timestamp");
            assert!(entry.get("level").is_some(), "Must have level");
            assert!(
                entry.get("message").is_some()
                    || entry.get("fields").and_then(|f| f.get("message")).is_some(),
                "Must have message"
            );
            assert!(
                entry
                    .get("test_event")
                    .or_else(|| entry.get("fields").and_then(|f| f.get("test_event")))
                    .is_some(),
                "Must have our test_event field"
            );
        }

        Ok(())
    }

    // This test validates that a request sent to the server is logged
    #[tokio::test]
    async fn test_request_id_logging_flow() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;

        let port = get_random_port().await?;
        let repo_path = temp_dir.path().join("repo");
        init_git_repo(&repo_path)?;
        let config = build_test_config(&repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();
        let payload = json!({"file_path": "test.txt", "content": "test"});
        let TestAuthHeaders {
            timestamp,
            nonce,
            signature,
            public_key,
        } = create_auth_headers(&payload.to_string()).await;

        let response = client
            .post(url_for("add-file", port))
            .header(HEADER_TIMESTAMP, timestamp)
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(HEADER_PUBLIC_KEY, public_key)
            .json(&payload)
            .send()
            .await?;

        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|h| h.to_str().ok())
            .expect("Should have request ID");

        // FIXME: sleeping to let server handle the request
        // Removing this sleep, I've had this test fail once
        // which makes it hard to validate if another way to
        // wait works (eg drop the guard before aborting)
        tokio::time::sleep(Duration::from_millis(500)).await;

        server_handle.abort();
        drop(_guard);

        wait_for_log_entry_with_request_id(&log_path, request_id).await?;

        let content = fs::read_to_string(&log_path)?;
        let log_lines = parse_log_lines(&content)?;

        let entries_with_request_id: Vec<_> = log_lines
            .iter()
            .filter(|entry| {
                entry
                    .get("request_id")
                    .or_else(|| entry.get("fields").and_then(|f| f.get("request_id")))
                    .and_then(|v| v.as_str())
                    == Some(request_id)
            })
            .collect();

        //dbg!(&entries_with_request_id);
        //dbg!(log_path);
        //test_helpers::pause();
        assert!(
            !entries_with_request_id.is_empty(),
            "Should have at least 1 log entry with request_id"
        );

        let levels: Vec<_> = entries_with_request_id
            .iter()
            .filter_map(|e| e.get("level").and_then(|l| l.as_str()))
            .collect();
        assert!(levels.contains(&"INFO"), "Should have INFO level entries");

        Ok(())
    }

    // This test was generated by AI. It validates our tracing setup logs errors.
    // If it proves unnecessary, it can be removed.
    #[tokio::test]
    async fn test_error_logging_structure() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let (_guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;

        tracing::error!(
            error_type = "validation",
            error_code = "invalid_path",
            "Test error message"
        );

        drop(_guard);

        let content = fs::read_to_string(&log_path)?;
        let log_lines = parse_log_lines(&content)?;

        let error_entry = log_lines.first().expect("Should have error entry");

        assert_eq!(
            error_entry.get("level").and_then(|l| l.as_str()),
            Some("ERROR"),
            "Level should be ERROR"
        );
        assert_eq!(
            error_entry
                .get("error_type")
                .or_else(|| error_entry.get("fields").and_then(|f| f.get("error_type")))
                .and_then(|t| t.as_str()),
            Some("validation"),
            "Should have error_type field"
        );
        assert_eq!(
            error_entry
                .get("error_code")
                .or_else(|| error_entry.get("fields").and_then(|f| f.get("error_code")))
                .and_then(|c| c.as_str()),
            Some("invalid_path"),
            "Should have error_code field"
        );
        assert_eq!(
            error_entry
                .get("message")
                .or_else(|| error_entry.get("fields").and_then(|f| f.get("message")))
                .and_then(|m| m.as_str()),
            Some("Test error message"),
            "Should have message"
        );

        Ok(())
    }
}
