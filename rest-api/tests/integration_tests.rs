#[cfg(test)]
pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use rest_api::file_auth::github::get_project_normalised_paths;
    use rest_api::server::run_server;
    use rest_api_auth::{HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP};
    use rest_api_test_helpers::parse_log_lines;
    use rest_api_test_helpers::setup_file_logging;
    use rest_api_test_helpers::wait_for_log_entry_with_request_id;
    use rest_api_test_helpers::{
        TestAuthHeaders, build_test_config, create_auth_headers, file_exists_in_repo,
        get_latest_commit, get_random_port, init_git_repo, read_file_content,
        send_add_file_request, url_for, wait_for_commit, wait_for_server,
    };
    #[cfg(feature = "test-utils")]
    use rest_api_test_helpers::{file_exists_in_latest_commit, file_is_tracked_in_git};
    use serde_json::{Value, json};
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::Duration;

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
        let response = send_add_file_request(&client, port, &payload).await;

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
        let response = send_add_file_request(&client, port, &payload).await;

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
        let response = send_add_file_request(&client, port, &payload).await;
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
        let response = send_add_file_request(&client, port, &payload).await;

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

        assert!(
            !entries_with_request_id.is_empty(),
            "Should have at least 1 log entry with request_id"
        );

        let levels: Vec<_> = entries_with_request_id
            .iter()
            .filter_map(|e| e.get("level").and_then(|l| l.as_str()))
            .collect();
        assert!(levels.contains(&"INFO"), "Should have INFO level entries");

        server_handle.abort();

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

    // ============================================================================
    // Register Repo Integration Tests
    //
    // NOTE: These tests establish the integration test infrastructure pattern for
    // register_repo endpoint. Due to architectural limitations where
    // GitHubProjectAuthenticator only accepts github.com URLs and httpmock can
    // only mock localhost, these tests require additional mocking infrastructure
    // or dependency injection to fully pass. This provides the foundation for
    // such enhancements.
    // ============================================================================

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_register_repo_success() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadKeyPairTrait;
        use features_lib::AsfaloadPublicKeyTrait;
        use git2::Repository;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;
        use rest_api_types::RegisterRepoResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        Repository::init(&git_repo_path)?;

        let mock_server = httpmock::MockServer::start();

        let test_password = "test_password";
        let key_pair = features_lib::AsfaloadKeyPairs::new(test_password)?;
        let public_key = key_pair.public_key();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(signers_json);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .json(&RegisterRepoRequest {
                signers_file_url: signers_url,
            })
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<RegisterRepoResponse>().await?;
        assert!(response_body.success);
        assert_eq!(response_body.project_id, "github.com/owner/repo");
        assert_eq!(
            response_body.message,
            "Project registered successfully. Collect signatures to activate."
        );
        assert_eq!(response_body.required_signers.len(), 1);
        assert_eq!(response_body.required_signers[0], public_key.to_base64());
        assert_eq!(response_body.signature_submission_url, "/v1/signatures");

        mock.assert();
        server_handle.abort();

        Ok(())
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_register_repo_already_exists() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadKeyPairTrait;
        use git2::Repository;
        use httpmock::Method;
        use rest_api_types::RegisterRepoRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        Repository::init(&git_repo_path)?;

        let project_dir = git_repo_path.join("github.com/owner/repo");
        tokio::fs::create_dir_all(&project_dir).await?;

        let mock_server = httpmock::MockServer::start();

        let test_password = "test_password";
        let key_pair = features_lib::AsfaloadKeyPairs::new(test_password)?;
        let public_key = key_pair.public_key();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let mock = mock_server.mock(|when, then| {
            when.method(Method::GET)
                .path("/owner/repo/main/signers.json");
            then.status(200).body(signers_json);
        });

        let signers_url = format!("{}/owner/repo/main/signers.json", mock_server.url(""));

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .json(&RegisterRepoRequest {
                signers_file_url: signers_url,
            })
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_body: serde_json::Value = response.json().await?;
        assert!(response_body.get("error").is_some());

        // project existence is detected before sending out request
        mock.assert_hits(0);

        server_handle.abort();

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_cleans_up_on_repo_handler_failure() -> Result<(), anyhow::Error> {
        use constants::PENDING_SIGNERS_DIR;
        use features_lib::AsfaloadKeyPairTrait;
        use git2::Repository;
        use kameo::actor::Spawn;
        use rest_api::file_auth::actors::git_actor::GitActor;
        use rest_api::file_auth::actors::signers_initialiser::{
            CleanupSignersRequest, InitialiseSignersRequest, SignersInitialiser,
        };
        use std::fs;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        let git_repo_path_clone = git_repo_path.clone();

        Repository::init(&git_repo_path)?;

        let test_password = "test_password";
        let key_pair = features_lib::AsfaloadKeyPairs::new(test_password)?;

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![key_pair.public_key().clone()], 1),
        )?;

        let project_id = "github.com/test/repo";
        let project_dir = git_repo_path.join(project_id);
        let signers_pending_dir = project_dir.join("asfaload.signers.pending");
        let signers_file_path = signers_pending_dir.join("index.json");
        let history_file_path = project_dir.join("asfaload.signers.history.json");
        let project_path = get_project_normalised_paths(&git_repo_path, project_id).await?;

        let signers_initialiser = SignersInitialiser::spawn(());
        let init_request = InitialiseSignersRequest {
            project_path,
            signers_config: signers_config.clone(),
            git_repo_path: git_repo_path.clone(),
            request_id: "test-123".to_string(),
        };

        let init_result = signers_initialiser.ask(init_request).await?;

        assert!(
            signers_file_path.exists(),
            "Signers file should exist after initialization"
        );
        assert!(
            history_file_path.exists(),
            "History file should exist after initialization"
        );
        assert!(
            signers_pending_dir.exists(),
            "Pending directory should exist after initialization"
        );

        let git_dir = git_repo_path.join(".git");
        fs::remove_dir_all(&git_dir)?;

        let git_actor = GitActor::spawn(git_repo_path_clone.clone());

        let write_commit_request = rest_api::file_auth::actors::git_actor::CommitFile {
            file_paths: vec![init_result.project_path.clone()],
            commit_message: "commit of test-123".to_string(),
            request_id: "test-123".to_string(),
        };

        let result = git_actor.ask(write_commit_request).await;

        assert!(
            result.is_err(),
            "RepoHandler should fail when git repo is corrupted"
        );

        let pending_dir = init_result.project_path.join(PENDING_SIGNERS_DIR).await?;

        let cleanup_request = CleanupSignersRequest {
            signers_file_path: init_result.signers_file_path.clone(),
            history_file_path: init_result.history_file_path.clone(),
            pending_dir,
            request_id: "test-123".to_string(),
        };

        let cleanup_result = signers_initialiser.ask(cleanup_request).await;

        assert!(cleanup_result.is_ok(), "Cleanup should succeed");

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            !signers_file_path.exists(),
            "Signers file should be cleaned up after failure"
        );
        assert!(
            !history_file_path.exists(),
            "History file should be cleaned up after failure"
        );
        assert!(
            !signers_pending_dir.exists(),
            "Pending directory should be cleaned up after failure"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_register_repo_errors_dont_leak_internal_details() -> Result<(), anyhow::Error> {
        use git2::Repository;
        use rest_api_types::RegisterRepoRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");
        Repository::init(&git_repo_path)?;

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        let response = client
            .post(format!("http://localhost:{}/v1/register_repo", port))
            .json(&RegisterRepoRequest {
                signers_file_url: "https://github.com/owner/repo/blob/main/nonexistent.json"
                    .to_string(),
            })
            .send()
            .await?;

        let response_body: serde_json::Value = response.json().await?;

        let error_msg = response_body
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("");

        assert!(
            !error_msg.contains("ActorOperationFailed"),
            "Should not expose actor errors"
        );
        assert!(!error_msg.contains("/"), "Should not expose file paths");
        assert!(
            error_msg.len() < 200,
            "Error message should be concise: {}",
            error_msg
        );

        server_handle.abort();

        Ok(())
    }

    // ============================================================================
    // Signature Collection Integration Tests
    // ============================================================================

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_submit_signature_for_artifact_file() -> Result<(), anyhow::Error> {
        use features_lib::{
            AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
            AsfaloadSignatureTrait, sha512_for_file,
        };
        use rest_api_types::SubmitSignatureRequest;
        use rest_api_types::SubmitSignatureResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        git2::Repository::init(&git_repo_path)?;

        // Create signers config
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let public_key = key_pair.public_key();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        // Create signers directory and file
        let signers_dir = git_repo_path.join("asfaload.signers");
        tokio::fs::create_dir_all(&signers_dir).await?;
        tokio::fs::write(signers_dir.join("index.json"), &signers_json).await?;

        // Create artifact file in a subdirectory
        let artifact_file = git_repo_path.join("releases/release.txt");
        tokio::fs::create_dir_all(artifact_file.parent().unwrap()).await?;
        tokio::fs::write(&artifact_file, "artifact content").await?;

        // Create the signature
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let app_state = rest_api::state::init_state(git_repo_path.clone(), config);

        let inner = axum::Router::new().route(
            "/signatures",
            axum::routing::post(rest_api::handlers::submit_signature_handler),
        );
        let app = axum::Router::new().nest("/v1", inner).with_state(app_state);

        let server = axum_test::TestServer::new(app)?;

        let response = server
            .post("/v1/signatures")
            .json(&SubmitSignatureRequest {
                file_path: "releases/release.txt".to_string(),
                public_key: public_key.to_base64(),
                signature: signature.to_base64(),
            })
            .await;

        response.assert_status_ok();

        let response_body = response.json::<SubmitSignatureResponse>();

        assert!(response_body.is_complete);

        // Wait for the commit to be processed
        let expected_commit_message = format!(
            "completed signature collection for {}",
            "releases/release.txt"
        );
        wait_for_commit(git_repo_path.clone(), &expected_commit_message, None).await?;

        // Verify the commit was created with correct message
        let commit_msg = get_latest_commit(&git_repo_path)?;
        assert!(
            commit_msg.contains(&expected_commit_message),
            "Commit message doesn't match expected format"
        );

        // Verify the signature file was created
        let signature_file_path = format!("{}.signatures.json", artifact_file.display());
        assert!(
            git_repo_path.join(signature_file_path).exists(),
            "Signature file should be created"
        );

        assert!(
            file_exists_in_latest_commit(&git_repo_path, "releases/release.txt.signatures.json")?,
            "Signature file should be in the latest git commit (BUG: files not being committed)"
        );

        // Verify the signature file is tracked in git
        assert!(
            file_is_tracked_in_git(&git_repo_path, "releases/release.txt.signatures.json")?,
            "Signature file should be tracked in git"
        );

        Ok(())
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_submit_signature_for_signers_file() -> Result<(), anyhow::Error> {
        use constants::PENDING_SIGNERS_DIR;
        use constants::SIGNATURES_SUFFIX;
        use constants::SIGNERS_DIR;
        use constants::SIGNERS_FILE;
        use features_lib::{
            AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
            AsfaloadSignatureTrait, sha512_for_file,
        };
        use rest_api_types::SubmitSignatureRequest;
        use rest_api_types::SubmitSignatureResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let public_key = key_pair.public_key();

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        let project_dir = git_repo_path.join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let complete_dir = project_dir.join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&pending_dir).await?;
        let pending_signers_path = pending_dir.join(SIGNERS_FILE);
        let complete_signers_path = complete_dir.join(SIGNERS_FILE);
        tokio::fs::write(pending_signers_path.clone(), &signers_json).await?;

        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;

        let port = get_random_port().await?;
        init_git_repo(&git_repo_path)?;
        let config = build_test_config(&git_repo_path, port);
        let config_clone = config.clone();
        let (guard, log_path, _subscriber_guard) = setup_file_logging(temp_dir.path())?;
        println!("Logs of server available at {}", log_path.display());
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();
        let payload = json!(&SubmitSignatureRequest {
            file_path: "github.com/test/repo/asfaload.signers.pending/index.json".to_string(),
            public_key: public_key.to_base64(),
            signature: signature.to_base64(),
        });
        let response = client
            .post(url_for("signatures", port))
            .json(&payload)
            .send()
            .await?;

        assert_eq!(response.status(), StatusCode::OK);

        let response_body = response.json::<SubmitSignatureResponse>().await?;

        assert!(
            response_body.is_complete,
            "Signers file signature should complete"
        );

        // Wait for the commit to be processed
        let expected_commit_message = format!(
            "completed signature collection for {}/{}",
            "github.com/test/repo", SIGNERS_DIR
        );

        wait_for_commit(git_repo_path.clone(), &expected_commit_message, None).await?;

        // Verify the commit was created with correct message
        let commit_msg = get_latest_commit(&git_repo_path)?;
        assert!(
            commit_msg.contains(&expected_commit_message),
            "Commit message doesn't match expected format"
        );

        let signature_file = format!("{}.{}", complete_signers_path.display(), SIGNATURES_SUFFIX);
        let signature_file = std::path::PathBuf::from(signature_file);
        assert!(
            signature_file.exists(),
            "Signature file should be created as complete"
        );

        // Verify the signature file is tracked in git
        let signature_file_path_string = signature_file
            .strip_prefix(&git_repo_path)?
            .to_string_lossy()
            .to_string();
        let signature_file_path = signature_file_path_string.as_str();
        drop(guard);
        assert!(
            file_is_tracked_in_git(&git_repo_path, signature_file_path)?,
            "Signature file should be tracked in git"
        );

        // Verify the signature file is in the latest git commit
        assert!(
            file_exists_in_latest_commit(&git_repo_path, signature_file_path)?,
            "Signature file should be in the latest git commit"
        );

        server_handle.abort();
        Ok(())
    }

    //#[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_get_signature_status() -> Result<(), anyhow::Error> {
        use features_lib::AsfaloadKeyPairTrait;
        use rest_api_types::GetSignatureStatusResponse;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        git2::Repository::init(&git_repo_path)?;

        // Create signers config
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            1,
            (vec![key_pair.public_key().clone()], 1),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        // Create artifact file (without signatures)
        let signers_dir = git_repo_path.join("asfaload.signers");
        tokio::fs::create_dir_all(&signers_dir).await?;
        tokio::fs::write(signers_dir.join("index.json"), &signers_json).await?;

        let artifact_file = git_repo_path.join("data.txt");
        tokio::fs::write(&artifact_file, "test data").await?;

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let app_state = rest_api::state::init_state(git_repo_path.clone(), config);

        let inner = axum::Router::new().route(
            "/signatures/{*file_path}",
            axum::routing::get(rest_api::handlers::get_signature_status_handler),
        );
        let app = axum::Router::new().nest("/v1", inner).with_state(app_state);

        let server = axum_test::TestServer::new(app)?;

        let response = server.get("/v1/signatures/data.txt").await;

        response.assert_status_ok();

        let status_body = response.json::<GetSignatureStatusResponse>();

        assert_eq!(status_body.file_path, "data.txt");
        assert!(!status_body.is_complete);

        Ok(())
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_submit_partial_signature() -> Result<(), anyhow::Error> {
        use constants::SIGNERS_DIR;
        use constants::SIGNERS_FILE;
        use features_lib::{
            AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
            AsfaloadSignatureTrait, sha512_for_file,
        };
        use rest_api_test_helpers::print_logs;
        use rest_api_types::SubmitSignatureRequest;
        use rest_api_types::SubmitSignatureResponse;

        print_logs();
        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        git2::Repository::init(&git_repo_path)?;

        // Create signers config with 2 signers, threshold 2
        let key_pair1 = features_lib::AsfaloadKeyPairs::new("test_password1")?;
        let key_pair2 = features_lib::AsfaloadKeyPairs::new("test_password2")?;

        let signers_config = signers_file_types::SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    key_pair1.public_key().clone(),
                    key_pair2.public_key().clone(),
                ],
                2,
            ),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        // Create signers directory and file
        let signers_dir = git_repo_path.join(SIGNERS_DIR);
        tokio::fs::create_dir_all(&signers_dir).await?;
        tokio::fs::write(signers_dir.join(SIGNERS_FILE), &signers_json).await?;

        // Create artifact file in a subdirectory
        let artifact_file = git_repo_path.join("releases/release.txt");
        tokio::fs::create_dir_all(artifact_file.parent().unwrap()).await?;
        tokio::fs::write(&artifact_file, "artifact content").await?;

        // Create signatures
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key1 = key_pair1.secret_key("test_password1")?;
        let signature1 = secret_key1.sign(&digest)?;
        let secret_key2 = key_pair2.secret_key("test_password2")?;
        let signature2 = secret_key2.sign(&digest)?;

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let app_state = rest_api::state::init_state(git_repo_path.clone(), config);

        let inner = axum::Router::new().route(
            "/signatures",
            axum::routing::post(rest_api::handlers::submit_signature_handler),
        );
        let app = axum::Router::new().nest("/v1", inner).with_state(app_state);

        let server = axum_test::TestServer::new(app)?;

        // Submit first signature (should be partial)
        let response = server
            .post("/v1/signatures")
            .json(&SubmitSignatureRequest {
                file_path: "releases/release.txt".to_string(),
                public_key: key_pair1.public_key().to_base64(),
                signature: signature1.to_base64(),
            })
            .await;

        response.assert_status_ok();
        let response_body = response.json::<SubmitSignatureResponse>();
        assert!(
            !response_body.is_complete,
            "First signature should not complete"
        );

        // Wait for partial commit
        let expected_commit_message = "added partial signature for releases/release.txt";
        wait_for_commit(git_repo_path.clone(), expected_commit_message, None).await?;

        // Verify commit message
        let commit_msg = get_latest_commit(&git_repo_path)?;
        assert!(
            commit_msg.contains(expected_commit_message),
            "Partial commit message doesn't match"
        );

        // Submit second signature (should complete)
        let response2 = server
            .post("/v1/signatures")
            .json(&SubmitSignatureRequest {
                file_path: "releases/release.txt".to_string(),
                public_key: key_pair2.public_key().to_base64(),
                signature: signature2.to_base64(),
            })
            .await;

        response2.assert_status_ok();
        let response_body2 = response2.json::<SubmitSignatureResponse>();
        assert!(
            response_body2.is_complete,
            "Second signature should complete"
        );

        // Wait for completion commit
        let expected_completion_message = "completed signature collection for releases/release.txt";
        wait_for_commit(git_repo_path.clone(), expected_completion_message, None).await?;

        // Verify completion commit message
        let commit_msg2 = get_latest_commit(&git_repo_path)?;
        assert!(
            commit_msg2.contains(expected_completion_message),
            "Completion commit message doesn't match"
        );

        // Verify the signature file is tracked in git
        assert!(
            file_is_tracked_in_git(&git_repo_path, "releases/release.txt.signatures.json")?,
            "Signature file should be tracked in git"
        );

        // Verify the signature file is in the latest git commit
        assert!(
            file_exists_in_latest_commit(&git_repo_path, "releases/release.txt.signatures.json")?,
            "Signature file should be in the latest git commit"
        );

        Ok(())
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_submit_signature_file_not_found() -> Result<(), anyhow::Error> {
        use features_lib::{AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait};
        use rest_api_types::SubmitSignatureRequest;

        let temp_dir = TempDir::new()?;
        let git_repo_path = temp_dir.path().join("git_repo");

        git2::Repository::init(&git_repo_path)?;

        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let public_key = key_pair.public_key();

        let port = get_random_port().await?;
        let config = build_test_config(&git_repo_path, port);
        let app_state = rest_api::state::init_state(git_repo_path.clone(), config);

        let inner = axum::Router::new().route(
            "/signatures",
            axum::routing::post(rest_api::handlers::submit_signature_handler),
        );
        let app = axum::Router::new().nest("/v1", inner).with_state(app_state);

        let server = axum_test::TestServer::new(app)?;

        let response = server
            .post("/v1/signatures")
            .json(&SubmitSignatureRequest {
                file_path: "nonexistent.txt".to_string(),
                public_key: public_key.to_base64(),
                signature: "invalid_signature".to_string(),
            })
            .await;

        response.assert_status(axum::http::StatusCode::BAD_REQUEST);

        let body: serde_json::Value = response.json();

        assert!(body.get("error").is_some());
        assert!(
            body["error"]
                .as_str()
                .unwrap_or("")
                .contains("File not found")
        );

        Ok(())
    }
}
