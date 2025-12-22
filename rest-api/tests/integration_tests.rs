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
        build_env, file_exists_in_repo, get_latest_commit, get_random_port, init_git_repo,
        read_file_content, url_for, wait_for_commit, wait_for_server,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

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
        let auth_signature = AuthSignature::new(auth_info, secret_key).unwrap();

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

        let env = build_env(&repo_path_buf, port);

        // Start the server in the background
        let env_clone = env.clone();
        let server_handle = tokio::spawn(async move { run_server(&env_clone).await });
        wait_for_server(&env, None).await?;

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

        let env = build_env(&repo_path_buf, port);
        // Start the server in the background
        let env_clone = env.clone();
        let server_handle = tokio::spawn(async move { run_server(&env_clone).await });
        wait_for_server(&env, None).await?;

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
        let env = build_env(&repo_path_buf, port);
        // Start the server in the background
        let env_clone = env.clone();
        let server_handle = tokio::spawn(async move { run_server(&env_clone).await });
        wait_for_server(&env, None).await?;

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

        let env = build_env(&repo_path_buf, port);
        // Start the server in the background
        let env_clone = env.clone();
        let server_handle = tokio::spawn(async move { run_server(&env_clone).await });
        wait_for_server(&env, None).await?;

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
        let env = build_env(&repo_path_buf, port);
        // Start the server in the background
        let env_clone = env.clone();
        let server_handle = tokio::spawn(async move { run_server(&env_clone).await });
        wait_for_server(&env, None).await?;

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
}
