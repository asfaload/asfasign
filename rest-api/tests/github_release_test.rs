pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use constants::{SIGNERS_DIR, SIGNERS_FILE};
    use rest_api::server::run_server;
    use rest_api_test_helpers::{build_test_config, get_random_port, url_for, wait_for_server};
    use rest_api_types::{RegisterReleaseRequest, rustls::setup_crypto_provider};
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::Duration;

    #[cfg(feature = "test-utils")]
    use rest_api_test_helpers::print_logs;
    #[cfg(feature = "test-utils")]
    use serde_json::Value;

    #[tokio::test]
    #[cfg(feature = "test-utils")]
    async fn test_register_github_release_endpoint() -> Result<()> {
        // Upgrading octocrab to version 0.49.5 from 0.39 caused an error for this test:
        //    Could not automatically determine the process-level CryptoProvider from Rustls crate features.
        //    Call CryptoProvider::install_default() before this point to select a provider manually, or make sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.
        //    See the documentation of the CryptoProvider type for more information.
        // The only solution that worked was to define and call this function.
        setup_crypto_provider();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();
        print_logs();

        // Initialize a git repository for the test
        git2::Repository::init(&git_repo_path).expect("Failed to initialize git repository");

        let port = get_random_port().await?;

        let signers_dir = git_repo_path
            .join("github.com/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).expect("Failed to create signers directory");

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": [
                {
                    "public_key": "test_key",
                    "name": "Test Signer"
                }
            ]
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .expect("Failed to write signers file");

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // Validate the URL through RegisterReleaseRequest::new()
        let _ = RegisterReleaseRequest::new(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0".to_string(),
        )?;

        // Manually construct JSON to ensure proper serialization
        let json_body = serde_json::json!({
            "release_url": "https://github.com/testowner/testrepo/releases/tag/v1.0.0"
        });

        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .post(url_for("release", port))
                .json(&json_body)
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("HTTP error: {}", e))?;

        let status = response.status();

        let response_json: Value = response.json().await?;

        assert_eq!(status, StatusCode::OK, "Expected 200 OK status");
        assert_eq!(response_json["success"], true, "Expected success=true");
        assert!(
            response_json["index_file_path"].is_string(),
            "Expected index_file_path to be a string"
        );

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_register_github_release_no_signers_file() -> Result<()> {
        setup_crypto_provider();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // Validate the URL through RegisterReleaseRequest::new()
        let _ = RegisterReleaseRequest::new(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0".to_string(),
        )?;

        // Manually construct JSON to ensure proper serialization
        let json_body = serde_json::json!({
            "release_url": "https://github.com/testowner/testrepo/releases/tag/v1.0.0"
        });

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .post(url_for("release", port))
                .json(&json_body)
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

        let status = response.status();
        let text = response.text().await?;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            text.contains("signers"),
            "Expected error about signers file, got: {}",
            text
        );

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_register_github_release_invalid_url_format() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let signers_dir = git_repo_path
            .join("github.com/testowner/testrepo")
            .join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).expect("Failed to create signers directory");

        let signers_json = r#"{
            "version": 1,
            "required_signers": 1,
            "signers": []
        }"#;
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
            .expect("Failed to write signers file");

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // Send invalid URL directly as JSON to test validation
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .post(url_for("release", port))
                .json(&serde_json::json!({
                    "release_url": "invalid"
                }))
                .send(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))??;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        server_handle.abort();
        Ok(())
    }
}
