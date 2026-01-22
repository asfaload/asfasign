pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE};
    use rest_api::server::run_server;
    use rest_api_test_helpers::{build_test_config, get_random_port, url_for, wait_for_server};
    use rest_api_types::RegisterGitHubReleaseRequest;
    use serde_json::Value;
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_register_github_release_endpoint() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let signers_dir = git_repo_path.join("testowner/testrepo").join(SIGNERS_DIR);
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

        // Validate the URL through RegisterGitHubReleaseRequest::new()
        let _ = RegisterGitHubReleaseRequest::new(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0".to_string(),
        )?;

        // Manually construct JSON to ensure proper serialization
        let json_body = serde_json::json!({
            "release_url": "https://github.com/testowner/testrepo/releases/tag/v1.0.0"
        });

        let response = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .post(url_for("github-release", port))
                .json(&json_body)
                .send(),
        )
        .await;

        match response {
            Ok(Ok(resp)) => {
                let status = resp.status();
                let response_json: Value = resp.json().await?;
                match status {
                    StatusCode::OK => {
                        assert_eq!(response_json["success"], true);
                        assert!(response_json["index_file_path"].is_string());
                    }
                    StatusCode::INTERNAL_SERVER_ERROR => {
                        if response_json.get("success").is_some() {
                            assert_eq!(response_json["success"], false);
                            assert!(response_json["message"].is_string());
                        } else {
                            assert!(
                                response_json["error"].as_str().unwrap().contains("GitHub")
                                    || response_json["error"].as_str().unwrap().contains("API")
                                    || response_json["error"].as_str().unwrap().contains("Timeout")
                            );
                        }
                    }
                    status_code => {
                        panic!(
                            "Expected 200 or 500 status code, got {}: {}",
                            status_code, response_json
                        );
                    }
                }
            }
            Ok(Err(e)) => {
                if e.is_timeout() || e.is_connect() {
                    println!(
                        "Request timed out or failed to connect (expected behavior for GitHub API call in tests)"
                    );
                } else {
                    return Err(e.into());
                }
            }
            Err(_) => {
                println!("Request timed out (expected behavior for GitHub API call in tests)");
            }
        }

        server_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_register_github_release_no_signers_file() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let git_repo_path = temp_dir.path().to_path_buf();

        let port = get_random_port().await?;

        let config = build_test_config(&git_repo_path, port);

        let config_clone = config.clone();
        let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
        wait_for_server(&config, None).await?;

        let client = reqwest::Client::new();

        // Validate the URL through RegisterGitHubReleaseRequest::new()
        let _ = RegisterGitHubReleaseRequest::new(
            "https://github.com/testowner/testrepo/releases/tag/v1.0.0".to_string(),
        )?;

        // Manually construct JSON to ensure proper serialization
        let json_body = serde_json::json!({
            "release_url": "https://github.com/testowner/testrepo/releases/tag/v1.0.0"
        });

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .post(url_for("github-release", port))
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

        let signers_dir = git_repo_path.join("testowner/testrepo").join(SIGNERS_DIR);
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
                .post(url_for("github-release", port))
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
