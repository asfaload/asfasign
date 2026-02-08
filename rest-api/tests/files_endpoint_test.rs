use anyhow::Result;
use reqwest::Client;
use rest_api::server::run_server;
use rest_api_test_helpers::{build_test_config, get_random_port, init_git_repo, wait_for_server};
use std::fs;
use tempfile::TempDir;

/// Test that the /files/{file_path} endpoint returns file content
#[tokio::test]
async fn test_get_file_success() -> Result<()> {
    // Setup temp directory and git repo
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    // Create a test file
    let test_file_path = "github.com/test/project/artifact.txt";
    let full_path = repo_path.join(test_file_path);
    fs::create_dir_all(full_path.parent().unwrap())?;
    fs::write(&full_path, "test file content")?;

    // Configure and start server
    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    // Make request to fetch file
    let client = Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/v1/files/{}",
            port, test_file_path
        ))
        .send()
        .await?;

    // Verify response
    assert_eq!(response.status(), 200);
    let content = response.bytes().await?;
    assert_eq!(content, "test file content".as_bytes());

    // Cleanup
    server_handle.abort();
    Ok(())
}

/// Test that the /files/{file_path} endpoint returns 404 for non-existent files
#[tokio::test]
async fn test_get_file_not_found() -> Result<()> {
    // Setup temp directory and git repo
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    // Configure and start server
    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    // Make request to fetch non-existent file
    let client = Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/files/github.com/test/project/nonexistent.txt",
            port
        ))
        .send()
        .await?;

    // Verify 404 response
    assert_eq!(response.status(), 404);

    // Cleanup
    server_handle.abort();
    Ok(())
}

/// Test that the /files/{file_path} endpoint handles path traversal attempts
#[tokio::test]
async fn test_get_file_path_traversal_blocked() -> Result<()> {
    // Setup temp directory and git repo
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().to_path_buf();
    init_git_repo(&repo_path)?;

    // Create a file outside the expected path (in parent directory)
    let secret_file = repo_path.parent().unwrap().join("secret.txt");
    fs::write(&secret_file, "secret content")?;

    // Configure and start server
    let port = get_random_port().await?;
    let config = build_test_config(&repo_path, port);
    let config_clone = config.clone();
    let server_handle = tokio::spawn(async move { run_server(&config_clone).await });
    wait_for_server(&config, None).await?;

    // Attempt path traversal
    let client = Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/v1/files/../secret.txt", port))
        .send()
        .await?;

    // Verify path traversal is blocked (returns error, not the secret file)

    assert_eq!(response.status(), 404, "Path traversal should be blocked");
    // We test the url returned to detect any change of behaviour in Axum
    // As you see, axum sanitises the input, removing the ..
    // With /v1/files/../secret.txt, the .. resolves to /v1/secret.txt
    use regex::Regex;
    let re = Regex::new(r"http://127.0.0.1:\d+/v1/secret.txt").unwrap();
    assert!(re.is_match(response.url().as_str()));
    // Cleanup
    server_handle.abort();
    Ok(())
}
