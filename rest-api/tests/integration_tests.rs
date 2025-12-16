use anyhow::Result;
use axum::http::StatusCode;
use rest_api::environment::Environment;
use rest_api::{error::ApiError, server::run_server};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tokio::time::Instant;

//
// Helper function to initialize a git repository in a temporary directory
fn init_git_repo(repo_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize git repo
    let output = Command::new("git").arg("init").arg(repo_path).output()?;

    if !output.status.success() {
        return Err(format!(
            "git init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    // Set user name and email for commits
    let output = Command::new("git")
        .args([
            "-C",
            repo_path.to_str().unwrap(),
            "config",
            "user.name",
            "Test User",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "git config user.name failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let output = Command::new("git")
        .args([
            "-C",
            repo_path.to_str().unwrap(),
            "config",
            "user.email",
            "test@example.com",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "git config user.email failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(())
}

// Helper function to get the latest commit message
fn get_latest_commit(repo_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_path.to_str().unwrap(),
            "log",
            "--oneline",
            "-1",
            "--abbrev-commit",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "git log failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// Helper function to check if a file exists in the repo
fn file_exists_in_repo(repo_path: &Path, file_path: &str) -> bool {
    repo_path.join(file_path).exists()
}

// Helper function to read file content
fn read_file_content(
    repo_path: &Path,
    file_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(repo_path.join(file_path))?;
    Ok(content)
}

async fn get_random_port() -> Result<u16, ApiError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // We must drop the listener to release the port for our server.
    drop(listener);
    Ok(port)
}

fn url_for(action: &str, port: u16) -> String {
    format!("http://localhost:{port}/{action}")
}

fn build_env(git_repo_path: &Path, server_port: u16) -> Environment {
    Environment {
        git_repo_path: git_repo_path.to_path_buf(),
        server_port,
    }
}

async fn wait_for_commit(
    test_repo_path_buf: PathBuf,
    commit_message: &str,
    deadline_in: Option<Instant>,
) -> Result<()> {
    let deadline =
        deadline_in.unwrap_or(tokio::time::Instant::now() + tokio::time::Duration::from_secs(5));
    loop {
        if let Ok(msg) = get_latest_commit(&test_repo_path_buf)
            && msg.contains(commit_message)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() > deadline {
            return Err(anyhow::Error::msg("Test timed out waiting for commit"));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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
    let server_handle = tokio::spawn(async move {
        // Set the environment variable for the git repository path

        run_server(env).await
        // Import and run the main function
    });

    // Create a client to send requests
    let client = reqwest::Client::new();

    // Define the file to add
    let file_path = "test_file.txt";
    let content = "This is a test file for integration testing.";
    let commit_message = format!("added file at /{}", file_path);

    // Send the request to add the file
    let response = client
        .post(url_for("add-file", port))
        .json(&json!({
            "file_path": file_path,
            "content": content
        }))
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
    let commit_msg = get_latest_commit(&test_repo_path_buf).expect("Failed to get latest commit");
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
    let server_handle = tokio::spawn(async move { run_server(env).await });

    // Create a client to send requests
    let client = reqwest::Client::new();

    // Send the request with an empty file path
    let response = client
        .post(url_for("add-file", port))
        .json(&json!({
            "file_path": "",
            "content": "This should fail"
        }))
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
    let server_handle = tokio::spawn(async move { run_server(env).await });

    // Create a client to send requests
    let client = reqwest::Client::new();

    // Define the file to add in a subdirectory
    let file_path = "subdir/nested_file.txt";
    let content = "This file is in a subdirectory.";
    let commit_message = format!("added file at /{}", file_path);

    // Send the request to add the file
    let response = client
        .post(url_for("add-file", port))
        .json(&json!({
            "file_path": file_path,
            "content": content
        }))
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
    let commit_msg = get_latest_commit(&test_repo_path_buf).expect("Failed to get latest commit");
    assert!(
        commit_msg.contains(&commit_message),
        "Commit message doesn't match"
    );

    // Clean up - abort the server task
    server_handle.abort();
    Ok(())
}
