#[cfg(test)]
pub mod tests {

    use anyhow::Result;
    use axum::http::StatusCode;
    use rest_api::server::run_server;
    use rest_api_test_helpers::{
        build_env, file_exists_in_repo, get_latest_commit, get_random_port, init_git_repo,
        read_file_content, url_for, wait_for_commit,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

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
}
