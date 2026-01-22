use axum::{http::StatusCode, routing::post};
use axum_test::TestServer;
use common::fs::names::{SIGNERS_DIR, SIGNERS_FILE};
use rest_api_types::RegisterGitHubReleaseRequest;
use tempfile::TempDir;

#[tokio::test]
async fn test_register_github_release_endpoint() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let git_repo_path = temp_dir.path().to_path_buf();

    let signers_dir = git_repo_path.join("testowner/testrepo").join(SIGNERS_DIR);
    tokio::fs::create_dir_all(&signers_dir).await.unwrap();

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
    tokio::fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
        .await
        .unwrap();

    let app_state = rest_api::state::init_state(git_repo_path.clone(), None);

    let app = axum::Router::new()
        .route(
            "/github-release",
            post(rest_api::handlers::register_github_release_handler),
        )
        .with_state(app_state);

    let server = TestServer::new(app).expect("Failed to create test server");

    let request_body = RegisterGitHubReleaseRequest {
        release_url: "testowner/testrepo/v1.0.0".to_string(),
    };

    let response = server.post("/github-release").json(&request_body).await;

    let response_json: serde_json::Value = response.json();

    match response.status_code() {
        StatusCode::OK => {
            assert_eq!(response_json["success"], true);
            assert!(response_json["index_file_path"].is_string());
        }
        StatusCode::INTERNAL_SERVER_ERROR => {
            if response_json.get("success").is_some() {
                assert_eq!(response_json["success"], false);
                assert!(response_json["message"].is_string());
            } else {
                assert!(response_json["error"].is_string());
            }
        }
        _ => {
            panic!(
                "Expected 200 or 500 status code, got {}: {}",
                response.status_code(),
                response_json
            );
        }
    }
}

#[tokio::test]
async fn test_register_github_release_no_signers_file() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let git_repo_path = temp_dir.path().to_path_buf();

    let app_state = rest_api::state::init_state(git_repo_path.clone(), None);

    let app = axum::Router::new()
        .route(
            "/github-release",
            post(rest_api::handlers::register_github_release_handler),
        )
        .with_state(app_state);

    let server = TestServer::new(app).expect("Failed to create test server");

    let request_body = RegisterGitHubReleaseRequest {
        release_url: "testowner/testrepo/v1.0.0".to_string(),
    };

    let response = server.post("/github-release").json(&request_body).await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let response_json: serde_json::Value = response.json();
    assert!(response_json["error"].as_str().unwrap().contains("signers"));
}

#[tokio::test]
async fn test_register_github_release_invalid_url_format() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let git_repo_path = temp_dir.path().to_path_buf();

    let signers_dir = git_repo_path.join("testowner/testrepo").join(SIGNERS_DIR);
    tokio::fs::create_dir_all(&signers_dir).await.unwrap();

    let signers_json = r#"{
        "version": 1,
        "required_signers": 1,
        "signers": []
    }"#;
    tokio::fs::write(signers_dir.join(SIGNERS_FILE), signers_json)
        .await
        .unwrap();

    let app_state = rest_api::state::init_state(git_repo_path.clone(), None);

    let app = axum::Router::new()
        .route(
            "/github-release",
            post(rest_api::handlers::register_github_release_handler),
        )
        .with_state(app_state);

    let server = TestServer::new(app).expect("Failed to create test server");

    let request_body = RegisterGitHubReleaseRequest {
        release_url: "invalid".to_string(),
    };

    let response = server.post("/github-release").json(&request_body).await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}
