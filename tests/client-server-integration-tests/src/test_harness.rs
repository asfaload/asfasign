use std::path::PathBuf;
use std::thread::JoinHandle;
use tempfile::TempDir;
use tokio::sync::{Mutex, OnceCell};

use anyhow::Result;
use features_lib::{
    AsfaloadKeyPairTrait, AsfaloadKeyPairs, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
};
use reqwest::Client;
use rest_api::server::run_server;
use rest_api_auth::HEADER_NONCE;
use rest_api_auth::HEADER_PUBLIC_KEY;
use rest_api_auth::HEADER_SIGNATURE;
use rest_api_auth::HEADER_TIMESTAMP;
use rest_api_test_helpers::{build_test_config, get_random_port, wait_for_server, TestAuthHeaders};
use serde_json::json;

pub const TEST_PASSWORD: &str = "test_password_1234";

static TEST_STATE: OnceCell<Mutex<TestState>> = OnceCell::const_new();

/// Shared test server and resources
///
/// The test server is spawned programmatically using `tokio::spawn(run_server())`,
/// sharing the same git repo as the test harness.
pub struct TestState {
    pub server: TestServer,
    pub client: reqwest::Client,
    pub keys_dir: PathBuf,
    pub secret_key_path: PathBuf,
    pub public_key_path: PathBuf,
}

pub struct TestServer {
    pub port: u16,
    pub git_repo_path: PathBuf,
    pub temp_dir: TempDir,
    // Server runs on a dedicated thread with its own tokio runtime,
    // so it survives across per-test runtimes created by #[tokio::test].
    pub _server_thread: JoinHandle<()>,
}

impl TestServer {
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn git_repo_path(&self) -> PathBuf {
        self.git_repo_path.clone()
    }
}

/// Initialize the shared test server and resources
///
/// Call this at the beginning of each test. The server is spawned once
/// and shared across all tests via `OnceCell`.
///
/// # Example
/// ```rust
/// #[tokio::test]
/// async fn test_example() {
///     let state = test_harness::initialize().await;
///     // Use state.server, state.keys_dir...
/// }
/// ```
pub async fn initialize() -> &'static Mutex<TestState> {
    TEST_STATE
        .get_or_init(|| async {
            Mutex::new(
                setup_server_and_keys()
                    .await
                    .expect("Failed to setup test server and keys"),
            )
        })
        .await
}

async fn setup_server_and_keys() -> Result<TestState> {
    let temp_dir = TempDir::new()?;
    let git_repo_path = temp_dir.path().join("git_repo");
    std::fs::create_dir_all(&git_repo_path)?;

    rest_api_test_helpers::init_git_repo(&git_repo_path)?;

    // Spawn server on a random port, sharing the same git repo.
    // The server runs on a dedicated thread with its own tokio runtime
    // so it survives across per-test runtimes created by #[tokio::test].
    let port = get_random_port().await?;
    let config = build_test_config(&git_repo_path, port);
    let config_clone = config.clone();
    let server_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
        rt.block_on(async move {
            if let Err(e) = run_server(&config_clone).await {
                panic!("Test server failed to start: {}", e);
            }
        });
    });
    wait_for_server(&config, None).await?;

    let keys_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&keys_dir)?;

    let key_pair = AsfaloadKeyPairs::new(TEST_PASSWORD)?;
    let secret_key_path = keys_dir.join("test_key.json");
    let public_key_path = keys_dir.join("test_key.pub.json");

    key_pair.save(&secret_key_path)?;

    let public_key = key_pair.public_key();
    std::fs::write(
        &public_key_path,
        serde_json::to_string_pretty(&public_key.to_base64())?,
    )?;

    let server = TestServer {
        port,
        git_repo_path,
        temp_dir,
        _server_thread: server_thread,
    };

    Ok(TestState {
        server,
        client: Client::builder()
            .pool_max_idle_per_host(0)
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
        keys_dir,
        secret_key_path,
        public_key_path,
    })
}

/// Get the base URL of the shared test server
pub async fn base_url() -> String {
    let state = TEST_STATE.get().expect("Test state not initialized");
    let guard = state.lock().await;
    guard.server.base_url()
}

/// Get the git repo path of the shared test server
pub async fn git_repo_path() -> PathBuf {
    let state = TEST_STATE.get().expect("Test state not initialized");
    let guard = state.lock().await;
    guard.server.git_repo_path()
}

/// Generate a unique test directory path to avoid conflicts between tests
///
/// # Arguments
/// * `test_name` - A unique name identifying the test (e.g., "sign_file", "add_to_aggregate")
/// * `file_name` - The name of the file to create (e.g., "test.txt", "config.json")
///
/// # Returns
/// A tuple of (project_dir_path, file_path_relative_to_git_root)
pub fn unique_test_paths(test_name: &str, file_name: &str) -> (PathBuf, String) {
    let dir_name = format!("test_project_{}", test_name);
    let project_dir = PathBuf::from(dir_name.clone());
    let file_path = format!("{}/{}", dir_name, file_name);
    (project_dir, file_path)
}

/// Add a file to the git repo via the REST API
pub async fn add_file_via_api(
    file_path: &str,
    content: &str,
    secret_key_path: &PathBuf,
    password: &str,
) -> Result<()> {
    let secret_key = features_lib::AsfaloadSecretKeys::from_file(secret_key_path, password)?;

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
    } = rest_api_test_helpers::create_auth_headers_with_key(&secret_key, &payload_string).await;

    let url = base_url().await;
    let state = TEST_STATE.get().expect("Test state not initialized");
    let guard = state.lock().await;
    let client = guard.client.clone();
    drop(guard);

    let response = client
        .post(format!("{}/add-file", url))
        .header(HEADER_TIMESTAMP, timestamp)
        .header(HEADER_NONCE, nonce)
        .header(HEADER_SIGNATURE, signature)
        .header(HEADER_PUBLIC_KEY, public_key)
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Failed to add file: {}", error_text);
    }

    Ok(())
}

/// Wait for a commit with the given message to appear in the git repo
pub async fn wait_for_commit(commit_message: &str) -> Result<()> {
    let git_repo_path = git_repo_path().await;
    rest_api_test_helpers::wait_for_commit(git_repo_path, commit_message, None).await
}
