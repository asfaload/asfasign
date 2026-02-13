use std::path::PathBuf;
use std::thread::JoinHandle;
use tempfile::TempDir;
use tokio::sync::{Mutex, OnceCell};

use anyhow::Result;
use features_lib::AsfaloadKeyPairTrait;
use rest_api::server::run_server;
use rest_api_test_helpers::{build_test_config, get_random_port, wait_for_server};

pub const TEST_PASSWORD: &str = "password";

static TEST_STATE: OnceCell<Mutex<TestState>> = OnceCell::const_new();

/// Shared test server and resources
///
/// The test server is spawned programmatically using `tokio::spawn(run_server())`,
/// sharing the same git repo as the test harness.
pub struct TestState {
    pub server: TestServer,
    pub keys_dir: PathBuf,
    pub test_keys: test_helpers::TestKeys,
    pub secret_key_paths: Vec<PathBuf>,
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

    let test_keys = test_helpers::TestKeys::new_generated(5);
    let mut secret_key_paths = Vec::with_capacity(5);

    for i in 0..5 {
        let key_pair = test_keys.key_pair(i).expect("key_pair should exist");
        let secret_key_path = keys_dir.join(format!("test_key_{}.json", i));
        key_pair.save(&secret_key_path)?;
        secret_key_paths.push(secret_key_path);
    }

    let server = TestServer {
        port,
        git_repo_path,
        temp_dir,
        _server_thread: server_thread,
    };

    Ok(TestState {
        server,
        keys_dir,
        test_keys,
        secret_key_paths,
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

/// Create a file in the git repo at the given relative path.
///
/// Creates parent directories as needed. The server reads files directly
/// from the filesystem, so no API call or git commit is required.
///
/// # Arguments
/// * `file_path` - Relative path within the git repo (e.g., "test_project_foo/artifact.txt")
/// * `content` - File content to write
pub async fn create_file_in_repo(file_path: &str, content: &str) -> Result<()> {
    let git_repo = git_repo_path().await;
    let absolute_path = git_repo.join(file_path);
    if let Some(parent) = absolute_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&absolute_path, content).await?;
    Ok(())
}

/// Create an empty pending signatures file for an artifact.
///
/// The server's `list-pending` endpoint discovers artifacts by looking for
/// `.signatures.json.pending` files. This helper creates that file so the
/// artifact appears in the pending list.
///
/// # Arguments
/// * `file_path` - Relative path to the artifact (e.g., "test_project_foo/artifact.txt")
pub async fn create_pending_signatures_for(file_path: &str) -> Result<()> {
    let git_repo = git_repo_path().await;
    let absolute_path = git_repo.join(file_path);
    let pending_sig_path = common::fs::names::pending_signatures_path_for(&absolute_path)?;
    tokio::fs::write(&pending_sig_path, "{}").await?;
    Ok(())
}

/// Wait for a commit with the given message to appear in the git repo
pub async fn wait_for_commit(commit_message: &str) -> Result<()> {
    let git_repo_path = git_repo_path().await;
    rest_api_test_helpers::wait_for_commit(git_repo_path, commit_message, None).await
}
