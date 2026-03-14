use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::Result;
use features_lib::{AsfaloadSecretKeys, AsfaloadSignatureTrait};
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_types::errors::ApiError;
use serde_json::Value;
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    net::TcpStream,
    time::{Instant, timeout},
};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

/// Read the git backend from the ASFALOAD_GIT_BACKEND environment variable.
/// Defaults to Sha1 if unset or unrecognised.
fn configured_backend() -> rest_api::config::GitBackendConfig {
    match std::env::var("ASFALOAD_GIT_BACKEND").as_deref() {
        Ok("sha256") => rest_api::config::GitBackendConfig::Sha256,
        _ => rest_api::config::GitBackendConfig::Sha1,
    }
}

//
// Helper function to initialize a git repository in a temporary directory
pub fn init_git_repo(repo_path: &Path) -> Result<(), ApiError> {
    fs::create_dir_all(repo_path).map_err(ApiError::ServerSetupError)?;

    if configured_backend() == rest_api::config::GitBackendConfig::Sha256 {
        run_git(repo_path, &["init", "--object-format=sha256"])?;
    } else {
        run_git(repo_path, &["init"])?;
    }
    run_git(repo_path, &["config", "user.name", "Test User"])?;
    run_git(repo_path, &["config", "user.email", "test@example.com"])?;

    Ok(())
}

// Helper function to get the latest commit message
pub fn get_latest_commit(repo_path: &Path) -> Result<String, ApiError> {
    run_git(repo_path, &["log", "--oneline", "-1"])
}

/// Check if a file exists in the latest git commit
pub fn file_exists_in_latest_commit(repo_path: &Path, file_path: &str) -> Result<bool, ApiError> {
    let output = Command::new("git")
        .args(["-C", &repo_path.to_string_lossy(), "cat-file", "-e"])
        .arg(format!("HEAD:{}", file_path))
        .output()
        .map_err(ApiError::ServerSetupError)?;
    Ok(output.status.success())
}

/// Check if a file is tracked in git (in the index)
pub fn file_is_tracked_in_git(repo_path: &Path, file_path: &str) -> Result<bool, ApiError> {
    let output = Command::new("git")
        .args([
            "-C",
            &repo_path.to_string_lossy(),
            "ls-files",
            "--error-unmatch",
            "--",
            file_path,
        ])
        .output()
        .map_err(ApiError::ServerSetupError)?;
    Ok(output.status.success())
}

// Helper function to check if a file exists in the repo
pub fn file_exists_in_repo(repo_path: &Path, file_path: &str) -> bool {
    repo_path.join(file_path).exists()
}

// Helper function to read file content
pub fn read_file_content(repo_path: &Path, file_path: &str) -> Result<String, ApiError> {
    let content = fs::read_to_string(repo_path.join(file_path))?;
    Ok(content)
}

pub async fn get_random_port() -> Result<u16, ApiError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // We must drop the listener to release the port for our server.
    drop(listener);
    Ok(port)
}

pub fn url_for(action: &str, port: u16) -> String {
    format!("http://localhost:{port}/v1/{action}")
}

/// Helper function to build a test config
pub fn build_test_config(git_repo_path: &Path, server_port: u16) -> rest_api::config::AppConfig {
    let git_backend = configured_backend();
    rest_api::config::AppConfig {
        git_repo_path: git_repo_path.to_path_buf(),
        server_port,
        log_level: "info".to_string(),
        git_backend,
        github_api_key: None,
        gitlab_api_key: None,
    }
}

/// Stage the given paths and create a commit in a test git repo.
pub fn git_commit(repo_path: &Path, paths: &[&str], message: &str) -> Result<(), ApiError> {
    for path in paths {
        run_git(repo_path, &["add", path])?;
    }
    run_git(repo_path, &["commit", "-m", message])?;
    Ok(())
}

fn run_git(repo_path: &Path, args: &[&str]) -> Result<String, ApiError> {
    let output = Command::new("git")
        .args(["-C", &repo_path.to_string_lossy()])
        .args(args)
        .output()
        .map_err(ApiError::ServerSetupError)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::GitOperationFailed(git2::Error::from_str(
            &format!("git {:?} failed: {}", args, stderr.trim()),
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub async fn wait_for_server(
    config: &rest_api::config::AppConfig,
    timeout_in_sec: Option<u64>,
) -> Result<(), ApiError> {
    let address = format!("127.0.0.1:{}", config.server_port);

    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_in_sec.unwrap_or(2));

    // Attempt to connect within a 2-second timeout.
    // `timeout` returns a Result, where Err means the operation timed out.
    loop {
        match timeout(
            Duration::from_secs(timeout_in_sec.unwrap_or(2)),
            TcpStream::connect(&address),
        )
        .await
        {
            Ok(Ok(_)) => {
                // Connection succeeded before the timeout.
                return Ok(());
            }
            Ok(Err(e)) => {
                // Connection failed (e.g., connection refused).
                if tokio::time::Instant::now() > deadline {
                    return Err(ApiError::ServerSetupError(e));
                }
            }
            Err(_) => {
                // The `timeout` elapsed, so we assume the port is filtered.
                if tokio::time::Instant::now() > deadline {
                    return Err(ApiError::ServerSetupError(std::io::Error::other(
                        "Timeout connecting server",
                    )));
                }
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
pub async fn wait_for_commit(
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
            return Err(anyhow::Error::msg(
                "Test timed out waiting for commit".to_string(),
            ));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

pub fn parse_log_lines(content: &str) -> Result<Vec<Value>> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).map_err(anyhow::Error::from))
        .collect()
}
pub async fn wait_for_log_entry_with_request_id<P: AsRef<Path>>(
    log_path: P,
    request_id: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(content) = fs::read_to_string(log_path.as_ref())
            && parse_log_lines(&content)?.iter().any(|entry| {
                entry
                    .get("request_id")
                    .or_else(|| entry.get("fields").and_then(|f| f.get("request_id")))
                    .and_then(|v| v.as_str())
                    == Some(request_id)
            })
        {
            return Ok(());
        }

        if tokio::time::Instant::now() > deadline {
            anyhow::bail!(
                "Timed out waiting for log entry with request_id. Log content: {}",
                fs::read_to_string(log_path).unwrap_or_default()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn write_git_hook(
    repo_path_buf: PathBuf,
    name: &str,
    code: &str,
) -> Result<(), ApiError> {
    // Create a pre-commit hook that will fail
    let hooks_dir = repo_path_buf.join(".git").join("hooks");
    fs::create_dir_all(&hooks_dir).unwrap();

    let hook_path = hooks_dir.join(name);
    let mut hook_file = File::create(&hook_path).await?;
    hook_file.write_all(code.as_bytes()).await?;
    hook_file.flush().await?;

    // Make the hook executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_git_repo_creates_repo() {
        let temp_dir = tempfile::tempdir().unwrap();
        init_git_repo(temp_dir.path()).unwrap();

        let inside = run_git(temp_dir.path(), &["rev-parse", "--is-inside-work-tree"]).unwrap();
        assert_eq!(inside, "true");
    }

    #[test]
    fn test_init_git_repo_creates_missing_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().join("git_repo");

        init_git_repo(&repo_path).unwrap();

        assert!(repo_path.exists());
        let inside = run_git(&repo_path, &["rev-parse", "--is-inside-work-tree"]).unwrap();
        assert_eq!(inside, "true");
    }

    /// Mutex to serialise tests that mutate `ASFALOAD_GIT_BACKEND`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_init_git_repo_uses_sha256_object_format() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: Access to the env var is serialised by ENV_LOCK.
        unsafe { std::env::set_var("ASFALOAD_GIT_BACKEND", "sha256") };
        let temp_dir = tempfile::tempdir().unwrap();
        init_git_repo(temp_dir.path()).unwrap();
        let fmt = run_git(temp_dir.path(), &["rev-parse", "--show-object-format"]).unwrap();
        assert_eq!(fmt, "sha256");
        unsafe { std::env::remove_var("ASFALOAD_GIT_BACKEND") };
    }

    #[test]
    fn test_build_test_config_defaults_to_sha1() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: Access to the env var is serialised by ENV_LOCK.
        unsafe { std::env::remove_var("ASFALOAD_GIT_BACKEND") };
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg = build_test_config(temp_dir.path(), 3000);
        assert_eq!(cfg.git_backend, rest_api::config::GitBackendConfig::Sha1);
    }

    #[test]
    fn test_build_test_config_reads_sha256_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: Access to the env var is serialised by ENV_LOCK.
        unsafe { std::env::set_var("ASFALOAD_GIT_BACKEND", "sha256") };
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg = build_test_config(temp_dir.path(), 3000);
        assert_eq!(cfg.git_backend, rest_api::config::GitBackendConfig::Sha256);
        unsafe { std::env::remove_var("ASFALOAD_GIT_BACKEND") };
    }
}

pub async fn make_git_commit_fail(repo_path_buf: PathBuf) -> Result<(), ApiError> {
    write_git_hook(
        repo_path_buf.clone(),
        "pre-commit",
        "#!/bin/sh\necho 'Simulating commit failure'; exit 1",
    )
    .await?;
    Ok(())
}

pub struct TestAuthHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub public_key: String,
}

/// Helper function to create authentication headers for a given payload
pub async fn create_auth_headers_with_key(
    secret_key: &AsfaloadSecretKeys,
    payload: &str,
) -> TestAuthHeaders {
    // Create authentication info and signature
    let auth_info = AuthInfo::new(payload.to_string());
    let auth_signature = AuthSignature::new(&auth_info, secret_key).unwrap();

    TestAuthHeaders {
        timestamp: auth_signature.auth_info().timestamp().to_rfc3339(),
        nonce: auth_signature.auth_info().nonce(),
        signature: auth_signature.signature().to_base64(),
        public_key: auth_signature.public_key(),
    }
}

/// Helper function to create authentication headers for a given payload
pub async fn create_auth_headers(payload: &str) -> TestAuthHeaders {
    let test_keys = test_helpers::TestKeys::new(1);
    let secret_key = test_keys.sec_key(0).unwrap();
    create_auth_headers_with_key(secret_key, payload).await
}
pub async fn send_authenticated_request_with_overwrite(
    client: &reqwest::Client,
    port: u16,
    secret_key: &AsfaloadSecretKeys,
    payload: &serde_json::Value,
    overwrite: HashMap<String, String>,
) -> reqwest::Response {
    let payload_string = payload.to_string();

    let TestAuthHeaders {
        timestamp,
        nonce,
        signature,
        public_key,
    } = create_auth_headers_with_key(secret_key, &payload_string).await;

    client
        .post(url_for("revoke", port))
        .header(
            HEADER_TIMESTAMP,
            overwrite.get(HEADER_TIMESTAMP).unwrap_or(&timestamp),
        )
        .header(HEADER_NONCE, overwrite.get(HEADER_NONCE).unwrap_or(&nonce))
        .header(
            HEADER_SIGNATURE,
            overwrite.get(HEADER_SIGNATURE).unwrap_or(&signature),
        )
        .header(
            HEADER_PUBLIC_KEY,
            overwrite.get(HEADER_PUBLIC_KEY).unwrap_or(&public_key),
        )
        .json(payload)
        .send()
        .await
        .expect("Failed to send request")
}
pub async fn send_authenticated_request_with_key(
    client: &reqwest::Client,
    port: u16,
    secret_key: &AsfaloadSecretKeys,
    payload: &serde_json::Value,
) -> reqwest::Response {
    send_authenticated_request_with_overwrite(client, port, secret_key, payload, HashMap::new())
        .await
}

pub async fn send_authenticated_request(
    client: &reqwest::Client,
    port: u16,
    payload: &serde_json::Value,
) -> reqwest::Response {
    let test_keys = test_helpers::TestKeys::new(1);
    let secret_key = test_keys.sec_key(0).unwrap();
    send_authenticated_request_with_key(client, port, secret_key, payload).await
}

pub async fn send_repeated_authenticated_request(
    client: &reqwest::Client,
    port: u16,
    payload: &serde_json::Value,
) -> reqwest::Response {
    let payload_string = payload.to_string();
    let TestAuthHeaders {
        timestamp,
        nonce,
        signature,
        public_key,
    } = create_auth_headers(&payload_string).await;

    let first_response = client
        .post(url_for("revoke", port))
        .header(HEADER_TIMESTAMP, &timestamp)
        .header(HEADER_NONCE, &nonce)
        .header(HEADER_SIGNATURE, &signature)
        .header(HEADER_PUBLIC_KEY, &public_key)
        .json(payload)
        .send()
        .await
        .expect("Failed to send request");
    assert!(
        first_response.status() != reqwest::StatusCode::UNAUTHORIZED,
        "The first request in the nonce reuse test must pass auth. Status: {}",
        first_response.status()
    );

    client
        .post(url_for("revoke", port))
        .header(HEADER_TIMESTAMP, timestamp)
        .header(HEADER_NONCE, nonce)
        .header(HEADER_SIGNATURE, signature)
        .header(HEADER_PUBLIC_KEY, public_key)
        .json(payload)
        .send()
        .await
        .expect("Failed to send request")
}

pub fn print_logs() {
    // Set log level with RUST_LOG env var
    if std::env::var("RUST_LOG").is_err() {
        println!("** Set the log level with RUST_LOG env var");
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .init();
}

pub fn setup_file_logging(
    temp_dir: &Path,
) -> Result<(
    WorkerGuard,
    std::path::PathBuf,
    tracing::subscriber::DefaultGuard,
)> {
    let log_path = temp_dir.join("test.log");
    let appender = tracing_appender::rolling::never(temp_dir, "test.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);

    let subscriber = Registry::default()
        .with(EnvFilter::new("info"))
        .with(fmt::layer().json().with_writer(non_blocking));

    let default_guard = tracing::subscriber::set_default(subscriber);

    Ok((guard, log_path, default_guard))
}
