use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use git2::Repository;
use rest_api_types::errors::ApiError;
use serde_json::Value;
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    net::TcpStream,
    time::{Instant, timeout},
};

//
// Helper function to initialize a git repository in a temporary directory
pub fn init_git_repo(repo_path: &Path) -> Result<(), ApiError> {
    // Initialize git repo using git2
    let repo = Repository::init(repo_path)?;

    // Set user name and email for commits using git2
    let mut config = repo.config()?;
    config.set_str("user.name", "Test User")?;
    config.set_str("user.email", "test@example.com")?;

    Ok(())
}

// Helper function to get the latest commit message
pub fn get_latest_commit(repo_path: &Path) -> Result<String, ApiError> {
    let repo = Repository::open(repo_path)?;
    let head = repo.head()?;
    let commit = head.peel_to_commit()?;

    // Get the commit message and shorten the commit hash
    let commit_id = commit.id();
    let short_id = format!("{}", commit_id).chars().take(7).collect::<String>();
    let message = commit
        .message()
        .unwrap_or("")
        .split('\n')
        .next()
        .unwrap_or("");

    Ok(format!("{} {}", short_id, message.trim()))
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
    format!("http://localhost:{port}/{action}")
}

/// Helper function to build a test config
pub fn build_test_config(git_repo_path: &Path, server_port: u16) -> rest_api::config::AppConfig {
    rest_api::config::AppConfig {
        git_repo_path: git_repo_path.to_path_buf(),
        server_port,
        log_level: "info".to_string(),
    }
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

pub async fn make_git_commit_fail(repo_path_buf: PathBuf) -> Result<(), ApiError> {
    write_git_hook(
        repo_path_buf.clone(),
        "pre-commit",
        "#!/bin/sh\necho 'Simulating commit failure'; exit 1",
    )
    .await?;
    Ok(())
}
