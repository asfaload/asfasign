use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Result;
use rest_api_types::{environment::Environment, errors::ApiError};
use tokio::{fs::File, time::Instant};

//
// Helper function to initialize a git repository in a temporary directory
pub fn init_git_repo(repo_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
            repo_path
                .to_str()
                .ok_or_else(|| "Path is not valid UTF-8".to_string())?,
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
            repo_path
                .to_str()
                .ok_or_else(|| "Path is not valid UTF-8".to_string())?,
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
pub fn get_latest_commit(repo_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_path
                .to_str()
                .ok_or_else(|| "Path is not valid UTF-8".to_string())?,
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
pub fn file_exists_in_repo(repo_path: &Path, file_path: &str) -> bool {
    repo_path.join(file_path).exists()
}

// Helper function to read file content
pub fn read_file_content(
    repo_path: &Path,
    file_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
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

pub fn build_env(git_repo_path: &Path, server_port: u16) -> Environment {
    Environment {
        git_repo_path: git_repo_path.to_path_buf(),
        server_port,
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
            return Err(anyhow::Error::msg("Test timed out waiting for commit"));
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

use tokio::io::AsyncWriteExt;
pub async fn write_git_hook(repo_path_buf: PathBuf, name: &str, code: &str) -> Result<()> {
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

pub async fn make_git_commit_fail(repo_path_buf: PathBuf) -> Result<()> {
    write_git_hook(
        repo_path_buf.clone(),
        "pre-commit",
        "#!/bin/sh\necho 'Simulating commit failure'; exit 1",
    )
    .await?;
    Ok(())
}
