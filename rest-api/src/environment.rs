use std::{env, path::PathBuf};

use crate::error::ApiError;

// Structure to hold environment in which the server runs.:which gg
pub struct Environment {
    pub git_repo_path: PathBuf,
    pub server_port: u16,
}

pub fn init_env() -> Result<Environment, ApiError> {
    // Get git repo path from environment
    let git_repo_path = env::var("ASFALOAD_GIT_REPO_PATH")
        .map(PathBuf::from)
        .map_err(|_| ApiError::GitRepoPathNotSet)?;

    let port_str = env::var("ASFALOAD_PORT").unwrap_or_else(|_| "3000".to_string());
    let server_port: u16 = port_str
        .parse()
        .map_err(|_| ApiError::PortInvalid(format!("'{}' is not a valid port number", port_str)))?;

    Ok(Environment {
        git_repo_path,
        server_port,
    })
}
