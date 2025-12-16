use env_logger::Builder;
use log::LevelFilter;
use rest_api::server::run_server;
use std::env;
use std::path::PathBuf;

use rest_api::error::ApiError;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    // Initialize logging
    Builder::new().filter_level(LevelFilter::Info).init();

    // Get git repo path from environment
    let git_repo_path = env::var("ASFALOAD_GIT_REPO_PATH")
        .map(PathBuf::from)
        .map_err(|_| ApiError::GitRepoPathNotSet)?;

    let port_str = env::var("ASFALOAD_PORT").unwrap_or_else(|_| "3000".to_string());
    let port: u16 = port_str
        .parse()
        .map_err(|_| ApiError::PortInvalid(format!("'{}' is not a valid port number", port_str)))?;

    run_server(git_repo_path, port).await
}
