use env_logger::Builder;
use log::LevelFilter;
use rest_api::server::run_server;
use std::env;
use std::path::PathBuf;

use rest_api::error::ApiError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    Builder::new().filter_level(LevelFilter::Info).init();

    // Get git repo path from environment
    let git_repo_path = env::var("ASFALOAD_GIT_REPO_PATH")
        .map(PathBuf::from)
        .map_err(|_| ApiError::GitRepoPathNotSet)?;

    run_server(git_repo_path).await
}
