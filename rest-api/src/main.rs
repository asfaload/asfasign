use axum::{Router, routing::post};
use env_logger::Builder;
use log::{LevelFilter, info};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

mod actors;
mod error;
mod handlers;
mod models;
mod state;

use error::ApiError;
use handlers::add_file_handler;

use crate::state::init_state;

#[tokio::main]
async fn main() {
    // Initialize logging
    Builder::new().filter_level(LevelFilter::Info).init();

    // Get git repo path from environment
    let git_repo_path = env::var("ASFALOAD_GIT_REPO_PATH")
        .map(PathBuf::from)
        .map_err(|_| ApiError::GitRepoPathNotSet)
        .expect("ASFALOAD_GIT_REPO_PATH environment variable must be set");

    info!(
        "Starting REST API server with git repo at: {:?}",
        git_repo_path
    );

    let app_state = init_state(git_repo_path);
    // Build the router
    let app = Router::new()
        .route("/add-file", post(add_file_handler))
        .with_state(app_state);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
