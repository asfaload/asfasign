use axum::{Router, routing::post};
use std::env;
use std::path::PathBuf;
use std::net::SocketAddr;
use log::{info, LevelFilter};
use env_logger::Builder;
use kameo::prelude::Spawn;

mod error;
mod models;
mod handlers;
mod git_actor;

use error::ApiError;
use handlers::{add_file_handler, AppState};
use git_actor::GitActor;

#[tokio::main]
async fn main() {
    // Initialize logging
    Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    // Get git repo path from environment
    let git_repo_path = env::var("ASFALOAD_GIT_REPO_PATH")
        .map(PathBuf::from)
        .map_err(|_| ApiError::GitRepoPathNotSet)
        .expect("ASFALOAD_GIT_REPO_PATH environment variable must be set");

    info!("Starting REST API server with git repo at: {:?}", git_repo_path);

    // Create git actor using spawn
    let git_actor = GitActor::spawn(git_repo_path.clone());

    // Create app state
    let app_state = AppState {
        git_repo_path,
        git_actor,
    };

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
