use crate::{handlers::add_file_handler, state::init_state};
use axum::{Router, routing::post};
use log::info;
use std::net::SocketAddr;
use std::path::PathBuf;

pub async fn run_server(git_repo_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
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

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
