use crate::{handlers::add_file_handler, state::init_state};
use axum::{Router, routing::post};
use log::info;
use rest_api_types::{environment::Environment, errors::ApiError};
use std::net::SocketAddr;

pub async fn run_server(env: &Environment) -> Result<(), ApiError> {
    info!(
        "Starting REST API server with git repo at: {:?}",
        env.git_repo_path
    );
    let canonical_repo_path = tokio::fs::canonicalize(&env.git_repo_path)
        .await
        .map_err(|e| ApiError::InvalidFilePath(format!("Invalid git repo path: {}", e)))?;
    let app_state = init_state(canonical_repo_path);
    // Build the router
    let app = Router::new()
        .route("/add-file", post(add_file_handler))
        .with_state(app_state);

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], env.server_port));
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
