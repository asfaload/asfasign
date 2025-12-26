use crate::{auth_middleware::auth_middleware, handlers::add_file_handler, state::init_state};
use axum::{Router, routing::post};
use log::info;
use rest_api_types::errors::ApiError;
use std::net::SocketAddr;

use super::config::AppConfig;

pub async fn run_server(config: &AppConfig) -> Result<(), ApiError> {
    info!(
        "Starting REST API server with git repo at: {:?}",
        config.git_repo_path
    );
    let canonical_repo_path = tokio::fs::canonicalize(&config.git_repo_path)
        .await
        .map_err(|e| ApiError::InvalidFilePath(format!("Invalid git repo path: {}", e)))?;
    let app_state = init_state(canonical_repo_path);
    // Build the router with authentication middleware
    let app = Router::new()
        .route("/add-file", post(add_file_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .with_state(app_state);

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server_port));
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
