use crate::{auth_middleware::auth_middleware, handlers::add_file_handler, state::init_state};
use axum::{Router, routing::post};
use rest_api_types::errors::ApiError;
use std::net::SocketAddr;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};

use super::config::AppConfig;

pub async fn run_server(config: &AppConfig) -> Result<(), ApiError> {
    tracing::info!(
        git_repo_path = %config.git_repo_path.display(),
        "Starting REST API server"
    );
    let canonical_repo_path = tokio::fs::canonicalize(&config.git_repo_path)
        .await
        .map_err(|e| ApiError::InvalidFilePath(format!("Invalid git repo path: {}", e)))?;
    let app_state = init_state(canonical_repo_path);
    // Build router with authentication middleware and request tracing
    let app = Router::new()
        .route("/add-file", post(add_file_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http()
            .make_span_with(DefaultMakeSpan::new().include_headers(true))
            .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
            .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)))
        .with_state(app_state);

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], config.server_port));
    tracing::info!(address = %addr, "Server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
