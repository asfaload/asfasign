use crate::{state::init_state, v1::routes::v1_router};
use axum::Router;
use rest_api_types::{errors::ApiError, rustls::setup_crypto_provider};
use std::net::SocketAddr;
use tokio::signal;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};

use super::config::AppConfig;

pub async fn run_server(config: &AppConfig) -> Result<(), ApiError> {
    tracing::info!(
        git_repo_path = %config.git_repo_path.display(),
        "Starting REST API server"
    );
    tracing::debug!("Selecting rustls crypto provider");
    setup_crypto_provider();
    let app_state = init_state(config.clone())?;

    let app = Router::new()
        .nest("/v1", v1_router(app_state.clone()))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .with_state(app_state);

    // Start the server
    let addr = SocketAddr::from((config.server_address, config.server_port));
    tracing::info!(address = %addr, "Server listening");

    // Install signal handlers up front so registration failures abort
    // startup before the server begins accepting connections.
    let shutdown = shutdown_signal()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

// Helper so the Axum server can be gracefully stopped when it is reunning as PID 1 in a container.
fn shutdown_signal() -> Result<impl std::future::Future<Output = ()>, std::io::Error> {
    #[cfg(unix)]
    let (mut interrupt_handler, mut terminate_handler) = (
        signal::unix::signal(signal::unix::SignalKind::interrupt())?,
        signal::unix::signal(signal::unix::SignalKind::terminate())?,
    );

    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt_handler.recv() => {},
            _ = terminate_handler.recv() => {},
        }

        #[cfg(not(unix))]
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "failed waiting on Ctrl+C signal");
        }

        tracing::info!("signal received, starting graceful shutdown");
    })
}
