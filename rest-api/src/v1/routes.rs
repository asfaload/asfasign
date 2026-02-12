use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    auth_middleware::auth_middleware,
    handlers::{
        add_file_handler, get_file_handler, get_pending_signatures_handler,
        get_signature_status_handler, get_signers_handler, register_release_handler,
        register_repo_handler, submit_signature_handler, update_signers_handler,
    },
    state::AppState,
};

/// Build the v1 API router with all route definitions.
pub fn v1_router(app_state: AppState) -> Router<AppState> {
    let register_router = Router::new()
        .route("/register_repo", post(register_repo_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let release_router = Router::new()
        .route("/release", post(register_release_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let update_signers_router = Router::new()
        .route("/update_signers", post(update_signers_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let add_file_router = Router::new()
        .route("/add-file", post(add_file_handler))
        .route("/pending_signatures", get(get_pending_signatures_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let signature_router = Router::new()
        .route("/signatures", post(submit_signature_handler))
        .route(
            "/signatures/{*file_path}",
            get(get_signature_status_handler),
        );
    let files_router = Router::new().route("/files/{*file_path}", get(get_file_handler));
    let signers_router = Router::new().route("/get-signers/{*file_path}", get(get_signers_handler));

    register_router
        .merge(release_router)
        .merge(update_signers_router)
        .merge(add_file_router)
        .merge(signature_router)
        .merge(files_router)
        .merge(signers_router)
}
