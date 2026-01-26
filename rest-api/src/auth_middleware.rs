use crate::actors::nonce_cache_actor::{NonceCacheMessage, NonceCacheResponse};
use crate::state::AppState;
use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use rest_api_auth::{
    AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_types::errors::ApiError;

// 1MB should be more than enough in our case
pub const MAX_BODY_SIZE: usize = 1024 * 1024;

// Heper to extract a header as string
fn get_header(request: &Request<Body>, header_name: &str) -> Result<String, ApiError> {
    Ok(request
        .headers()
        .get(header_name)
        .ok_or(ApiError::MissingAuthenticationHeaders)?
        .to_str()?
        .to_string())
}

pub async fn validate_nonce(state: AppState, nonce: &str) -> Result<(), ApiError> {
    // Check for replay attacks using nonce cache (when state is available)
    // This will be a no-op in tests where state is not provided
    let nonce_check_result = state
        .nonce_cache_actor
        .ask(NonceCacheMessage::CheckAndStoreNonce {
            nonce: nonce.to_string(),
        })
        .await;

    match nonce_check_result {
        Ok(response) => match response {
            NonceCacheResponse::Refused => Err(ApiError::ReplayAttackDetected),
            NonceCacheResponse::Accepted => Ok(()),
        },
        Err(e) => Err(ApiError::ActorMessageFailed(e.to_string())),
    }
}

/// Middleware that validates authentication headers and signatures
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let request_id = get_header(&request, "x-request-id")?;
    tracing::debug!(
        request_id = %request_id,
        "Starting authentication"
    );
    // Clone header values before moving the request
    let timestamp = get_header(&request, HEADER_TIMESTAMP)?;
    let nonce = get_header(&request, HEADER_NONCE)?;
    let signature = get_header(&request, HEADER_SIGNATURE)?;
    let public_key = get_header(&request, HEADER_PUBLIC_KEY)?;

    tracing::debug!(
        request_id = %request_id,
        timestamp = %timestamp,
        nonce = %nonce,
        signature = %signature,
        public_key = %public_key,
        "Extracted auth data"
    );
    //Reject reused nonce
    validate_nonce(state, &nonce).await.map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Failed to validate nonce"
        );
        e
    })?;

    // Extract the request body for signature validation
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, MAX_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                error = %e,
                "Request too big"
            );
            ApiError::RequestTooBig(e.to_string())
        })?;

    let payload = std::str::from_utf8(&body_bytes).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Request too big"
        );
        ApiError::InvalidRequestBody(format!("Request body contains invalid UTF-8: {}", e))
    })?;

    // Validate the authentication signature
    AuthSignature::validate_from_headers(&timestamp, &nonce, &signature, &public_key, payload)
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                error = %e,
                "Could not validate signature"
            );
            e
        })?;

    // Reconstruct the request with the original body
    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));

    // Continue to the next middleware/handler
    Ok(next.run(request).await)
}
