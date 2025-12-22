use axum::{http::Request, middleware::Next, response::Response};
use rest_api_auth::AuthSignature;
use rest_api_types::errors::ApiError;

// 1MB should be more than enough in our case
const MAX_BODY_SIZE: usize = 1024 * 1024;
/// Middleware that validates authentication headers and signatures
pub async fn auth_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Clone header values before moving the request
    let timestamp = request
        .headers()
        .get("X-asfld-timestamp")
        .ok_or(ApiError::MissingAuthenticationHeaders)?
        .to_str()?
        .to_string();

    let nonce = request
        .headers()
        .get("X-asfld-nonce")
        .ok_or(ApiError::MissingAuthenticationHeaders)?
        .to_str()?
        .to_string();

    let signature = request
        .headers()
        .get("X-asfld-sig")
        .ok_or(ApiError::MissingAuthenticationHeaders)?
        .to_str()?
        .to_string();

    let public_key = request
        .headers()
        .get("X-asfld-pk")
        .ok_or(ApiError::MissingAuthenticationHeaders)?
        .to_str()?
        .to_string();

    // Extract the request body for signature validation
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, MAX_BODY_SIZE)
        .await
        .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;

    let payload = std::str::from_utf8(&body_bytes).map_err(|e| {
        ApiError::InvalidRequestBody(format!("Request body contains invalid UTF-8: {}", e))
    })?;

    // Validate the authentication signature
    AuthSignature::validate_from_headers(&timestamp, &nonce, &signature, &public_key, payload)?;

    // Reconstruct the request with the original body
    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));

    // Continue to the next middleware/handler
    Ok(next.run(request).await)
}

