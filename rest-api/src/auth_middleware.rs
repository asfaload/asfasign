use axum::{body::Body, http::Request, middleware::Next, response::Response};
use rest_api_auth::AuthSignature;
use rest_api_types::errors::ApiError;

// 1MB should be more than enough in our case
const MAX_BODY_SIZE: usize = 1024 * 1024;

// Heper to extract a header as string
fn get_header(request: &Request<Body>, header_name: &str) -> Result<String, ApiError> {
    Ok(request
        .headers()
        .get(header_name)
        .ok_or(ApiError::MissingAuthenticationHeaders)?
        .to_str()?
        .to_string())
}

/// Middleware that validates authentication headers and signatures
pub async fn auth_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Clone header values before moving the request
    let timestamp = get_header(&request, "X-asfld-timestamp")?;
    let nonce = get_header(&request, "X-asfld-nonce")?;
    let signature = get_header(&request, "X-asfld-sig")?;
    let public_key = get_header(&request, "X-asfld-pk")?;

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
