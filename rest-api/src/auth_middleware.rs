use crate::actors::nonce_cache_actor::{NonceCacheMessage, NonceCacheResponse};
use crate::state::AppState;
use axum::{
    body::Body, extract::State, http::HeaderMap, http::Request, middleware::Next,
    response::Response,
};
use features_lib::AsfaloadPublicKeyTrait;
use rest_api_auth::{
    AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use rest_api_types::errors::ApiError;

// 1MB should be more than enough in our case
pub const MAX_BODY_SIZE: usize = 1024 * 1024;

// Heper to extract a header as string
fn get_header_value(headers: &HeaderMap, header_name: &str) -> Result<String, ApiError> {
    Ok(headers
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

/// Outcome of validating authentication headers against a payload.
///
/// `Success` carries the base64 public key as sent in the header.
/// `Failed` carries the public key when it was present and parseable,
/// and the `ApiError` describing the failure (returned verbatim by the
/// middleware so error responses are unchanged).
#[must_use]
pub enum AuthOutcome {
    NotAttempted,
    Success {
        public_key: String,
    },
    Failed {
        public_key: Option<String>,
        error: ApiError,
    },
}

/// Return the raw public key header value if it is present and parses
/// as a valid public key.
fn parseable_public_key(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(HEADER_PUBLIC_KEY)?.to_str().ok()?;
    features_lib::AsfaloadPublicKeys::from_base64(raw).ok()?;
    Some(raw.to_string())
}

/// Validate authentication headers and signature for a request payload.
///
/// Single source of truth for request authentication: used by
/// `auth_middleware` (which rejects on anything but `Success`) and by the
/// ping handler (which reports the outcome). A successful validation
/// consumes the nonce in the replay cache.
pub async fn validate_auth(
    state: AppState,
    headers: &HeaderMap,
    payload: &str,
    request_id: &str,
) -> AuthOutcome {
    let auth_headers = [
        HEADER_TIMESTAMP,
        HEADER_NONCE,
        HEADER_SIGNATURE,
        HEADER_PUBLIC_KEY,
    ];
    if auth_headers.iter().all(|h| !headers.contains_key(*h)) {
        return AuthOutcome::NotAttempted;
    }

    let public_key_if_valid = parseable_public_key(headers);

    let extracted: Result<_, ApiError> = (|| {
        Ok((
            get_header_value(headers, HEADER_TIMESTAMP)?,
            get_header_value(headers, HEADER_NONCE)?,
            get_header_value(headers, HEADER_SIGNATURE)?,
            get_header_value(headers, HEADER_PUBLIC_KEY)?,
        ))
    })();
    let (timestamp, nonce, signature, public_key) = match extracted {
        Ok(values) => values,
        Err(error) => {
            tracing::warn!(
                request_id = %request_id,
                error = %error,
                "Failed to extract auth headers"
            );
            return AuthOutcome::Failed {
                public_key: public_key_if_valid,
                error,
            };
        }
    };

    tracing::debug!(
        request_id = %request_id,
        timestamp = %timestamp,
        nonce = %nonce,
        signature = %signature,
        public_key = %public_key,
        "Extracted auth data"
    );
    //Reject reused nonce
    if let Err(error) = validate_nonce(state, &nonce).await {
        tracing::error!(
            request_id = %request_id,
            error = %error,
            "Failed to validate nonce"
        );
        return AuthOutcome::Failed {
            public_key: public_key_if_valid,
            error,
        };
    }

    // Validate the authentication signature
    if let Err(e) =
        AuthSignature::validate_from_headers(&timestamp, &nonce, &signature, &public_key, payload)
    {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Could not validate signature"
        );
        return AuthOutcome::Failed {
            public_key: public_key_if_valid,
            error: e.into(),
        };
    }

    AuthOutcome::Success { public_key }
}

/// Middleware that validates authentication headers and signatures
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let request_id = get_header_value(request.headers(), "x-request-id")?;
    tracing::debug!(
        request_id = %request_id,
        "Starting authentication"
    );

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

    match validate_auth(state, &parts.headers, payload, &request_id).await {
        AuthOutcome::Success { .. } => {
            // Reconstruct the request with the original body
            let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));

            // Continue to the next middleware/handler
            Ok(next.run(request).await)
        }
        AuthOutcome::NotAttempted => Err(ApiError::MissingAuthenticationHeaders),
        AuthOutcome::Failed { error, .. } => Err(error),
    }
}
