use crate::error::AdminLibResult;
use features_lib::{AsfaloadSecretKeys, AsfaloadSignatureTrait};
use reqwest::header::{HeaderMap, HeaderValue};
use rest_api_auth::{
    AuthInfo, AuthSignature, HEADER_NONCE, HEADER_PUBLIC_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP,
};

/// Creates authentication headers for REST API requests.
pub(crate) fn create_auth_headers(
    payload: &str,
    secret_key: &AsfaloadSecretKeys,
) -> AdminLibResult<HeaderMap> {
    let auth_info = AuthInfo::new(payload.to_string());
    let auth_signature = AuthSignature::new(&auth_info, secret_key)?;

    let mut headers = HeaderMap::new();

    headers.insert(
        HEADER_TIMESTAMP,
        HeaderValue::from_str(&auth_signature.auth_info().timestamp().to_rfc3339())?,
    );
    headers.insert(
        HEADER_NONCE,
        HeaderValue::from_str(&auth_signature.auth_info().nonce())?,
    );
    headers.insert(
        HEADER_SIGNATURE,
        HeaderValue::from_str(&auth_signature.signature().to_base64())?,
    );
    headers.insert(
        HEADER_PUBLIC_KEY,
        HeaderValue::from_str(&auth_signature.public_key())?,
    );

    Ok(headers)
}
