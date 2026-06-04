use crate::ClientLibError;
use crate::types::DownloadCallbacks;
use features_lib::{AsfaloadPublicKeyTrait, RevocationInfo};
use reqwest::Client;
use rest_api_types::models::{GetRevocationRequest, GetRevocationResponse};

/// Probe the backend for a revocation of the artifact.
///
/// If a revocation is found, returns a `FileRevoked` error with details.
/// If the revocation cannot be fetched (e.g. no revocation exists),
/// returns `Ok(())`.
pub(crate) async fn check_revocation(
    client: &Client,
    backend_url: &str,
    req: GetRevocationRequest,
    callbacks: &DownloadCallbacks,
) -> Result<(), ClientLibError> {
    match try_verify_revocation(client, backend_url, req).await {
        Ok(resp) => {
            let revocation = RevocationInfo::from_json(&resp.revocation_json)
                .map_err(|e| ClientLibError::RevocationParse(e.to_string()))?;
            let timestamp = revocation.timestamp.to_rfc3339();
            let initiator = revocation.initiator.to_base64();
            callbacks.emit_revocation_detected(&timestamp, &initiator);
            Err(ClientLibError::FileRevoked {
                timestamp,
                initiator,
            })
        }
        Err(_) => Ok(()),
    }
}

/// Fetch the revocation payload from the backend's get_revocation endpoint.
async fn try_verify_revocation(
    client: &Client,
    backend_url: &str,
    req: GetRevocationRequest,
) -> Result<GetRevocationResponse, ClientLibError> {
    let url = format!("{}/v1/get_revocation", backend_url);
    let response = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| ClientLibError::RevocationFetchError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "(failed to read response body)".to_string());
        return Err(ClientLibError::RevocationFetchError(format!(
            "{}: {}",
            status, body
        )));
    }
    response
        .json::<GetRevocationResponse>()
        .await
        .map_err(|e| ClientLibError::RevocationParse(e.to_string()))
}
