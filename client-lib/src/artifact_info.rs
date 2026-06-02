use crate::{AsfaloadLibResult, ClientLibError};
use rest_api_types::models::{GetArtifactInfoRequest, GetArtifactInfoResponse};
/// Fetch from the backend all info required for validation of a signed artifact download.
///
/// Makes an unauthenticated POST  request to `/v1/get_artifact_info
///
pub async fn get_artifact_info(
    client: &reqwest::Client,
    backend_url: &str,
    req: GetArtifactInfoRequest,
) -> AsfaloadLibResult<GetArtifactInfoResponse> {
    let url = format!("{}/v1/get_artifact_info", backend_url);
    let response = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| ClientLibError::ArtifactInfoFetchError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "(failed to read response body)".to_string());
        return Err(ClientLibError::ArtifactInfoFetchError(format!(
            "{}: {}",
            status, body
        )));
    }

    response
        .json::<GetArtifactInfoResponse>()
        .await
        .map_err(|e| ClientLibError::ArtifactInfoFetchError(e.to_string()))
}
