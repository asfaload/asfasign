use futures_util::StreamExt;
use rest_api_types::errors::ApiError;
use sha2::{Digest, Sha256};

/// Downloads a file from the given URL using the provided reqwest client and
/// computes its SHA-256 hash via streaming.
///
/// `require_content_length` controls whether a missing Content-Length header
/// is treated as an error (forge APIs guarantee it) or tolerated (file servers
/// may omit it).
pub async fn download_and_hash(
    client: &reqwest::Client,
    url: &str,
    max_size: u64,
    source_name: &str,
    require_content_length: bool,
) -> Result<String, ApiError> {
    let response = client.get(url).send().await.map_err(|e| {
        ApiError::ReleaseApiError(
            source_name.to_string(),
            format!("Failed to download file: {}", e),
        )
    })?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(ApiError::ReleaseApiError(
            source_name.to_string(),
            format!("HTTP error downloading file {}: {}", url, response.status()),
        ));
    }

    match (response.content_length(), require_content_length) {
        (Some(len), _) if len > max_size => {
            return Err(ApiError::ReleaseApiError(
                source_name.to_string(),
                format!("File size {} exceeds limit {}", len, max_size),
            ));
        }
        (None, true) => {
            return Err(ApiError::ReleaseApiError(
                source_name.to_string(),
                "Missing Content-Length header".to_string(),
            ));
        }
        _ => {}
    }

    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    let mut total_bytes = 0u64;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            ApiError::ReleaseApiError(
                source_name.to_string(),
                format!("Error reading stream: {}", e),
            )
        })?;

        total_bytes += chunk.len() as u64;
        if total_bytes > max_size {
            return Err(ApiError::ReleaseApiError(
                source_name.to_string(),
                format!("File size exceeded limit during download: {}", max_size),
            ));
        }

        hasher.update(&chunk);
    }

    Ok(hex::encode(hasher.finalize()))
}
