use crate::{ClientLibError, Result};
use reqwest::Client;
use futures_util::stream::StreamExt;

pub async fn download_file(url: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client
        .get(url)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(ClientLibError::HttpError {
            status: response.status().as_u16(),
            url: url.to_string(),
        });
    }

    let mut buffer = Vec::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.extend_from_slice(&chunk);
    }

    Ok(buffer)
}

pub async fn download_signers(backend_url: &str, index_file_path: &str) -> Result<Vec<u8>> {
    let signers_url = format!("{}/get-signers/{}", backend_url, index_file_path);
    download_file(&signers_url).await
}

pub async fn download_index(backend_url: &str, index_file_path: &str) -> Result<Vec<u8>> {
    let index_url = format!("{}/files/{}", backend_url, index_file_path);
    download_file(&index_url).await
}

pub async fn download_signatures(backend_url: &str, signatures_file_path: &str) -> Result<Vec<u8>> {
    let signatures_url = format!("{}/files/{}", backend_url, signatures_file_path);
    download_file(&signatures_url).await
}
