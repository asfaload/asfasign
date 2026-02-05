use crate::{ClientLibError, DownloadEvent, Result};
use futures_util::stream::StreamExt;
use reqwest::Client;

pub async fn download_file<F, H>(url: &str, mut on_event: F, mut on_chunk: H) -> Result<Vec<u8>>
where
    F: FnMut(DownloadEvent) + Send,
    H: FnMut(&[u8]) + Send,
{
    let client = Client::new();
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(ClientLibError::HttpError {
            status: response.status().as_u16(),
            url: url.to_string(),
        });
    }

    let total_bytes = response.content_length();

    let mut buffer = Vec::new();
    let mut bytes_downloaded = 0u64;
    let mut last_progress_emitted = 0u64;

    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let chunk_size = chunk.len() as u64;
        bytes_downloaded += chunk_size;
        buffer.extend_from_slice(&chunk);
        on_chunk(&chunk);

        if let Some(total) = total_bytes {
            let byte_milestone = bytes_downloaded >= last_progress_emitted + 1_048_576;
            let percent_milestone =
                (bytes_downloaded * 10 / total) > (last_progress_emitted * 10 / total);

            if byte_milestone || percent_milestone {
                on_event(DownloadEvent::FileDownloadProgress {
                    bytes_downloaded,
                    total_bytes: Some(total),
                    chunk_size: chunk_size as usize,
                });
                last_progress_emitted = bytes_downloaded;
            }
        }
    }

    Ok(buffer)
}
