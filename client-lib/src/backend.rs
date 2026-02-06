use crate::{AsfaloadLibResult, ClientLibError, DownloadEvent, constants::ONE_MEGABYTE};
use futures_util::stream::StreamExt;
use reqwest::Client;
use std::io::Write;
use tempfile::NamedTempFile;

pub async fn download_file<F, H>(url: &str, on_event: F, on_chunk: H) -> AsfaloadLibResult<Vec<u8>>
where
    F: FnMut(DownloadEvent) + Send,
    H: FnMut(&[u8]) + Send,
{
    let mut buffer = Vec::new();
    download_file_to_writer(url, &mut buffer, on_event, on_chunk).await?;
    Ok(buffer)
}

pub async fn download_file_to_temp<F, H>(
    url: &str,
    on_event: F,
    on_chunk: H,
) -> AsfaloadLibResult<(NamedTempFile, u64)>
where
    F: FnMut(DownloadEvent) + Send,
    H: FnMut(&[u8]) + Send,
{
    let mut temp_file = NamedTempFile::new()?;
    let bytes_downloaded = download_file_to_writer(url, &mut temp_file, on_event, on_chunk).await?;
    temp_file.flush()?;
    Ok((temp_file, bytes_downloaded))
}
/// Download file to temporary location with incremental hash computation
async fn download_file_to_writer<F, H, W: std::io::Write + Send>(
    url: &str,
    writer: &mut W,
    mut on_event: F,
    mut on_chunk: H,
) -> AsfaloadLibResult<u64>
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

    let mut bytes_downloaded = 0u64;
    let mut last_progress_emitted = 0u64;

    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let chunk_size = chunk.len() as u64;
        bytes_downloaded += chunk_size;

        // Write chunk to temp file and update hasher
        writer.write_all(&chunk)?;
        on_chunk(&chunk);

        if let Some(total) = total_bytes {
            let byte_milestone = bytes_downloaded >= last_progress_emitted + ONE_MEGABYTE;
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

    // Ensure all data is flushed to disk
    writer.flush()?;

    Ok(bytes_downloaded)
}
