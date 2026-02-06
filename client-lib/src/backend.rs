use crate::constants::ONE_MEGABYTE;
use crate::types::DownloadCallbacks;
use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::HashAlgorithm;
use futures_util::stream::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256, Sha512};
use std::io::Write;
use tempfile::NamedTempFile;

enum IncrementalHasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl IncrementalHasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            IncrementalHasher::Sha256(h) => h.update(data),
            IncrementalHasher::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            IncrementalHasher::Sha256(h) => h.finalize().to_vec(),
            IncrementalHasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

pub async fn download_file(url: &str, callbacks: &DownloadCallbacks) -> AsfaloadLibResult<Vec<u8>> {
    let hasher = &mut IncrementalHasher::Sha512(Sha512::new());
    let mut buffer = Vec::new();
    download_file_to_writer(url, &mut buffer, hasher, callbacks).await?;
    Ok(buffer)
}

pub async fn download_file_to_temp(
    url: &str,
    hash_algorithm: &HashAlgorithm,
    callbacks: &DownloadCallbacks,
) -> AsfaloadLibResult<(NamedTempFile, u64, String)> {
    let mut hasher = match hash_algorithm {
        HashAlgorithm::Sha256 => IncrementalHasher::Sha256(Sha256::new()),
        HashAlgorithm::Sha512 => IncrementalHasher::Sha512(Sha512::new()),
        HashAlgorithm::Sha1 | HashAlgorithm::Md5 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(
                hash_algorithm.clone(),
            ));
        }
    };

    let mut temp_file = NamedTempFile::new()?;
    let bytes_downloaded =
        download_file_to_writer(url, &mut temp_file, &mut hasher, callbacks).await?;
    temp_file.flush()?;

    let hash_bytes = hasher.finalize();
    let computed_hash = hex::encode(hash_bytes);

    Ok((temp_file, bytes_downloaded, computed_hash))
}
/// Download file to temporary location with incremental hash computation
async fn download_file_to_writer<W: std::io::Write + Send>(
    url: &str,
    writer: &mut W,
    hasher: &mut IncrementalHasher,
    callbacks: &DownloadCallbacks,
) -> AsfaloadLibResult<u64> {
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

        // Write chunk to writer and emit callback
        writer.write_all(&chunk)?;
        hasher.update(&chunk);
        callbacks.emit_chunk_received(&chunk);

        if let Some(total) = total_bytes {
            let byte_milestone = bytes_downloaded >= last_progress_emitted + ONE_MEGABYTE;
            let percent_milestone =
                (bytes_downloaded * 10 / total) > (last_progress_emitted * 10 / total);

            if byte_milestone || percent_milestone {
                callbacks.emit_file_download_progress(
                    bytes_downloaded,
                    Some(total),
                    chunk_size as usize,
                );
                last_progress_emitted = bytes_downloaded;
            }
        }
    }

    // Ensure all data is flushed
    writer.flush()?;

    Ok(bytes_downloaded)
}
