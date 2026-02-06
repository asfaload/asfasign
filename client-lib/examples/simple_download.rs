use client_lib::ClientLibError;
use client_lib::{DownloadCallbacks, DownloadResult, download_file_with_verification};

#[tokio::main]
async fn main() -> Result<(), ClientLibError> {
    let callbacks = DownloadCallbacks::default()
        .with_file_download_progress(|bytes_downloaded, total_bytes, _chunk_size| {
            if let Some(total) = total_bytes {
                println!(
                    "Progress: {:.1}%",
                    (bytes_downloaded as f64 / total as f64) * 100.0
                );
            }
        })
        .with_completed(|result| {
            println!("Download complete: {:?}", result.file_path);
        });

    let result: DownloadResult = download_file_with_verification(
        "https://github.com/user/repo/releases/download/v1.0.0/file.tar.gz",
        None, // Auto-generate filename
        "https://asfaload.backend.com",
        &callbacks,
    )
    .await?;

    println!(
        "Successfully downloaded and verified: {}",
        result.file_path.display()
    );
    Ok(())
}
