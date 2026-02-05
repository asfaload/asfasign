use client_lib::{download_file_with_verification, DownloadEvent, DownloadResult};
use client_lib::ClientLibError;

#[tokio::main]
async fn main() -> Result<(), ClientLibError> {
    let result: DownloadResult = download_file_with_verification(
        "https://github.com/user/repo/releases/download/v1.0.0/file.tar.gz",
        None, // Auto-generate filename
        "https://asfaload.backend.com",
        |event| {
            // Handle progress events
            match event {
                DownloadEvent::FileDownloadProgress { bytes_downloaded, total_bytes, .. } => {
                    if let Some(total) = total_bytes {
                        println!("Progress: {:.1}%", (bytes_downloaded as f64 / total as f64) * 100.0);
                    }
                }
                DownloadEvent::Completed(result) => {
                    println!("Download complete: {:?}", result.file_path);
                }
                _ => {}
            }
        },
    ).await?;

    println!("Successfully downloaded and verified: {}", result.file_path.display());
    Ok(())
}
