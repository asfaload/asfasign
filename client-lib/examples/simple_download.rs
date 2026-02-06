use client_lib::ClientLibError;
use client_lib::{DownloadCallbacks, DownloadResult, download_file_with_verification};

#[tokio::main]
async fn main() -> Result<(), ClientLibError> {
    let callbacks = DownloadCallbacks::default()
        .with_file_download_progress(|args| {
            if let Some(total) = args.total_bytes {
                println!(
                    "Progress: {:.1}%",
                    (args.bytes_downloaded as f64 / total as f64) * 100.0
                );
            }
        })
        .with_completed(|args| {
            println!("Download complete: {:?}", args.result.file_path);
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
