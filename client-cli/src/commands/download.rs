use crate::error::Result;
use client_lib::{DownloadCallbacks, constants::ONE_MEGABYTE, download_file_with_verification};
use std::{io::Write, path::PathBuf};

pub async fn handle_download_command(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
) -> Result<()> {
    let callbacks = DownloadCallbacks::default()
        .with_starting(|file_url| {
            println!("Starting download: {}", file_url);
        })
        .with_signers_downloaded(|bytes| {
            println!("✓ Downloaded signers file ({} bytes)", bytes);
        })
        .with_index_downloaded(|bytes| {
            println!("✓ Downloaded index file ({} bytes)", bytes);
        })
        .with_signatures_downloaded(|bytes| {
            println!("✓ Downloaded signatures file ({} bytes)", bytes);
        })
        .with_signatures_verified(|valid_count, invalid_count| {
            if invalid_count > 0 {
                println!("⚠ Warning: {} invalid signature(s)", invalid_count);
            }
            println!("✓ Signatures verified successfully ({} valid)", valid_count);
        })
        .with_file_hash_verified(|algorithm| {
            println!(
                "✓ File hash verified ({})",
                match algorithm {
                    features_lib::HashAlgorithm::Sha256 => "SHA-256",
                    features_lib::HashAlgorithm::Sha512 => "SHA-512",
                    features_lib::HashAlgorithm::Sha1 => "SHA-1",
                    features_lib::HashAlgorithm::Md5 => "MD5",
                }
            );
        })
        .with_file_download_started(|filename, total_bytes| {
            println!("Downloading {}", filename);
            if let Some(size) = total_bytes {
                println!("  Size: {:.2} MB", size as f64 / ONE_MEGABYTE as f64);
            }
        })
        .with_file_download_progress(|bytes_downloaded, total_bytes, _chunk_size| {
            if let Some(total) = total_bytes {
                let percent = (bytes_downloaded as f64 / total as f64) * 100.0;
                print!(
                    "\rProgress: {:.1}% ({:.2} MB / {:.2} MB)",
                    percent,
                    bytes_downloaded as f64 / ONE_MEGABYTE as f64,
                    total as f64 / ONE_MEGABYTE as f64
                );
                let _ = std::io::stdout().flush();
            }
        })
        .with_file_download_completed(|bytes_downloaded| {
            println!(); // New line after progress
            println!(
                "✓ Download complete ({:.2} MB)",
                bytes_downloaded as f64 / ONE_MEGABYTE as f64
            );
        })
        .with_file_saved(|path| {
            println!("✓ File saved to: {}", path.display());
        })
        .with_completed(|result| {
            println!(
                "✓ All done! Verified {} signature(s)",
                result.signatures_verified
            );
        });

    download_file_with_verification(file_url, output, backend_url, &callbacks).await?;

    Ok(())
}
