use crate::error::Result;
use client_lib::{DownloadCallbacks, constants::ONE_MEGABYTE, download_file_with_verification};
use std::{io::Write, path::PathBuf};

pub async fn handle_download_command(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
) -> Result<()> {
    let callbacks = DownloadCallbacks::default()
        .with_starting(|args| {
            println!("Starting download: {}", args.file_url);
        })
        .with_signers_downloaded(|args| {
            println!("✓ Downloaded signers file ({} bytes)", args.bytes);
        })
        .with_index_downloaded(|args| {
            println!("✓ Downloaded index file ({} bytes)", args.bytes);
        })
        .with_signatures_downloaded(|args| {
            println!("✓ Downloaded signatures file ({} bytes)", args.bytes);
        })
        .with_signatures_verified(|args| {
            if args.invalid_count > 0 {
                println!("⚠ Warning: {} invalid signature(s)", args.invalid_count);
            }
            println!("✓ Signatures verified successfully ({} valid)", args.valid_count);
        })
        .with_file_hash_verified(|args| {
            println!(
                "✓ File hash verified ({})",
                match args.algorithm {
                    features_lib::HashAlgorithm::Sha256 => "SHA-256",
                    features_lib::HashAlgorithm::Sha512 => "SHA-512",
                    features_lib::HashAlgorithm::Sha1 => "SHA-1",
                    features_lib::HashAlgorithm::Md5 => "MD5",
                }
            );
        })
        .with_file_download_started(|args| {
            println!("Downloading {}", args.filename);
            if let Some(size) = args.total_bytes {
                println!("  Size: {:.2} MB", size as f64 / ONE_MEGABYTE as f64);
            }
        })
        .with_file_download_progress(|args| {
            if let Some(total) = args.total_bytes {
                let percent = (args.bytes_downloaded as f64 / total as f64) * 100.0;
                print!(
                    "\rProgress: {:.1}% ({:.2} MB / {:.2} MB)",
                    percent,
                    args.bytes_downloaded as f64 / ONE_MEGABYTE as f64,
                    total as f64 / ONE_MEGABYTE as f64
                );
                let _ = std::io::stdout().flush();
            }
        })
        .with_file_download_completed(|args| {
            println!(); // New line after progress
            println!(
                "✓ Download complete ({:.2} MB)",
                args.bytes_downloaded as f64 / ONE_MEGABYTE as f64
            );
        })
        .with_file_saved(|args| {
            println!("✓ File saved to: {}", args.path.display());
        })
        .with_completed(|args| {
            println!(
                "✓ All done! Verified {} signature(s)",
                args.result.signatures_verified
            );
        });

    download_file_with_verification(file_url, output, backend_url, &callbacks).await?;

    Ok(())
}
