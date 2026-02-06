# client-lib

A library for downloading and verifying files from Asfaload-backed sources.

## Features

- Type-safe error handling with `thiserror`
- Event-driven progress reporting
- Streaming downloads with byte-level progress
- Signature verification
- Hash verification

## Usage

See `examples/simple_download.rs` for a complete example of how to use the library.

## Callbacks

The library reports progress through a `DownloadCallbacks` builder. Register only the callbacks you need:

```rust
use client_lib::{download_file_with_verification, DownloadCallbacks, DownloadResult};

let callbacks = DownloadCallbacks::default()
    .with_file_download_progress(|args| {
        if let Some(total) = args.total_bytes {
            let percent = (args.bytes_downloaded as f64 / total as f64) * 100.0;
            println!("Progress: {:.1}%", percent);
        }
    });

let result = download_file_with_verification(
    file_url,
    output,
    backend_url,
    &callbacks,
).await?;
```

**Available callbacks:** `with_starting`, `with_signers_downloaded`, `with_index_downloaded`, `with_signatures_downloaded`, `with_signatures_verified`, `with_file_download_started`, `with_file_download_progress`, `with_chunk_received`, `with_file_download_completed`, `with_file_hash_verified`, `with_file_saved`, `with_completed`.

**Progress frequency:** Progress events are emitted at approximately 10% intervals or every 1MB, whichever comes first.

**Note:** Progress events are only emitted for the main file download. Metadata downloads (signers, index, signatures) do not emit progress events.

## Error Handling

The library uses typed errors via `thiserror`. See `ClientLibError` in `src/error.rs` for all error variants.
