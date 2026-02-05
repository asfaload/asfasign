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

## Progress Events

The library emits real-time progress events during file downloads via `FileDownloadProgress`.

Example:

```rust
|event| match event {
    DownloadEvent::FileDownloadProgress { bytes_downloaded, total_bytes, chunk_size } => {
        if let Some(total) = total_bytes {
            let percent = (bytes_downloaded as f64 / total as f64) * 100.0;
            println!("Progress: {:.1}% ({:.2} MB / {:.2} MB)",
                percent,
                bytes_downloaded as f64 / 1_048_576.0,
                total as f64 / 1_048_576.0
            );
        }
    }
    // ... handle other events
}
```

**FileDownloadProgress includes:**
- `bytes_downloaded`: Total bytes downloaded so far
- `total_bytes`: Total file size (if available, `None` if server doesn't provide Content-Length)
- `chunk_size`: Size of the last downloaded chunk

**Event frequency:** Progress events are emitted at approximately 10% intervals or every 1MB, whichever comes first. This provides good progress visibility without event spam.

**Note:** Progress events are only emitted for the main file download. Metadata downloads (signers, index, signatures) do not emit progress events to avoid unnecessary noise.

## API

The main API is `download_file_with_verification`:

```rust
use client_lib::{download_file_with_verification, DownloadEvent, DownloadResult};

let result = download_file_with_verification(
    file_url,
    output,
    backend_url,
    |event| {
        // Handle progress events
    },
).await?;
```

## Error Handling

The library uses typed errors via `thiserror`. See `ClientLibError` in `src/error.rs` for all error variants.
