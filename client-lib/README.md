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
