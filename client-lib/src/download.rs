mod revocation;
mod v1;

// Re-export v1's download function as the current API surface
pub use v1::download_file_with_verification;

// The download-path forge layer now lives in forge-url. Re-export so in-crate
// callers (download/revocation.rs and download/v1.rs via `super::`) keep their
// import paths.
pub use forge_url::ForgesPathMethods;
pub use forge_url::forges::{Forges, get_forge};
