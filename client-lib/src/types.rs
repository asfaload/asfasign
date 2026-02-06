use features_lib::HashAlgorithm;
use std::path::PathBuf;

pub enum DownloadEvent {
    Starting {
        file_url: String,
    },
    SignersDownloaded {
        bytes: usize,
    },
    IndexDownloaded {
        bytes: usize,
    },
    SignaturesDownloaded {
        bytes: usize,
    },
    SignaturesVerified {
        valid_count: usize,
        invalid_count: usize,
    },
    FileHashVerified {
        algorithm: HashAlgorithm,
    },
    FileDownloadStarted {
        filename: String,
        total_bytes: Option<u64>,
    },
    FileDownloadProgress {
        bytes_downloaded: u64,
        total_bytes: Option<u64>,
        chunk_size: usize,
    },
    FileDownloadCompleted {
        bytes_downloaded: u64,
    },
    FileSaved {
        path: PathBuf,
    },
    Completed(DownloadResult),
    ChunkReceived {
        chunk: Vec<u8>,
    },
}

#[derive(Clone)]
pub struct DownloadResult {
    pub file_path: PathBuf,
    pub bytes_downloaded: u64,
    pub signatures_verified: usize,
    pub signatures_invalid: usize,
    pub hash_algorithm: HashAlgorithm,
}
