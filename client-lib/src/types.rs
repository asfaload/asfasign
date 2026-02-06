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

#[allow(clippy::type_complexity)]
#[derive(Default)]
pub struct DownloadCallbacks {
    pub on_starting: Option<Box<dyn Fn(&str) + Send>>,
    pub on_signers_downloaded: Option<Box<dyn Fn(usize) + Send>>,
    pub on_index_downloaded: Option<Box<dyn Fn(usize) + Send>>,
    pub on_signatures_downloaded: Option<Box<dyn Fn(usize) + Send>>,
    pub on_signatures_verified: Option<Box<dyn Fn(usize, usize) + Send>>,
    pub on_file_download_started: Option<Box<dyn Fn(&str, Option<u64>) + Send>>,
    pub on_file_download_progress: Option<Box<dyn Fn(u64, Option<u64>, usize) + Send>>,
    // Note that although this function is Fn and not FnMut, you can still maintain
    // a changing state using an Arc (and for thread safety Atomic values)
    pub on_chunk_received: Option<Box<dyn Fn(&[u8]) + Send>>,
    pub on_file_download_completed: Option<Box<dyn Fn(u64) + Send>>,
    pub on_file_hash_verified: Option<Box<dyn Fn(HashAlgorithm) + Send>>,
    pub on_file_saved: Option<Box<dyn Fn(&std::path::Path) + Send>>,
    pub on_completed: Option<Box<dyn Fn(&DownloadResult) + Send>>,
}

impl DownloadCallbacks {
    pub fn with_starting<F: Fn(&str) + Send + 'static>(mut self, f: F) -> Self {
        self.on_starting = Some(Box::new(f));
        self
    }

    pub fn with_signers_downloaded<F: Fn(usize) + Send + 'static>(mut self, f: F) -> Self {
        self.on_signers_downloaded = Some(Box::new(f));
        self
    }

    pub fn with_index_downloaded<F: Fn(usize) + Send + 'static>(mut self, f: F) -> Self {
        self.on_index_downloaded = Some(Box::new(f));
        self
    }

    pub fn with_signatures_downloaded<F: Fn(usize) + Send + 'static>(mut self, f: F) -> Self {
        self.on_signatures_downloaded = Some(Box::new(f));
        self
    }

    pub fn with_signatures_verified<F: Fn(usize, usize) + Send + 'static>(mut self, f: F) -> Self {
        self.on_signatures_verified = Some(Box::new(f));
        self
    }

    pub fn with_file_download_started<F: Fn(&str, Option<u64>) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_file_download_started = Some(Box::new(f));
        self
    }

    pub fn with_file_download_progress<F: Fn(u64, Option<u64>, usize) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_file_download_progress = Some(Box::new(f));
        self
    }

    pub fn with_chunk_received<F: Fn(&[u8]) + Send + 'static>(mut self, f: F) -> Self {
        self.on_chunk_received = Some(Box::new(f));
        self
    }

    pub fn with_file_download_completed<F: Fn(u64) + Send + 'static>(mut self, f: F) -> Self {
        self.on_file_download_completed = Some(Box::new(f));
        self
    }

    pub fn with_file_hash_verified<F: Fn(HashAlgorithm) + Send + 'static>(mut self, f: F) -> Self {
        self.on_file_hash_verified = Some(Box::new(f));
        self
    }

    pub fn with_file_saved<F: Fn(&std::path::Path) + Send + 'static>(mut self, f: F) -> Self {
        self.on_file_saved = Some(Box::new(f));
        self
    }

    pub fn with_completed<F: Fn(&DownloadResult) + Send + 'static>(mut self, f: F) -> Self {
        self.on_completed = Some(Box::new(f));
        self
    }
}

impl DownloadCallbacks {
    pub(crate) fn emit_starting(&self, file_url: &str) {
        if let Some(ref f) = self.on_starting {
            f(file_url);
        }
    }

    pub(crate) fn emit_signers_downloaded(&self, bytes: usize) {
        if let Some(ref f) = self.on_signers_downloaded {
            f(bytes);
        }
    }

    pub(crate) fn emit_index_downloaded(&self, bytes: usize) {
        if let Some(ref f) = self.on_index_downloaded {
            f(bytes);
        }
    }

    pub(crate) fn emit_signatures_downloaded(&self, bytes: usize) {
        if let Some(ref f) = self.on_signatures_downloaded {
            f(bytes);
        }
    }

    pub(crate) fn emit_signatures_verified(&self, valid_count: usize, invalid_count: usize) {
        if let Some(ref f) = self.on_signatures_verified {
            f(valid_count, invalid_count);
        }
    }

    pub(crate) fn emit_file_download_started(&self, filename: &str, total_bytes: Option<u64>) {
        if let Some(ref f) = self.on_file_download_started {
            f(filename, total_bytes);
        }
    }

    pub(crate) fn emit_file_download_progress(
        &self,
        bytes_downloaded: u64,
        total_bytes: Option<u64>,
        chunk_size: usize,
    ) {
        if let Some(ref f) = self.on_file_download_progress {
            f(bytes_downloaded, total_bytes, chunk_size);
        }
    }

    pub(crate) fn emit_chunk_received(&self, chunk: &[u8]) {
        if let Some(ref f) = self.on_chunk_received {
            f(chunk);
        }
    }

    pub(crate) fn emit_file_download_completed(&self, bytes_downloaded: u64) {
        if let Some(ref f) = self.on_file_download_completed {
            f(bytes_downloaded);
        }
    }

    pub(crate) fn emit_file_hash_verified(&self, algorithm: HashAlgorithm) {
        if let Some(ref f) = self.on_file_hash_verified {
            f(algorithm);
        }
    }

    pub(crate) fn emit_file_saved(&self, path: &std::path::Path) {
        if let Some(ref f) = self.on_file_saved {
            f(path);
        }
    }

    pub(crate) fn emit_completed(&self, result: &DownloadResult) {
        if let Some(ref f) = self.on_completed {
            f(result);
        }
    }
}
