use crate::ClientLibError;
use features_lib::HashAlgorithm;
use std::fmt;
use std::path::PathBuf;

/// Strongly-typed wrapper for computed file hashes.
///
/// Binds the hash algorithm to its hex-encoded value at the type level,
/// preventing algorithm/value mismatches.
#[derive(Clone, Debug)]
pub enum ComputedHash {
    /// SHA-256 hash (32 bytes, 64 hex characters)
    Sha256(String),
    /// SHA-512 hash (64 bytes, 128 hex characters)
    Sha512(String),
}

impl ComputedHash {
    /// Get the hex-encoded hash value.
    pub fn hex_value(&self) -> &str {
        match self {
            ComputedHash::Sha256(h) | ComputedHash::Sha512(h) => h,
        }
    }

    /// Get the hash algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        match self {
            ComputedHash::Sha256(_) => HashAlgorithm::Sha256,
            ComputedHash::Sha512(_) => HashAlgorithm::Sha512,
        }
    }

    /// Create from a `HashAlgorithm` and hex string.
    /// Returns an error for unsupported algorithms (Sha1, Md5).
    pub fn from_algorithm_and_hex(
        algo: HashAlgorithm,
        hex: impl Into<String>,
    ) -> Result<Self, ClientLibError> {
        match algo {
            HashAlgorithm::Sha256 => Ok(ComputedHash::Sha256(hex.into())),
            HashAlgorithm::Sha512 => Ok(ComputedHash::Sha512(hex.into())),
            unsupported => Err(ClientLibError::UnsupportedHashAlgorithm(unsupported)),
        }
    }
}

impl PartialEq for ComputedHash {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm() == other.algorithm()
            && self.hex_value().eq_ignore_ascii_case(other.hex_value())
    }
}

impl Eq for ComputedHash {}

impl fmt::Display for ComputedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComputedHash::Sha256(h) => write!(f, "sha256:{}", h),
            ComputedHash::Sha512(h) => write!(f, "sha512:{}", h),
        }
    }
}

#[derive(Clone)]
pub struct StartingArgs {
    pub file_url: String,
}

#[derive(Clone)]
pub struct SignersDownloadedArgs {
    pub bytes: usize,
}

#[derive(Clone)]
pub struct IndexDownloadedArgs {
    pub bytes: usize,
}

#[derive(Clone)]
pub struct SignaturesDownloadedArgs {
    pub bytes: usize,
}

#[derive(Clone)]
pub struct SignaturesVerifiedArgs {
    pub valid_count: usize,
    pub invalid_count: usize,
}

#[derive(Clone)]
pub struct FileDownloadStartedArgs {
    pub filename: String,
    pub total_bytes: Option<u64>,
}

#[derive(Clone)]
pub struct FileDownloadProgressArgs {
    pub bytes_downloaded: u64,
    pub total_bytes: Option<u64>,
    pub chunk_size: usize,
}

#[derive(Clone)]
pub struct ChunkReceivedArgs {
    pub chunk: Vec<u8>,
}

#[derive(Clone)]
pub struct FileDownloadCompletedArgs {
    pub bytes_downloaded: u64,
}

#[derive(Clone)]
pub struct FileHashVerifiedArgs {
    pub algorithm: HashAlgorithm,
}

#[derive(Clone)]
pub struct FileSavedArgs {
    pub path: PathBuf,
}

#[derive(Clone)]
pub struct CompletedArgs {
    pub result: DownloadResult,
}

#[derive(Clone)]
pub struct DownloadResult {
    pub file_path: PathBuf,
    pub bytes_downloaded: u64,
    pub signatures_verified: usize,
    pub signatures_invalid: usize,
    pub computed_hash: ComputedHash,
}

#[allow(clippy::type_complexity)]
#[derive(Default)]
pub struct DownloadCallbacks {
    pub on_starting: Option<Box<dyn Fn(&StartingArgs) + Send>>,
    pub on_signers_downloaded: Option<Box<dyn Fn(&SignersDownloadedArgs) + Send>>,
    pub on_index_downloaded: Option<Box<dyn Fn(&IndexDownloadedArgs) + Send>>,
    pub on_signatures_downloaded: Option<Box<dyn Fn(&SignaturesDownloadedArgs) + Send>>,
    pub on_signatures_verified: Option<Box<dyn Fn(&SignaturesVerifiedArgs) + Send>>,
    pub on_file_download_started: Option<Box<dyn Fn(&FileDownloadStartedArgs) + Send>>,
    pub on_file_download_progress: Option<Box<dyn Fn(&FileDownloadProgressArgs) + Send>>,
    // Note that although this function is Fn and not FnMut, you can still maintain
    // a changing state using an Arc (and for thread safety Atomic values)
    pub on_chunk_received: Option<Box<dyn Fn(&ChunkReceivedArgs) + Send>>,
    pub on_file_download_completed: Option<Box<dyn Fn(&FileDownloadCompletedArgs) + Send>>,
    pub on_file_hash_verified: Option<Box<dyn Fn(&FileHashVerifiedArgs) + Send>>,
    pub on_file_saved: Option<Box<dyn Fn(&FileSavedArgs) + Send>>,
    pub on_completed: Option<Box<dyn Fn(&CompletedArgs) + Send>>,
}

impl DownloadCallbacks {
    pub fn with_starting<F: Fn(&StartingArgs) + Send + 'static>(mut self, f: F) -> Self {
        self.on_starting = Some(Box::new(f));
        self
    }

    pub fn with_signers_downloaded<F: Fn(&SignersDownloadedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_signers_downloaded = Some(Box::new(f));
        self
    }

    pub fn with_index_downloaded<F: Fn(&IndexDownloadedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_index_downloaded = Some(Box::new(f));
        self
    }

    pub fn with_signatures_downloaded<F: Fn(&SignaturesDownloadedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_signatures_downloaded = Some(Box::new(f));
        self
    }

    pub fn with_signatures_verified<F: Fn(&SignaturesVerifiedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_signatures_verified = Some(Box::new(f));
        self
    }

    pub fn with_file_download_started<F: Fn(&FileDownloadStartedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_file_download_started = Some(Box::new(f));
        self
    }

    pub fn with_file_download_progress<F: Fn(&FileDownloadProgressArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_file_download_progress = Some(Box::new(f));
        self
    }

    pub fn with_chunk_received<F: Fn(&ChunkReceivedArgs) + Send + 'static>(mut self, f: F) -> Self {
        self.on_chunk_received = Some(Box::new(f));
        self
    }

    pub fn with_file_download_completed<F: Fn(&FileDownloadCompletedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_file_download_completed = Some(Box::new(f));
        self
    }

    pub fn with_file_hash_verified<F: Fn(&FileHashVerifiedArgs) + Send + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_file_hash_verified = Some(Box::new(f));
        self
    }

    pub fn with_file_saved<F: Fn(&FileSavedArgs) + Send + 'static>(mut self, f: F) -> Self {
        self.on_file_saved = Some(Box::new(f));
        self
    }

    pub fn with_completed<F: Fn(&CompletedArgs) + Send + 'static>(mut self, f: F) -> Self {
        self.on_completed = Some(Box::new(f));
        self
    }
}

impl DownloadCallbacks {
    pub(crate) fn emit_starting(&self, file_url: &str) {
        if let Some(ref f) = self.on_starting {
            let args = StartingArgs {
                file_url: file_url.to_string(),
            };
            f(&args);
        }
    }

    pub(crate) fn emit_signers_downloaded(&self, bytes: usize) {
        if let Some(ref f) = self.on_signers_downloaded {
            let args = SignersDownloadedArgs { bytes };
            f(&args);
        }
    }

    pub(crate) fn emit_index_downloaded(&self, bytes: usize) {
        if let Some(ref f) = self.on_index_downloaded {
            let args = IndexDownloadedArgs { bytes };
            f(&args);
        }
    }

    pub(crate) fn emit_signatures_downloaded(&self, bytes: usize) {
        if let Some(ref f) = self.on_signatures_downloaded {
            let args = SignaturesDownloadedArgs { bytes };
            f(&args);
        }
    }

    pub(crate) fn emit_signatures_verified(&self, valid_count: usize, invalid_count: usize) {
        if let Some(ref f) = self.on_signatures_verified {
            let args = SignaturesVerifiedArgs {
                valid_count,
                invalid_count,
            };
            f(&args);
        }
    }

    pub(crate) fn emit_file_download_started(&self, filename: &str, total_bytes: Option<u64>) {
        if let Some(ref f) = self.on_file_download_started {
            let args = FileDownloadStartedArgs {
                filename: filename.to_string(),
                total_bytes,
            };
            f(&args);
        }
    }

    pub(crate) fn emit_file_download_progress(
        &self,
        bytes_downloaded: u64,
        total_bytes: Option<u64>,
        chunk_size: usize,
    ) {
        if let Some(ref f) = self.on_file_download_progress {
            let args = FileDownloadProgressArgs {
                bytes_downloaded,
                total_bytes,
                chunk_size,
            };
            f(&args);
        }
    }

    pub(crate) fn emit_chunk_received(&self, chunk: &[u8]) {
        if let Some(ref f) = self.on_chunk_received {
            let args = ChunkReceivedArgs {
                chunk: chunk.to_vec(),
            };
            f(&args);
        }
    }

    pub(crate) fn emit_file_download_completed(&self, bytes_downloaded: u64) {
        if let Some(ref f) = self.on_file_download_completed {
            let args = FileDownloadCompletedArgs { bytes_downloaded };
            f(&args);
        }
    }

    pub(crate) fn emit_file_hash_verified(&self, algorithm: HashAlgorithm) {
        if let Some(ref f) = self.on_file_hash_verified {
            let args = FileHashVerifiedArgs { algorithm };
            f(&args);
        }
    }

    pub(crate) fn emit_file_saved(&self, path: &std::path::Path) {
        if let Some(ref f) = self.on_file_saved {
            let args = FileSavedArgs {
                path: path.to_path_buf(),
            };
            f(&args);
        }
    }

    pub(crate) fn emit_completed(&self, result: &DownloadResult) {
        if let Some(ref f) = self.on_completed {
            let args = CompletedArgs {
                result: result.clone(),
            };
            f(&args);
        }
    }
}

#[cfg(test)]
mod computed_hash_tests {
    use super::*;

    #[test]
    fn sha256_creation_and_accessors() {
        let hash = ComputedHash::Sha256("abc123".to_string());
        assert_eq!(hash.hex_value(), "abc123");
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha256);
    }

    #[test]
    fn sha512_creation_and_accessors() {
        let hash = ComputedHash::Sha512("def456".to_string());
        assert_eq!(hash.hex_value(), "def456");
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha512);
    }

    #[test]
    fn equality_same_algorithm_same_value() {
        let a = ComputedHash::Sha256("abc".to_string());
        let b = ComputedHash::Sha256("abc".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_values() {
        let a = ComputedHash::Sha256("abc".to_string());
        let b = ComputedHash::Sha256("def".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_algorithms() {
        let a = ComputedHash::Sha256("abc".to_string());
        let b = ComputedHash::Sha512("abc".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn case_insensitive_comparison() {
        let a = ComputedHash::Sha256("ABC123".to_string());
        let b = ComputedHash::Sha256("abc123".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn from_algorithm_and_hex_sha256() {
        let hash = ComputedHash::from_algorithm_and_hex(HashAlgorithm::Sha256, "abc123").unwrap();
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(hash.hex_value(), "abc123");
    }

    #[test]
    fn from_algorithm_and_hex_sha512() {
        let hash = ComputedHash::from_algorithm_and_hex(HashAlgorithm::Sha512, "def456").unwrap();
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha512);
        assert_eq!(hash.hex_value(), "def456");
    }

    #[test]
    fn from_algorithm_and_hex_unsupported() {
        match ComputedHash::from_algorithm_and_hex(HashAlgorithm::Sha1, "abc") {
            Err(ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Sha1)) => {}
            Err(e) => panic!("Expected UnsupportedHashAlgorithm(Sha1), got: {e:?}"),
            Ok(_) => panic!("Expected error for unsupported algorithm, got Ok"),
        }
    }

    #[test]
    fn display_sha256() {
        let hash = ComputedHash::Sha256("abc123".to_string());
        assert_eq!(hash.to_string(), "sha256:abc123");
    }

    #[test]
    fn display_sha512() {
        let hash = ComputedHash::Sha512("def456".to_string());
        assert_eq!(hash.to_string(), "sha512:def456");
    }
}
