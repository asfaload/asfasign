use crate::path_validation::NormalisedPaths;
use common::errors::SignedFileError;
use features_lib::AsfaloadPublicKeys;

pub mod walkdir_impl;

pub use walkdir_impl::WalkdirPendingDiscovery;

/// Trait for discovering pending signature files in the mirror.
///
/// This trait abstracts the discovery mechanism to allow different
/// implementations (walkdir, ripgrep, etc.) without changing the calling code.
pub trait PendingSignaturesDiscovery: Send + Sync {
    /// Find all pending signature files in the repository.
    ///
    /// Returns paths to `.signatures.json.pending` files relative to base_path.
    fn find_all_pending(
        &self,
        base_path: &NormalisedPaths,
    ) -> Result<Vec<NormalisedPaths>, SignedFileError>;

    /// Find pending signature files for a specific signer.
    ///
    /// Returns paths where the signer is authorized but has not yet signed.
    /// This includes checking both authorization (is signer in the signers file)
    /// and existing signatures (has signer already contributed).
    fn find_pending_for_signer(
        &self,
        base_path: &NormalisedPaths,
        signer: &AsfaloadPublicKeys,
    ) -> Result<Vec<NormalisedPaths>, SignedFileError>;
}

/// Create the default pending discovery implementation.
///
/// Currently returns a Walkdir-based implementation, but can be
/// changed to return other implementations without affecting callers.
pub fn create_default_discovery() -> Box<dyn PendingSignaturesDiscovery> {
    Box::new(WalkdirPendingDiscovery::new())
}
