use crate::path_validation::NormalisedPaths;
use common::fs::names::pending_signatures_path_for;
use rest_api_types::errors::ApiError;

/// Creates an empty aggregate signature file for a given file path.
///
/// # Arguments
/// * `file_path` - The path to the file that needs an aggregate signature
///
/// # Returns
/// * `Ok(NormalisedPaths)` - The path to the created signature file
/// * `Err(ApiError)` - If the signature file could not be created
pub async fn create_empty_aggregate_signature(
    file_path: &NormalisedPaths,
) -> Result<NormalisedPaths, ApiError> {
    let pending_sig_path = pending_signatures_path_for(file_path)?;

    tokio::fs::write(&pending_sig_path, "{}")
        .await
        .map_err(|e| {
            ApiError::FileWriteFailed(format!(
                "Failed to write signature file {}: {}",
                pending_sig_path.display(),
                e
            ))
        })?;

    let repo_path = file_path.base_dir();
    let relative_path = pending_sig_path.strip_prefix(&repo_path).map_err(|e| {
        ApiError::InvalidFilePath(format!("Failed to compute relative path: {}", e))
    })?;

    NormalisedPaths::new(&repo_path, relative_path).await
}
