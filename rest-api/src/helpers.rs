use common::fs::names::pending_signatures_path_for;
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use signatures::signatures_file::SignaturesFile;

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

    let sig_file = SignaturesFile::new();
    let json = common::to_posix_json(&sig_file).map_err(|e| {
        ApiError::FileWriteFailed(format!("Failed to serialize empty signatures file: {}", e))
    })?;
    tokio::fs::write(&pending_sig_path, json)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_signatures_file_has_trailing_newline() {
        let tmp = tempfile::TempDir::new().unwrap();
        let artifact = tmp.path().join("artifact.bin");
        std::fs::write(&artifact, b"content").unwrap();
        let file_path = NormalisedPaths::new(tmp.path(), "artifact.bin")
            .await
            .unwrap();
        let written = create_empty_aggregate_signature(&file_path).await.unwrap();
        let bytes = std::fs::read_to_string(written.absolute_path()).unwrap();
        assert!(
            bytes.ends_with("}\n"),
            "file should end with }}\\n, got: {:?}",
            bytes
        );
        assert!(
            !bytes.ends_with("\n\n"),
            "file must not end with double newline"
        );
    }
}
