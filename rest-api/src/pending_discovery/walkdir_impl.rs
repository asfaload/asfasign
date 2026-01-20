use crate::path_validation::build_normalised_absolute_path;
use crate::path_validation::NormalisedPaths;
use common::errors::SignedFileError;

pub struct WalkdirPendingDiscovery;

impl Default for WalkdirPendingDiscovery {
    fn default() -> Self {
        Self
    }
}

impl WalkdirPendingDiscovery {
    pub fn new() -> Self {
        Self
    }
}

impl super::PendingSignaturesDiscovery for WalkdirPendingDiscovery {
    fn find_all_pending(&self, base_path: &NormalisedPaths) -> Result<Vec<NormalisedPaths>, SignedFileError> {
        let mut pending_files = Vec::new();
        let base = base_path.absolute_path();

        for entry in walkdir::WalkDir::new(&base)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".signatures.json.pending"))
                .unwrap_or(false)
            {
                if let Ok(relative_path) = path.strip_prefix(&base) {
                    match build_normalised_absolute_path(base.clone(), relative_path) {
                        Ok(normalised) => pending_files.push(normalised),
                        Err(e) => {
                            tracing::warn!("Failed to normalize path {}: {}", path.display(), e);
                        }
                    }
                } else {
                    tracing::warn!("File {} is not under base path {}", path.display(), base.display());
                }
            }
        }

        Ok(pending_files)
    }

    fn find_pending_for_signer(
        &self,
        _base_path: &NormalisedPaths,
        _signer: &features_lib::AsfaloadPublicKeys,
    ) -> Result<Vec<NormalisedPaths>, SignedFileError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending_discovery::PendingSignaturesDiscovery;
    use crate::path_validation::build_normalised_absolute_path;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_find_all_pending_discovers_pending_files() {
        let temp_dir = TempDir::new().unwrap();
        let normalised = build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let file1 = temp_dir.path().join("nested/file1.txt.signatures.json.pending");
        let file2 = temp_dir.path().join("nested/file2.txt.signatures.json.pending");
        fs::create_dir_all(file1.parent().unwrap()).unwrap();
        fs::write(&file1, "sig1").unwrap();
        fs::write(&file2, "sig2").unwrap();

        let complete = temp_dir.path().join("complete.txt.signatures.json");
        fs::write(&complete, "complete").unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();

        assert_eq!(result.len(), 2);
        let paths: Vec<String> = result.iter()
            .map(|p| p.relative_path().display().to_string())
            .collect();
        assert!(paths.contains(&"nested/file1.txt.signatures.json.pending".to_string()));
        assert!(paths.contains(&"nested/file2.txt.signatures.json.pending".to_string()));
    }

    #[test]
    fn test_find_all_pending_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let normalised = build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();

        assert!(result.is_empty());
    }
}
