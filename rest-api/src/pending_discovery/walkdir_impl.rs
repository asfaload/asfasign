use crate::path_validation::build_normalised_absolute_path;
use crate::path_validation::NormalisedPaths;
use common::errors::{AggregateSignatureError, SignedFileError};

pub fn can_signer_add_signature(
    pending_sig_path: &NormalisedPaths,
    signer: &features_lib::AsfaloadPublicKeys,
) -> Result<bool, SignedFileError> {
    use features_lib::aggregate_signature_helpers::{get_authorized_signers_for_file, get_individual_signatures};

    let authorized = get_authorized_signers_for_file(pending_sig_path.absolute_path())
        .map_err(|e| SignedFileError::AggregateSignatureError(
            AggregateSignatureError::LogicError(format!("Failed to get authorized signers: {}", e))
        ))?;

    if !authorized.contains(signer) {
        return Ok(false);
    }

    let existing_signatures = get_individual_signatures(pending_sig_path.absolute_path())
        .map_err(|e| SignedFileError::AggregateSignatureError(
            AggregateSignatureError::LogicError(format!("Failed to get existing signatures: {}", e))
        ))?;

    Ok(!existing_signatures.contains_key(signer))
}

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
    use common::fs::names::pending_signatures_path_for;
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, sha512_for_file};
    use signers_file_types::SignersConfig;
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

    #[test]
    fn test_can_signer_add_signature_authorized() {
        let temp_dir = TempDir::new().unwrap();

        let key_pair = features_lib::AsfaloadKeyPairs::new("test_pwd").unwrap();
        let public_key = key_pair.public_key();

        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1)
        ).unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let artifact_dir = temp_dir.path().join("nested");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        let signers_dir = temp_dir.path().join("asfaload.signers");
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join("index.json"), signers_json).unwrap();

        let pending_sig_path = pending_signatures_path_for(&artifact_path).unwrap();
        let pending_content = serde_json::json!({});
        fs::write(&pending_sig_path, pending_content.to_string()).unwrap();

        let normalised = build_normalised_absolute_path(temp_dir.path(), pending_sig_path.strip_prefix(temp_dir.path()).unwrap()).unwrap();

        let result = can_signer_add_signature(&normalised, &public_key);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_can_signer_add_signature_unauthorized() {
        let temp_dir = TempDir::new().unwrap();

        let key_pair1 = features_lib::AsfaloadKeyPairs::new("test_pwd1").unwrap();
        let key_pair2 = features_lib::AsfaloadKeyPairs::new("test_pwd2").unwrap();
        let public_key1 = key_pair1.public_key();
        let public_key2 = key_pair2.public_key();

        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key1.clone()], 1)
        ).unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let artifact_dir = temp_dir.path().join("nested");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        let signers_dir = temp_dir.path().join("asfaload.signers");
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join("index.json"), signers_json).unwrap();

        let pending_sig_path = pending_signatures_path_for(&artifact_path).unwrap();
        fs::write(&pending_sig_path, "{}").unwrap();

        let normalised = build_normalised_absolute_path(temp_dir.path(), pending_sig_path.strip_prefix(temp_dir.path()).unwrap()).unwrap();

        let result = can_signer_add_signature(&normalised, &public_key2);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_can_signer_add_signature_already_signed() {
        let temp_dir = TempDir::new().unwrap();

        let key_pair = features_lib::AsfaloadKeyPairs::new("test_pwd").unwrap();
        let public_key = key_pair.public_key();

        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![public_key.clone()], 1)
        ).unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let artifact_dir = temp_dir.path().join("nested");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("artifact.txt");
        fs::write(&artifact_path, "content").unwrap();

        let signers_dir = temp_dir.path().join("asfaload.signers");
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join("index.json"), signers_json).unwrap();

        let pending_sig_path = pending_signatures_path_for(&artifact_path).unwrap();
        let hash = sha512_for_file(&artifact_path).unwrap();
        let secret_key = key_pair.secret_key("test_pwd").unwrap();
        let signature = secret_key.sign(&hash).unwrap();
        let pending_content = serde_json::json!({
            public_key.to_base64(): signature.to_base64()
        });
        fs::write(&pending_sig_path, pending_content.to_string()).unwrap();

        let normalised = build_normalised_absolute_path(temp_dir.path(), pending_sig_path.strip_prefix(temp_dir.path()).unwrap()).unwrap();

        let result = can_signer_add_signature(&normalised, &public_key);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
