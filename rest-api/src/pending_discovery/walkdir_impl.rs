use crate::path_validation::NormalisedPaths;
use crate::path_validation::build_normalised_absolute_path;
use common::errors::SignedFileError;
use constants::PENDING_SIGNATURES_SUFFIX;
use features_lib::can_signer_add_signature;

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
    fn find_all_pending(
        &self,
        base_path: &NormalisedPaths,
    ) -> Result<Vec<NormalisedPaths>, SignedFileError> {
        let mut pending_files = Vec::new();
        let base = base_path.absolute_path();

        for entry_result in walkdir::WalkDir::new(&base).into_iter() {
            match entry_result {
                Ok(entry) => {
                    let path = entry.path();

                    if path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.ends_with(PENDING_SIGNATURES_SUFFIX))
                        .unwrap_or(false)
                    {
                        if let Ok(relative_path) = path.strip_prefix(&base) {
                            match build_normalised_absolute_path(base.clone(), relative_path) {
                                Ok(normalised) => pending_files.push(normalised),
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to normalize path {}: {}",
                                        path.display(),
                                        e
                                    );
                                }
                            }
                        } else {
                            tracing::warn!(
                                "File {} is not under base path {}",
                                path.display(),
                                base.display()
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error entry in directory traversal : {}", e);
                }
            }
        }

        Ok(pending_files)
    }

    fn find_pending_for_signer(
        &self,
        base_path: &NormalisedPaths,
        signer: &features_lib::AsfaloadPublicKeys,
    ) -> Result<Vec<NormalisedPaths>, SignedFileError> {
        let mut pending_for_signer = Vec::new();

        let all_pending = self.find_all_pending(base_path)?;

        for pending_path in all_pending {
            match can_signer_add_signature(&pending_path, signer) {
                Ok(true) => pending_for_signer.push(pending_path),
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(
                        "Error checking if signer can add signature to {}: {}",
                        pending_path.relative_path().display(),
                        e
                    );
                }
            }
        }

        Ok(pending_for_signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_validation::build_normalised_absolute_path;
    use crate::pending_discovery::PendingSignaturesDiscovery;
    use common::determine_file_type;
    use common::fs::names::{find_global_signers_for, pending_signatures_path_for};
    use constants::{PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::{
        AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait, sha512_for_file,
    };
    use signers_file_types::{SignersConfig, parse_signers_config};
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use test_helpers::scenarios::setup_asfald_project_registered;

    #[test]
    fn test_find_all_pending_discovers_pending_files() {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let file1 = temp_dir
            .path()
            .join("nested/file1.txt.signatures.json.pending");
        let file2 = temp_dir
            .path()
            .join("nested/file2.txt.signatures.json.pending");
        fs::create_dir_all(file1.parent().unwrap()).unwrap();
        fs::write(&file1, "sig1").unwrap();
        fs::write(&file2, "sig2").unwrap();

        let complete = temp_dir.path().join("complete.txt.signatures.json");
        fs::write(&complete, "complete").unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();

        assert_eq!(result.len(), 2);
        let paths: Vec<String> = result
            .iter()
            .map(|p| p.relative_path().display().to_string())
            .collect();
        assert!(paths.contains(&"nested/file1.txt.signatures.json.pending".to_string()));
        assert!(paths.contains(&"nested/file2.txt.signatures.json.pending".to_string()));
    }

    #[test]
    fn test_find_all_pending_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_find_pending_for_signer_filters_correctly() {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        // The keypair for which we will search pending sigs
        let test_keys = test_helpers::TestKeys::new(1);

        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        fs::write(signers_dir.join(SIGNERS_FILE), signers_json).unwrap();

        // dir1/file1.txt is not yet signed
        let artifact1_dir = temp_dir.path().join("dir1");
        fs::create_dir_all(&artifact1_dir).unwrap();
        let artifact1 = artifact1_dir.join("file1.txt");
        fs::write(&artifact1, "content1").unwrap();
        let pending1 = pending_signatures_path_for(&artifact1).unwrap();
        fs::write(&pending1, "{}").unwrap();

        // dir2/file2.txt is signed
        let artifact2_dir = temp_dir.path().join("dir2");
        fs::create_dir_all(&artifact2_dir).unwrap();
        let artifact2 = artifact2_dir.join("file2.txt");
        fs::write(&artifact2, "content2").unwrap();
        let hash = sha512_for_file(&artifact2).unwrap();
        let sig = test_keys.sec_key(0).unwrap().sign(&hash).unwrap();
        let pending2 = pending_signatures_path_for(&artifact2).unwrap();
        let pending2_content = serde_json::json!({
            test_keys.pub_key(0).unwrap().to_base64(): sig.to_base64()
        });
        fs::write(&pending2, pending2_content.to_string()).unwrap();

        // dir3/file3.txt is considered complete because the pending file is not present.
        let artifact3_dir = temp_dir.path().join("dir3");
        fs::create_dir_all(&artifact3_dir).unwrap();
        let artifact3 = artifact3_dir.join("file3.txt");
        fs::write(&artifact3, "content3").unwrap();
        let complete3 = artifact3.with_extension("signatures.json");
        fs::write(&complete3, "{}").unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery
            .find_pending_for_signer(&normalised, test_keys.pub_key(0).unwrap())
            .unwrap();

        // Only file1 is awaiting a signature
        assert_eq!(result.len(), 1);
        let path = result[0].relative_path().to_string_lossy().to_string();
        assert!(path.contains("file1.txt"));
    }

    #[test]
    fn test_find_pending_for_signer_file_after_registration() -> anyhow::Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        // The keypair for which we will search pending sigs
        let test_keys = test_helpers::TestKeys::new(1);

        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();
        let signers_file = setup_asfald_project_registered(temp_dir.path(), signers_json)?;
        let pending_signatures_file = pending_signatures_path_for(&signers_file)?;
        // First check the signers file was written correctly
        let json_from_file = fs::read_to_string(&signers_file)?;
        let signers_config_from_file = parse_signers_config(json_from_file.as_str())?;
        assert_eq!(signers_config_from_file.artifact_signers().len(), 1);
        assert_eq!(
            signers_file
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            PENDING_SIGNERS_DIR,
            "signers file was placed in wrong directory"
        );
        assert_eq!(
            signers_file.file_name().unwrap(),
            SIGNERS_FILE,
            "signers file was not named correctly"
        );
        assert!(pending_signatures_file.exists());
        let file_type = determine_file_type(signers_file)?;
        assert_eq!(
            file_type,
            common::FileType::InitialSigners,
            "File type of new signers file should be InitialSigners"
        );

        // Now seach for all pending signature, which should be the number of artifact signers in
        // the newly written pending signers file.
        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();
        assert_eq!(result.len(), 1);
        Ok(())
    }
    #[test]
    fn test_find_all_pending_discovers_pending_signers_files() {
        use constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE};
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let pending_signers_dir = project_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_signers_dir).unwrap();

        let signers_file = pending_signers_dir.join(SIGNERS_FILE);
        let signers_json = serde_json::to_string(&signers_config).unwrap();
        fs::write(&signers_file, signers_json).unwrap();

        let pending_signers_sig = pending_signatures_path_for(&signers_file).unwrap();
        fs::write(&pending_signers_sig, "{}").unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();

        assert_eq!(result.len(), 1);
        let path = result[0].relative_path().to_string_lossy().to_string();
        assert!(path.contains("project"));
        assert!(path.contains(PENDING_SIGNERS_DIR));
        assert!(path.contains(SIGNERS_FILE));
        assert!(path.contains(PENDING_SIGNATURES_SUFFIX));
    }

    #[test]
    fn test_find_all_pending_discovers_both_artifacts_and_signers() {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let pending_signers_dir = project_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_signers_dir).unwrap();

        let signers_file = pending_signers_dir.join(SIGNERS_FILE);
        let signers_json = serde_json::to_string(&signers_config).unwrap();
        fs::write(&signers_file, signers_json).unwrap();

        let pending_signers_sig = pending_signatures_path_for(&signers_file).unwrap();
        fs::write(&pending_signers_sig, "{}").unwrap();

        let artifact = project_dir.join("artifact.txt");
        fs::write(&artifact, "content").unwrap();
        let pending_artifact_sig = pending_signatures_path_for(&artifact).unwrap();
        fs::write(&pending_artifact_sig, "{}").unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery.find_all_pending(&normalised).unwrap();

        assert_eq!(result.len(), 2);
        let paths: Vec<String> = result
            .iter()
            .map(|p| p.relative_path().to_string_lossy().to_string())
            .collect();

        let signers_found = paths
            .iter()
            .any(|p| p.contains(PENDING_SIGNERS_DIR) && p.contains(SIGNERS_FILE));
        assert!(signers_found, "Pending signers file should be found");

        let artifact_found = paths
            .iter()
            .any(|p| p.contains("artifact.txt") && p.contains(PENDING_SIGNATURES_SUFFIX));
        assert!(artifact_found, "Pending artifact file should be found");
    }

    #[test]
    fn test_find_pending_for_signer_includes_pending_signers_file() -> anyhow::Result<()> {
        use test_helpers::scenarios::setup_asfald_project_registered;

        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();
        let signers_json = serde_json::to_string(&signers_config).unwrap();
        let signers_file = setup_asfald_project_registered(temp_dir.path(), signers_json)?;
        let pending_signatures_file = pending_signatures_path_for(&signers_file)?;

        // First check the signers file was written correctly
        let json_from_file = fs::read_to_string(&signers_file)?;
        let signers_config_from_file = parse_signers_config(json_from_file.as_str())?;
        assert_eq!(signers_config_from_file.artifact_signers().len(), 1);
        assert_eq!(
            signers_file
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy(),
            PENDING_SIGNERS_DIR,
            "signers file was placed in wrong directory"
        );
        assert_eq!(
            signers_file.file_name().unwrap(),
            SIGNERS_FILE,
            "signers file was not named correctly"
        );
        assert!(pending_signatures_file.exists());
        let file_type = determine_file_type(&signers_file)?;
        assert_eq!(
            file_type,
            common::FileType::InitialSigners,
            "File type of new signers file should be InitialSigners"
        );

        // Check that we don't find a global signers file as expected
        let global_signers = find_global_signers_for(&signers_file);
        match global_signers {
            Ok(v) => panic!(
                "Unexpectedly found a global signers at {} ",
                v.to_string_lossy()
            ),
            Err(e) => {
                if !e
                    .to_string()
                    .contains("No signers file found in parent directories")
                {
                    panic!(
                        "Expected 'No signers file found in parent directories' but got {}",
                        e
                    );
                }
            }
        }

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery
            .find_pending_for_signer(&normalised, test_keys.pub_key(0).unwrap())
            .unwrap();

        assert_eq!(result.len(), 1);
        let path = result[0].relative_path().to_string_lossy().to_string();
        assert!(path.contains(PENDING_SIGNERS_DIR));
        assert!(path.contains(SIGNERS_FILE));
        assert!(path.contains(PENDING_SIGNATURES_SUFFIX));
        Ok(())
    }

    #[test]
    fn test_find_pending_for_signer_filters_signed_out_pending_signers() {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let signers_config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let pending_signers_dir = project_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_signers_dir).unwrap();

        let signers_file = pending_signers_dir.join(SIGNERS_FILE);
        let signers_json = serde_json::to_string(&signers_config).unwrap();
        fs::write(&signers_file, signers_json.clone()).unwrap();

        let pending_signers_sig = pending_signatures_path_for(&signers_file).unwrap();

        let hash = sha512_for_file(&signers_file).unwrap();
        let sig = test_keys.sec_key(0).unwrap().sign(&hash).unwrap();
        let signed_content = serde_json::json!({
            test_keys.pub_key(0).unwrap().to_base64(): sig.to_base64()
        });
        fs::write(&pending_signers_sig, signed_content.to_string()).unwrap();

        let global_signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&global_signers_dir).unwrap();
        fs::write(global_signers_dir.join(SIGNERS_FILE), signers_json).unwrap();

        let discovery = WalkdirPendingDiscovery::new();
        let result = discovery
            .find_pending_for_signer(&normalised, test_keys.pub_key(0).unwrap())
            .unwrap();

        assert!(
            result.is_empty(),
            "Signer should not see pending signers file as needing signature after signing"
        );
    }

    #[test]
    fn test_find_pending_for_signer_multiple_signers_partial_signatures() {
        let temp_dir = TempDir::new().unwrap();
        let normalised =
            build_normalised_absolute_path(temp_dir.path(), PathBuf::from(".")).unwrap();

        let test_keys = test_helpers::TestKeys::new(2);

        let signers_config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )
        .unwrap();

        let project_dir = temp_dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let pending_signers_dir = project_dir.join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&pending_signers_dir).unwrap();

        let signers_file = pending_signers_dir.join(SIGNERS_FILE);
        let signers_json = serde_json::to_string(&signers_config).unwrap();
        fs::write(&signers_file, signers_json.clone()).unwrap();

        let pending_signers_sig = pending_signatures_path_for(&signers_file).unwrap();
        fs::write(&pending_signers_sig, "{}").unwrap();

        let global_signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&global_signers_dir).unwrap();
        fs::write(global_signers_dir.join(SIGNERS_FILE), signers_json).unwrap();

        let discovery = WalkdirPendingDiscovery::new();

        let result1 = discovery
            .find_pending_for_signer(&normalised, test_keys.pub_key(0).unwrap())
            .unwrap();
        let result2 = discovery
            .find_pending_for_signer(&normalised, test_keys.pub_key(1).unwrap())
            .unwrap();

        assert_eq!(
            result1.len(),
            1,
            "Signer1 should see pending signers file as needing signature"
        );
        assert_eq!(
            result2.len(),
            1,
            "Signer2 should see pending signers file as needing signature"
        );

        let path1 = result1[0].relative_path().to_string_lossy().to_string();
        let path2 = result2[0].relative_path().to_string_lossy().to_string();
        assert_eq!(
            path1, path2,
            "Both signers should see the same pending file"
        );
        assert!(path1.contains(PENDING_SIGNERS_DIR));
    }
}
