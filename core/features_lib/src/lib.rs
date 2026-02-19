use std::path::{Path, PathBuf};

pub use common::errors;
use common::fs::names::{find_global_signers_for, pending_signers_file_in_dir};
pub use common::fs::names::{local_signers_path_for, signatures_path_for};
pub use common::{
    ArtifactMarker, FileType, InitialSignersFileMarker, SignedFile, SignersFileMarker,
    errors::SignedFileError,
};
use common::{RevocationMarker, RevokedArtifactMarker};
pub use common::{SignedFileLoader, SignedFileWithKind};

pub use common::{AsfaloadHashes, sha512_for_content, sha512_for_file};

pub use common::index_types::{AsfaloadIndex, FileChecksum, HashAlgorithm};

// Re-export traits for users
pub use signatures::keys::AsfaloadKeyPairTrait;
pub use signatures::keys::AsfaloadPublicKeyTrait;
pub use signatures::keys::AsfaloadSecretKeyTrait;
pub use signatures::keys::AsfaloadSignatureTrait;

// Re-export the types directly
pub use signatures::types::AsfaloadKeyPairs;
pub use signatures::types::AsfaloadPublicKeys;
pub use signatures::types::AsfaloadSecretKeys;
pub use signatures::types::AsfaloadSignatures;

pub use signers_file::activate_signers_file;
use signers_file::sign_signers_file;
pub use signers_file_types::{SignersConfig, parse_signers_config};

// In this type argument we use AsfaloadPublicKeys and AsfaloadSignatures directly.
// This allows the user of this type to not specify any type arguments.
pub type SignatureWithState = aggregate_signature::SignatureWithState;
pub use aggregate_signature::can_revoke;
pub use aggregate_signature::can_signer_add_signature;

// We define and implement this trait in the user_lib as it depends on traits defined in other crates,
// which we want to avoid in common.
pub trait SignedFileTrait
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

//SignedFileTrait implementation for initial signers file and signers file updates
//are identical. The way to avoid duplicated code is to:
//* define an empty helper trait implemented by both marker types that lead to
//  the same implementation.
//* implement the SignefFileTrait once for all markers implementing that helper trait.
pub trait SignableFileMarker {}
impl SignableFileMarker for InitialSignersFileMarker {}
impl SignableFileMarker for SignersFileMarker {}

impl<T> SignedFileTrait for SignedFile<T>
where
    T: SignableFileMarker,
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        sign_signers_file(&self.location, &sig, &pubkey).map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<ArtifactMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::LogicError(
                    "Signature is already complete; cannot add another signature.".to_string(),
                ),
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<RevocationMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::LogicError(
                    "Signature is already complete; cannot add another signature.".to_string(),
                ),
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<RevokedArtifactMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        _sig: AsfaloadSignatures,
        _pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        Err(SignedFileError::Revoked())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        Ok(false)
    }
}

pub trait SignedFileWithKindTrait
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

impl SignedFileWithKindTrait for SignedFileWithKind
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        match self {
            SignedFileWithKind::InitialSignersFile(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::SignersFile(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::Artifact(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::Revocation(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::RevokedArtifact(sf) => sf.add_signature(sig, pubkey),
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        match self {
            SignedFileWithKind::InitialSignersFile(sf) => sf.is_signed(),
            SignedFileWithKind::SignersFile(sf) => sf.is_signed(),
            SignedFileWithKind::Artifact(sf) => sf.is_signed(),
            SignedFileWithKind::Revocation(sf) => sf.is_signed(),
            SignedFileWithKind::RevokedArtifact(sf) => sf.is_signed(),
        }
    }
}

pub trait SignersFileTrait {
    fn find_for_path<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error>;
    fn find_pending_in_dir<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error>;
}

pub struct SignersFile;
impl SignersFileTrait for SignersFile {
    fn find_for_path<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
        find_global_signers_for(path_in.as_ref())
    }
    fn find_pending_in_dir<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
        pending_signers_file_in_dir(path_in)
    }
}

pub mod aggregate_signature_helpers {
    use std::{collections::HashMap, path::Path};

    pub use aggregate_signature::{
        check_groups, get_authorized_signers_for_file, get_missing_signers, load_signers_config,
    };
    use aggregate_signature::{
        get_individual_signatures_from_bytes as get_individual_signatures_from_bytes_ori,
        get_individual_signatures_from_file as get_individual_signatures_ori,
        parse_individual_signatures_from_map as parse_individual_signatures_from_map_ori,
    };
    use common::errors::AggregateSignatureError;
    use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
    use signatures::types::{AsfaloadPublicKeys, AsfaloadSignatures};

    pub fn get_individual_signatures<P: AsRef<Path>>(
        sig_file_path: P,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        get_individual_signatures_ori::<AsfaloadPublicKeys, AsfaloadSignatures, _>(sig_file_path)
    }

    pub fn get_individual_signatures_from_bytes<T: std::borrow::Borrow<[u8]>>(
        signatures_content_in: T,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        get_individual_signatures_from_bytes_ori::<AsfaloadPublicKeys, AsfaloadSignatures, _>(
            signatures_content_in.borrow(),
        )
    }

    pub fn parse_individual_signatures_from_map(
        signatures_map: HashMap<String, String>,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        parse_individual_signatures_from_map_ori::<AsfaloadPublicKeys, AsfaloadSignatures>(
            signatures_map,
        )
    }
}

pub mod constants {
    pub use constants::*;
}
pub mod rest_api {
    pub use rest_api_types::{
        ListPendingResponse, RegisterReleaseResponse, SubmitSignatureRequest,
        SubmitSignatureResponse,
    };
}

#[cfg(test)]
mod tests_signed_file_revocation {
    use super::*;
    use ::constants::{REVOCATION_SUFFIX, SIGNERS_DIR, SIGNERS_FILE};
    use chrono::Utc;
    use common::fs::names::{local_signers_path_for, revocation_path_for};
    use common::{sha512_for_content, sha512_for_file};
    use signatures::keys::AsfaloadSecretKeyTrait;
    use signers_file_types::SignersConfig;
    use std::fs;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    /// Set up a temp directory with:
    /// - An active signers config containing explicit revocation_keys
    /// - A revocation JSON file for a dummy artifact
    /// - A local signers copy for the revocation file (needed after completion)
    ///
    /// Returns the path to the revocation file.
    fn setup_revocation_test(
        temp_dir: &TempDir,
        test_keys: &TestKeys,
        revocation_key_indices: &[usize],
        revocation_threshold: u32,
    ) -> anyhow::Result<std::path::PathBuf> {
        let root = temp_dir.path();

        // Create active signers config with explicit revocation_keys
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);

        let revocation_keys: Vec<_> = revocation_key_indices
            .iter()
            .map(|&i| test_keys.pub_key(i).unwrap().clone())
            .collect();

        let signers_config = SignersConfig::with_keys(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
            None,
            None,
            Some((revocation_keys, revocation_threshold)),
        )?;

        let config_json = serde_json::to_string_pretty(&signers_config)?;
        fs::write(&signers_file, &config_json)?;

        // Create subdirectory for artifact and revocation files
        let sub_dir = root.join("releases");
        fs::create_dir_all(&sub_dir)?;

        // Create revocation JSON file
        let revocation_file = signers_file_types::revocation::RevocationFile {
            timestamp: Utc::now(),
            subject_digest: sha512_for_content(b"artifact content".to_vec())?,
            initiator: test_keys
                .pub_key(revocation_key_indices[0])
                .unwrap()
                .clone(),
        };
        let revocation_json = serde_json::to_string_pretty(&revocation_file)?;
        let revocation_path = sub_dir.join(format!("artifact.bin.{}", REVOCATION_SUFFIX));
        fs::write(&revocation_path, &revocation_json)?;

        // Create local signers copy for the revocation file
        // (mirrors what revoke_signed_file does; needed when signatures complete)
        let local_signers = local_signers_path_for(&revocation_path)?;
        fs::copy(&signers_file, &local_signers)?;

        Ok(revocation_path)
    }

    #[test]
    fn test_add_signature_stays_pending_when_threshold_not_met() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        let signed_file = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );

        // Sign with first key only (threshold=2, so stays pending)
        let file_hash = sha512_for_file(&revocation_path)?;
        let sig = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        let result = signed_file.add_signature(sig, test_keys.pub_key(0).unwrap().clone())?;

        assert!(
            matches!(result, SignatureWithState::Pending(_)),
            "Expected Pending after 1 of 2 required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_add_signature_completes_when_threshold_met() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(3);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1, 2], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Add first signature
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        let intermediate = sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        assert!(
            matches!(intermediate, SignatureWithState::Pending(_)),
            "Expected Pending after only one signatures"
        );

        // Add second signature (should complete)
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig1 = test_keys.sec_key(1).unwrap().sign(&file_hash)?;
        let result = sf.add_signature(sig1, test_keys.pub_key(1).unwrap().clone())?;

        assert!(
            matches!(result, SignatureWithState::Complete(_)),
            "Expected Complete after both required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_add_signature_does_not_reject_non_member() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(3);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Add first signature
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(2).unwrap().sign(&file_hash)?;
        let result = sf.add_signature(sig0, test_keys.pub_key(2).unwrap().clone());

        match result {
            Ok(_) => {}
            Err(e) => panic!(
                "Expected success as the signature from group membership is not validated by SignedFile::add_signature, but got {}",
                e
            ),
        }

        Ok(())
    }
    #[test]
    fn test_add_signature_errors_when_already_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(3);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1, 2], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Complete the signatures with keys 0 and 1
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig1 = test_keys.sec_key(1).unwrap().sign(&file_hash)?;
        sf.add_signature(sig1, test_keys.pub_key(1).unwrap().clone())?;

        // Try to add a third signature — should error
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig2 = test_keys.sec_key(2).unwrap().sign(&file_hash)?;
        let result = sf.add_signature(sig2, test_keys.pub_key(2).unwrap().clone());

        match result {
            Err(e) => {
                let err_str = e.to_string();
                assert!(
                    err_str.contains("already complete"),
                    "Expected 'already complete' error, got: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Expected error when adding signature to already complete revocation"),
        }

        Ok(())
    }

    #[test]
    fn test_is_signed_false_when_pending() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        // No signatures yet
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        assert!(!sf.is_signed()?);

        // Add one signature (still not complete)
        let file_hash = sha512_for_file(&revocation_path)?;
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        assert!(
            !sf.is_signed()?,
            "Expected is_signed=false after 1 of 2 required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_is_signed_true_when_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(2);
        let revocation_path = setup_revocation_test(&temp_dir, &test_keys, &[0, 1], 2)?;

        let file_hash = sha512_for_file(&revocation_path)?;

        // Add both signatures
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig0 = test_keys.sec_key(0).unwrap().sign(&file_hash)?;
        sf.add_signature(sig0, test_keys.pub_key(0).unwrap().clone())?;

        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        let sig1 = test_keys.sec_key(1).unwrap().sign(&file_hash)?;
        sf.add_signature(sig1, test_keys.pub_key(1).unwrap().clone())?;

        // Verify is_signed
        let sf = SignedFile::<common::RevocationMarker>::new(
            revocation_path.to_string_lossy().to_string(),
            None,
        );
        assert!(
            sf.is_signed()?,
            "Expected is_signed=true after both required signatures"
        );

        Ok(())
    }

    #[test]
    fn test_add_signature_rejected_for_revoked_artifact() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(1);

        let artifact_path = temp_dir.path().join("artifact.bin");
        fs::write(&artifact_path, "artifact content")?;

        let revocation_path = revocation_path_for(&artifact_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        let signed_file = SignedFile::<RevokedArtifactMarker>::new(
            artifact_path.to_string_lossy().to_string(),
            None,
        );

        let file_hash = sha512_for_file(&artifact_path)?;
        let sig = test_keys.sec_key(0).unwrap().sign(&file_hash)?;

        let result = signed_file.add_signature(sig, test_keys.pub_key(0).unwrap().clone());

        match result {
            Err(SignedFileError::Revoked()) => {}
            Ok(_) => panic!("Expected SignedFileError::Revoked(), got Ok"),
            Err(e) => panic!("Expected SignedFileError::Revoked(), got: {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_is_signed_returns_false_for_revoked_artifact() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let artifact_path = temp_dir.path().join("artifact.bin");

        let signed_file = SignedFile::<RevokedArtifactMarker>::new(
            artifact_path.to_string_lossy().to_string(),
            None,
        );

        let result = signed_file.is_signed()?;
        assert!(
            !result,
            "Expected is_signed() to return false for revoked artifact"
        );

        Ok(())
    }

    #[test]
    fn test_signed_file_with_kind_rejects_revoked_artifact() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let test_keys = TestKeys::new(1);

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir)?;
        let signers_file = signers_dir.join(SIGNERS_FILE);

        let signers_config = SignersConfig::with_keys(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
            None,
            None,
            None,
        )?;
        fs::write(&signers_file, serde_json::to_string(&signers_config)?)?;

        let artifact_path = temp_dir.path().join("artifact.bin");
        fs::write(&artifact_path, "artifact content")?;

        let revocation_path = revocation_path_for(&artifact_path)?;
        fs::write(&revocation_path, r#"{"revoked": true}"#)?;

        let signed_file = SignedFileLoader::load(&artifact_path)?;

        match &signed_file {
            SignedFileWithKind::RevokedArtifact(_) => {}
            _ => panic!("Expected RevokedArtifact variant"),
        }

        let file_hash = sha512_for_file(&artifact_path)?;
        let sig = test_keys.sec_key(0).unwrap().sign(&file_hash)?;

        use crate::SignedFileWithKindTrait;
        let result = signed_file.add_signature(sig, test_keys.pub_key(0).unwrap().clone());

        match result {
            Err(SignedFileError::Revoked()) => {}
            Ok(_) => panic!("Expected SignedFileError::Revoked(), got Ok"),
            Err(e) => panic!("Expected SignedFileError::Revoked(), got: {}", e),
        }

        Ok(())
    }
}
