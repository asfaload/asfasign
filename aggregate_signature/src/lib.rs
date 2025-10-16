use common::AsfaloadHashes;
use common::fs::names::{
    PENDING_SIGNERS_DIR, SIGNERS_DIR, SIGNERS_FILE, local_signers_path_for,
    pending_signatures_path_for, signatures_path_for,
};
use sha2::{Digest, Sha512};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
use signers_file_types::{SignerGroup, SignersConfig};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AggregateSignatureError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Signature error: {0}")]
    Signature(String),
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("UTF8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Public key error: {0}")]
    PublicKey(String),
    #[error("Threshold not met for group")]
    ThresholdNotMet,
    #[error("Cannot transition incomplete signature to complete")]
    IsIncomplete,
    #[error("Complete signature file according to name is not complete according to signatures")]
    MissingSignaturesInCompleteSignature,
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub struct PendingSignature;
pub struct CompleteSignature;

// This trait allows to have one implementation of the save_to_file fn, saving
// to the correct location according to completeness of the signature (with or
// without the .pending suffix)
pub trait SignatureState {
    fn signature_path_for(origin: &Path) -> Result<PathBuf, AggregateSignatureError>;
}

impl SignatureState for PendingSignature {
    fn signature_path_for(origin: &Path) -> Result<PathBuf, AggregateSignatureError> {
        pending_signatures_path_for(origin).map_err(|e| e.into())
    }
}

impl SignatureState for CompleteSignature {
    fn signature_path_for(origin: &Path) -> Result<PathBuf, AggregateSignatureError> {
        signatures_path_for(origin).map_err(|e| e.into())
    }
}

pub enum SignatureWithState<P, S>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    Pending(AggregateSignature<P, S, PendingSignature>),
    Complete(AggregateSignature<P, S, CompleteSignature>),
}

impl<P, S> SignatureWithState<P, S>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    pub fn get_complete(&self) -> Option<&AggregateSignature<P, S, CompleteSignature>> {
        match self {
            Self::Pending(_s) => None,
            Self::Complete(s) => Some(s),
        }
    }
    pub fn get_pending(&self) -> Option<&AggregateSignature<P, S, PendingSignature>> {
        match self {
            Self::Complete(_s) => None,
            Self::Pending(s) => Some(s),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Artifact,
    Signers,
    InitialSigners,
}
#[derive(Clone)]
pub struct SignedFile {
    pub kind: FileType,
    pub path: PathBuf,
}

impl SignedFile {
    fn determine_file_type<P: AsRef<Path>>(file_path: P) -> FileType {
        let path = file_path.as_ref();
        let global_signers = find_global_signers_for(file_path.as_ref());
        let is_in_signers_dir = path
            .parent()
            .and_then(|dir| dir.file_name())
            .is_some_and(|name| name == SIGNERS_DIR || name == PENDING_SIGNERS_DIR);
        let is_signers_file = path.file_name().is_some_and(|fname| fname == SIGNERS_FILE);

        // Signers file if {SIGNERS_DIR}/{SIGNERSFILE}
        match (is_in_signers_dir, is_signers_file, global_signers) {
            (true, true, Err(_)) => FileType::InitialSigners,
            (true, true, Ok(_)) => FileType::Signers,
            (_, _, _) => FileType::Artifact,
        }
    }
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let file_type = Self::determine_file_type(&path);
        Self {
            kind: file_type,
            path: path.as_ref().to_path_buf(),
        }
    }
}
#[derive(Clone)]
pub struct AggregateSignature<P, S, SS>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    signatures: HashMap<P, S>,
    // The origin is a String. I originally wanted to make it a Url, but
    // then the path must be absolute, and I didn't want to set that restriction right now
    origin: String,
    subject: SignedFile,
    marker: PhantomData<SS>,
}

impl<P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone, S: AsfaloadSignatureTrait, SS>
    AggregateSignature<P, S, SS>
{
    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }
    pub fn subject(&self) -> SignedFile {
        self.subject.clone()
    }
}

impl AsRef<Path> for SignedFile {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}

/// Check if all groups in a category meet their thresholds with valid signatures
/// Note that invalid signatures are ignored, they are not reported as errors.
pub fn check_groups<P, S>(
    groups: &[SignerGroup<P>],
    signatures: &HashMap<P, S>,
    data: &AsfaloadHashes,
) -> bool
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    !groups.is_empty()
        && groups.iter().all(|group| {
            let count = group
                .signers
                .iter()
                .filter(|signer| {
                    signatures
                        .get(&signer.data.pubkey)
                        .is_some_and(|signature| signer.data.pubkey.verify(signature, data).is_ok())
                })
                .count();
            count >= group.threshold as usize
        })
}

// Check that all signers in signers config have signed.
// This does not take the thresholds in account.
pub fn check_all_signers<P, S>(
    signatures: &HashMap<P, S>,
    signers_config: &SignersConfig<P>,
    admin_data: &AsfaloadHashes,
) -> bool
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    let mut keys_iter = signers_config
        .admin_keys()
        .iter()
        .chain(signers_config.master_keys.iter())
        .chain(signers_config.artifact_signers.iter())
        .peekable();

    keys_iter.peek().is_some()
        && keys_iter.all(|group| {
            group.signers.iter().all(|signer| {
                signatures
                    .get(&signer.data.pubkey)
                    .is_some_and(|signature| {
                        signer.data.pubkey.verify(signature, admin_data).is_ok()
                    })
            })
        })
}
// Load individual signatures from the file.
// If the file does not exist, act as if no signature was collected yet.
fn get_individual_signatures<P, S, PP: AsRef<Path>>(
    sig_file_path: PP,
) -> Result<HashMap<P, S>, AggregateSignatureError>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    let mut signatures: HashMap<P, S> = HashMap::new();
    // Attempt to read the signatures file, returning an empty set if not found.
    let signatures_map: HashMap<String, String> = match std::fs::File::open(&sig_file_path) {
        Ok(file) => serde_json::from_reader(file)?,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => return Err(e.into()),
    };

    // Parse each entry
    for (pubkey_b64, sig_b64) in signatures_map {
        let pubkey = P::from_base64(pubkey_b64)
            .map_err(|e| AggregateSignatureError::PublicKey(format!("{}", e)))?;
        let signature = S::from_base64(&sig_b64)
            .map_err(|e| AggregateSignatureError::Signature(e.to_string()))?;
        signatures.insert(pubkey, signature);
    }
    Ok(signatures)
}

/// Find the active signers file by traversing parent directories
fn find_global_signers_for(file_path: &Path) -> Result<PathBuf, AggregateSignatureError> {
    if file_path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Not looking for global signers for a directory.",
        )
        .into());
    }
    let mut current_dir = file_path.parent().ok_or_else(|| {
        AggregateSignatureError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "File has no parent directory",
        ))
    })?;

    loop {
        let candidate = current_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        if candidate.exists() {
            return Ok(candidate);
        }

        // Move up to the parent directory
        current_dir = match current_dir.parent() {
            Some(parent) => parent,
            None => {
                return Err(AggregateSignatureError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No signers file found in parent directories",
                )));
            }
        };
    }
}

fn create_local_signers_for<P: AsRef<Path>>(
    file_path_in: P,
) -> Result<PathBuf, AggregateSignatureError> {
    let file_path = file_path_in.as_ref();

    // Not working on directories
    if file_path.is_dir() {
        return Err(AggregateSignatureError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Not creating local signers for a directory.",
        )));
    }

    let local_signers_path = local_signers_path_for(file_path)?;

    // Not overwriting existing files
    if local_signers_path.exists() {
        return Err({
            AggregateSignatureError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "Not overwriting existing local signers file at {}",
                    local_signers_path.to_string_lossy()
                ),
            ))
        });
    }

    let global_signers = find_global_signers_for(file_path)?;
    std::fs::copy(global_signers, &local_signers_path)?;
    Ok(local_signers_path)
}

/// Load signers configuration from a file
fn load_signers_config<P>(
    signers_file_path: &Path,
) -> Result<SignersConfig<P>, AggregateSignatureError>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
{
    let content = std::fs::read_to_string(signers_file_path)?;
    let config = signers_file_types::parse_signers_config(&content)
        .map_err(AggregateSignatureError::JsonError)?;
    Ok(config)
}

/// Check if an aggregate signature for a file is complete
pub fn is_aggregate_signature_complete<P: AsRef<Path>, PK>(
    file_path: P,
    look_at_pending: bool,
) -> Result<bool, AggregateSignatureError>
where
    PK: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    <PK as signatures::keys::AsfaloadPublicKeyTrait>::Signature:
        signatures::keys::AsfaloadSignatureTrait,
{
    let file_path = file_path.as_ref();

    //  Determine the file type
    let signed_file = SignedFile::new(file_path);

    //  Get the path to the complete signature file
    let sig_file_path = if look_at_pending {
        pending_signatures_path_for(file_path)?
    } else {
        signatures_path_for(file_path)?
    };

    //  Load individual signatures if the complete signature file exists
    let signatures = if sig_file_path.exists() {
        get_individual_signatures(&sig_file_path)?
    } else {
        HashMap::new()
    };

    //  Compute the file's hash, as this is what is signed.
    let file_hash = common::sha512_for_file(file_path)?;

    //  Check completeness based on file type
    let is_complete = match signed_file.kind {
        FileType::Artifact => {
            // For artifact, look at the local signers file created when
            // the new artifact signature was initialised.
            let signers_file_path = local_signers_path_for(file_path)?;
            let signers_config = load_signers_config::<PK>(&signers_file_path)?;
            check_groups(&signers_config.artifact_signers, &signatures, &file_hash)
        }
        FileType::Signers => {
            // For signers updates, we need to
            // - Respect the current signers file
            // - Respect the new signers file
            // - Collect signatures from all new signers
            // FIXME: implement the criteria above
            let signers_file_path = local_signers_path_for(file_path)?;
            let signers_config = load_signers_config::<PK>(&signers_file_path)?;
            check_groups(signers_config.admin_keys(), &signatures, &file_hash)
                || check_groups(&signers_config.master_keys, &signatures, &file_hash)
        }

        FileType::InitialSigners => {
            // For initial signers, the config is the signers file itself,
            // and we require all signers in the file to sign it
            let signers_config = load_signers_config::<PK>(file_path)?;
            check_all_signers(&signatures, &signers_config, &file_hash)
        }
    };
    if !look_at_pending && !is_complete {
        Err(AggregateSignatureError::MissingSignaturesInCompleteSignature)
    } else {
        Ok(is_complete)
    }
}
/// Load signatures for a file from the corresponding signatures file
// This function cannot be placed in the implemetation of AggregateSignature<P,S,SS> because
// in that case, it would have to be called like this: AggregateSignature<_,_,_>::load_for_file(...)
// which requires to determine the phantom type on AggregateSignature before load can be called.
// This is annoying but also makes no sense as a call like this one
//   AggregateSignature<_,_,CompleteSignature>::load_for_file(...)
// could still return a pending signature.
pub fn load_for_file<P, S, PP: AsRef<Path>>(
    path_in: PP,
) -> Result<SignatureWithState<P, S>, AggregateSignatureError>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    let signed_file = SignedFile::new(&path_in);
    let file_path = path_in.as_ref();

    // Check if the aggregate signature is complete
    let complete_sig_path = signatures_path_for(file_path)?;

    if complete_sig_path.exists() {
        // Load the complete signature file
        // We double check the signature is complete. If it is not, it
        // will return an error. If it is complete, we don't care about
        // its true return value
        is_aggregate_signature_complete::<_, P>(file_path, false)?;
        let signatures = get_individual_signatures(&complete_sig_path)?;
        Ok(SignatureWithState::Complete(AggregateSignature {
            signatures,
            origin: file_path.to_string_lossy().to_string(),
            subject: signed_file,
            marker: PhantomData,
        }))
    } else {
        // Load the pending signature file
        let pending_sig_file_path = pending_signatures_path_for(file_path)?;
        let signatures = get_individual_signatures(pending_sig_file_path)?;

        Ok(SignatureWithState::Pending(AggregateSignature {
            signatures,
            origin: file_path.to_string_lossy().to_string(),
            subject: signed_file,
            marker: PhantomData,
        }))
    }
}
impl<P, S, SS> AggregateSignature<P, S, SS>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
    SS: SignatureState,
{
    /// Check if aggregate signature meets all thresholds in signers config for artifacts
    pub fn is_artifact_complete(
        &self,
        signers_config: &SignersConfig<P>,
        artifact_data: &AsfaloadHashes,
    ) -> bool {
        // Check artifact_signers groups
        check_groups(
            &signers_config.artifact_signers,
            &self.signatures,
            artifact_data,
        )
    }

    /// Check if aggregate signature meets all thresholds in signers config for master keys
    pub fn is_master_complete(
        &self,
        signers_config: &SignersConfig<P>,
        master_data: &AsfaloadHashes,
    ) -> bool {
        // Check master_keys groups
        check_groups(&signers_config.master_keys, &self.signatures, master_data)
    }

    /// Check if aggregate signature meets all thresholds in signers config for admin keys
    pub fn is_admin_complete(
        &self,
        signers_config: &SignersConfig<P>,
        admin_data: &AsfaloadHashes,
    ) -> bool {
        // Check admin_keys groups if present
        let keys = signers_config.admin_keys();
        check_groups(keys, &self.signatures, admin_data)
    }

    pub fn save_to_file(&self) -> Result<(), AggregateSignatureError> {
        let file_path = PathBuf::from(&self.origin);
        let sig_file_path = SS::signature_path_for(&file_path)?;

        // Convert signatures to a HashMap of base64-encoded public keys and signatures
        let signatures_map: HashMap<String, String> = self
            .signatures
            .iter()
            .map(|(pubkey, sig)| (pubkey.to_base64(), sig.to_base64()))
            .collect();

        // Serialize the HashMap to JSON
        let json_content = serde_json::to_string_pretty(&signatures_map)?;

        // Write the JSON content to the signature file
        std::fs::write(&sig_file_path, json_content)?;

        Ok(())
    }
}

impl<P, S> AggregateSignature<P, S, PendingSignature>
where
    P: AsfaloadPublicKeyTrait<Signature = S> + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait + Clone,
{
    pub fn try_transition_to_complete(
        &self,
    ) -> Result<AggregateSignature<P, S, CompleteSignature>, AggregateSignatureError> {
        let pending_sig_path = pending_signatures_path_for(&self.subject)?;
        if !pending_sig_path.exists() {
            return Err({
                AggregateSignatureError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "Pending signatures not found for moving to complete ({})",
                        pending_sig_path.to_string_lossy()
                    ),
                ))
            });
        }
        let complete_sig_path = signatures_path_for(&self.subject)?;
        if complete_sig_path.exists() {
            return Err({
                AggregateSignatureError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "Not overwriting existing complete aggregate signature {}",
                        complete_sig_path.to_string_lossy()
                    ),
                ))
            });
        }
        if is_aggregate_signature_complete::<_, P>(&self.subject, true)? {
            std::fs::rename(pending_sig_path, complete_sig_path)?;
            Ok(AggregateSignature::<P, S, CompleteSignature> {
                origin: self.origin.clone(),
                subject: self.subject.clone(),
                signatures: self.signatures.clone(),
                marker: PhantomData,
            })
        } else {
            Err(AggregateSignatureError::IsIncomplete)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use common::fs::names::{PENDING_SIGNATURES_SUFFIX, SIGNATURES_SUFFIX, SIGNERS_SUFFIX};
    use minisign::SignatureBox;
    use signatures::keys::{AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait};
    use signatures::keys::{AsfaloadPublicKey, AsfaloadSignature};
    use signers_file_types::{
        InitialVersion, KeyFormat, Signer, SignerData, SignerGroup, SignerKind, SignersConfig,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use tempfile::TempDir;
    use test_helpers::TestKeys;

    #[test]
    fn test_load_and_complete() -> Result<()> {
        // Generate keypairs
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();
        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let _seckey2 = keypair2.secret_key("password").unwrap();

        // Create signature
        let data = common::sha512_for_content(b"test data".to_vec())?;
        let signature = seckey.sign(&data).unwrap();

        // Create signatures map manually
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature);

        // Create a dummy file path to represent the signed file
        let signed_file_path = PathBuf::from("test_file.txt");

        // Create pending aggregate signature manually
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures,
            origin: signed_file_path.to_string_lossy().to_string(),
            marker: PhantomData,
            subject: SignedFile::new(signed_file_path),
        };

        // Create signers config JSON string
        let json_config_template = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://example.com",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } },
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ],
          "threshold": THRESHOLD_PLACEHOLDER
        }
      ],
      "master_keys": [],
      "admin_keys": null
    }
    "#;

        // Replace placeholders with actual public keys
        let json_config = json_config_template.replace("PUBKEY1_PLACEHOLDER", &pubkey.to_base64());
        let json_config = json_config.replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());
        let json_config = json_config.replace("THRESHOLD_PLACEHOLDER", "1");

        // Parse signers config from JSON
        let signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            signers_file_types::parse_signers_config(&json_config).unwrap();

        // Should be complete with threshold 1
        assert!(agg_sig.is_artifact_complete(&signers_config, &data));

        // Should be incomplete with threshold 2
        let high_threshold_config =
            json_config_template.replace("PUBKEY1_PLACEHOLDER", &pubkey.to_base64());
        let high_threshold_config =
            high_threshold_config.replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());
        let high_threshold_config = high_threshold_config.replace("THRESHOLD_PLACEHOLDER", "2");
        let signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            signers_file_types::parse_signers_config(&high_threshold_config).unwrap();
        assert!(!agg_sig.is_artifact_complete(&signers_config, &data));
        assert_eq!(agg_sig.origin, "test_file.txt");
        Ok(())
    }

    // This test illustrates how a signers config can be defined programmatically. This
    // will not be the usual case, but could be handy.
    #[test]
    fn test_load_and_complete_programmatically() -> Result<()> {
        // Create temp directory
        let temp_dir = TempDir::new().unwrap();
        // Crete a work_dir so we can place the  asfaload_signers dir
        // in its parent directory temp_dir
        let dir_path = temp_dir.path().join("work_dir");
        fs::create_dir_all(&dir_path).unwrap();

        // Generate keypairs
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();

        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let _seckey2 = keypair2.secret_key("password").unwrap();

        // Create signers configuration with threshold 2

        // Create signers config with threshold 1
        let signer = signers_file_types::Signer {
            kind: SignerKind::Key,
            data: signers_file_types::SignerData {
                format: KeyFormat::Minisign,
                pubkey: pubkey.clone(),
            },
        };
        let signer2 = signers_file_types::Signer {
            kind: SignerKind::Key,
            data: signers_file_types::SignerData {
                format: KeyFormat::Minisign,
                pubkey: pubkey2.clone(),
            },
        };
        let group = SignerGroup {
            signers: vec![signer, signer2],
            threshold: 1,
        };
        let signers_config = SignersConfig {
            version: 1,
            initial_version: signers_file_types::InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers: vec![group.clone()],
            master_keys: vec![],
            admin_keys: None,
        };
        // Write signers configuration
        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create signature
        let data = b"test data";
        let hash_for_content = common::sha512_for_content(data.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a dummy file to represent the signed file
        let signed_file_path = dir_path.join("data.txt");
        std::fs::write(&signed_file_path, data).unwrap();

        // Create local signers file
        create_local_signers_for(&signed_file_path)?;
        // Write the signatures file for the signed file
        let mut signatures_map = std::collections::HashMap::new();
        signatures_map.insert(pubkey.to_base64(), signature.to_base64());
        let json_content = serde_json::to_string_pretty(&signatures_map).unwrap();

        let sig_file_path = signed_file_path.with_file_name(format!(
            "{}.{}",
            signed_file_path.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));

        std::fs::write(&sig_file_path, json_content).unwrap();

        // Load aggregate signature for the signed file
        let agg_sig: SignatureWithState<_, _> = load_for_file(&signed_file_path)?;

        let agg_sig = agg_sig
            .get_complete()
            .ok_or(anyhow::anyhow!("Signature should have been complete"))?;

        // Should be complete with threshold 1
        assert!(agg_sig.is_artifact_complete(&signers_config, &hash_for_content));

        // Should still be complete when threshold set to 2
        // in global signers file as local file still has threshold 1
        let mut high_threshold_group = group.clone();
        high_threshold_group.threshold = 2;
        let high_threshold_config = SignersConfig {
            artifact_signers: vec![high_threshold_group],
            ..signers_config.clone()
        };

        let config_json = serde_json::to_string_pretty(&high_threshold_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        let agg_sig: SignatureWithState<_, _> = load_for_file(&signed_file_path)?;
        let agg_sig = agg_sig
            .get_complete()
            .ok_or(anyhow::anyhow!("Signature should have been complete"))?;
        assert!(agg_sig.is_artifact_complete(&signers_config, &hash_for_content));

        assert_eq!(
            agg_sig.origin,
            signed_file_path.to_string_lossy().to_string()
        );
        Ok(())
    }

    #[test]
    fn test_multiple_groups() -> Result<()> {
        // Generate two keypairs
        let keypair1 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey1 = keypair1.public_key();
        let seckey1 = keypair1.secret_key("password").unwrap();
        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let seckey2 = keypair2.secret_key("password").unwrap();

        // Create signatures
        let data = common::sha512_for_content(b"test data".to_vec())?;
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();

        // Create signatures map manually
        let mut signatures = HashMap::new();
        signatures.insert(pubkey1.clone(), sig1);
        signatures.insert(pubkey2.clone(), sig2);

        // Create aggregate signature manually
        let agg_sig: AggregateSignature<_, _, CompleteSignature> = AggregateSignature {
            signatures,
            origin: "test_origin".to_string(),
            marker: PhantomData,
            subject: SignedFile {
                kind: FileType::Artifact,
                path: PathBuf::from_str("/data/file").unwrap(),
            },
        };

        // Create signers config JSON string with two groups
        let json_config = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://example.com",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ],
          "threshold": 1
        },
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [],
      "admin_keys": null
    }
    "#;

        // Replace placeholders with actual public keys
        let json_config = json_config.replace("PUBKEY1_PLACEHOLDER", &pubkey1.to_base64());
        let json_config = json_config.replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());

        // Parse signers config from JSON
        let signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            signers_file_types::parse_signers_config(&json_config).unwrap();

        // Should be complete with both groups
        assert!(agg_sig.is_artifact_complete(&signers_config, &data));

        // Test mixed configuration (one group in artifact_signers, one in master_keys)
        let json_config_mixed = r#"
    {
      "version": 1,
      "initial_version": {
        "permalink": "https://example.com",
        "mirrors": []
      },
      "artifact_signers": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ],
          "threshold": 1
        }
      ],
      "master_keys": [
        {
          "signers": [
            { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ],
          "threshold": 1
        }
      ],
      "admin_keys": null
    }
    "#;

        // Replace placeholders with actual public keys
        let json_config_mixed =
            json_config_mixed.replace("PUBKEY1_PLACEHOLDER", &pubkey1.to_base64());
        let json_config_mixed =
            json_config_mixed.replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());

        // Parse mixed signers config from JSON
        let signers_config_mixed: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            signers_file_types::parse_signers_config(&json_config_mixed).unwrap();

        // Should be complete with mixed configuration
        assert!(agg_sig.is_artifact_complete(&signers_config_mixed, &data));
        assert!(agg_sig.is_master_complete(&signers_config_mixed, &data));
        // The admin group is implicitly made equal to the artifacti signers group here
        assert!(agg_sig.is_admin_complete(&signers_config_mixed, &data));

        assert_eq!(agg_sig.origin, "test_origin");
        Ok(())
    }

    #[test]
    fn test_check_groups_from_json_minimal() -> Result<()> {
        // Generate keypairs
        let test_keys = TestKeys::new(5);
        // Keys 0 are not used because in a previous version of the code
        // before switching to the use of TestKeys, the keys were generated
        // manually with index starting at 1 and refactoring it is a lot of work
        // for no benefit...
        let _pubkey0 = test_keys.pub_key(0).unwrap();
        let _seckey0 = test_keys.sec_key(0).unwrap();
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();
        let pubkey3 = test_keys.pub_key(3).unwrap();
        let seckey3 = test_keys.sec_key(3).unwrap();
        let pubkey4 = test_keys.pub_key(4).unwrap();
        let seckey4 = test_keys.sec_key(4).unwrap();

        let data = common::sha512_for_content(b"test data".to_vec())?;

        let build_groups = |tpl: String| {
            let json = test_keys.substitute_keys(tpl);

            let groups: Vec<SignerGroup<AsfaloadPublicKey<minisign::PublicKey>>> =
                serde_json::from_str(&json).unwrap();
            groups
        };

        let check_validity = |tpl: String,
                              signatures: &HashMap<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<SignatureBox>,
        >,
                              expected_valid: bool| {
            let groups = build_groups(tpl);
            if expected_valid {
                assert!(check_groups(&groups, signatures, &data))
            } else {
                assert!(!check_groups(&groups, signatures, &data))
            }
        };
        // Create signatures
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();
        let sig3 = seckey3.sign(&data).unwrap();
        let sig4 = seckey4.sign(&data).unwrap();

        // Create also signature for other data
        let other_data = common::sha512_for_content(b"my other data".to_vec())?;
        let other_sig1 = seckey1.sign(&other_data).unwrap();
        let other_sig2 = seckey2.sign(&other_data).unwrap();
        let other_sig3 = seckey3.sign(&other_data).unwrap();
        let other_sig4 = seckey4.sign(&other_data).unwrap();

        // Create signatures maps
        // The name of the variable indicates which signatures is contains
        let mut signatures_1 = HashMap::new();
        signatures_1.insert(pubkey1.clone(), sig1.clone());
        let mut signatures_1_2 = HashMap::new();
        signatures_1_2.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2.insert(pubkey2.clone(), sig2.clone());
        let mut signatures_1_2_4 = HashMap::new();
        signatures_1_2_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2_4.insert(pubkey2.clone(), sig2.clone());
        signatures_1_2_4.insert(pubkey4.clone(), sig4.clone());
        let mut signatures_1_3 = HashMap::new();
        signatures_1_3.insert(pubkey1.clone(), sig1.clone());
        signatures_1_3.insert(pubkey3.clone(), sig3.clone());
        let mut signatures_2_4 = HashMap::new();
        signatures_2_4.insert(pubkey2.clone(), sig2.clone());
        signatures_2_4.insert(pubkey4.clone(), sig4.clone());
        let mut signatures_1_3_4 = HashMap::new();
        signatures_1_3_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_3_4.insert(pubkey3.clone(), sig3.clone());
        signatures_1_3_4.insert(pubkey4.clone(), sig4.clone());
        let mut signatures_1_2_3_4 = HashMap::new();
        signatures_1_2_3_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2_3_4.insert(pubkey2.clone(), sig2.clone());
        signatures_1_2_3_4.insert(pubkey3.clone(), sig3.clone());
        signatures_1_2_3_4.insert(pubkey4.clone(), sig4.clone());

        // Signature by key 3 signed other data, which should make
        // it invalid, hence the i indicator.
        let mut signatures_1_2_i3_4 = HashMap::new();
        signatures_1_2_i3_4.insert(pubkey1.clone(), sig1.clone());
        signatures_1_2_i3_4.insert(pubkey2.clone(), sig2.clone());
        signatures_1_2_i3_4.insert(pubkey3.clone(), other_sig3.clone());
        signatures_1_2_i3_4.insert(pubkey4.clone(), sig4.clone());

        // Aliases for explicit meaning of argument passed
        let complete = true;
        let incomplete = false;

        // Define group check tests in this vector of tuples of the form
        // (json_string, signatures_present, expected_completeness)
        let test_groups = [
            //------------------------------------------------------------
            // 1-of-1 complete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // 1-of-1 complete, with additional irrelevant signature
            // The signature by someone not in the signers groups is not an error
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1_2.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // 2-of-2 complete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // 2-of-2 incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // 2-of-2 incomplete but with an additional irrelevant signature.
            // The signature from a signer not in the group does not help reach the threshold.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_3.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // 2-of-2 complete but with additional irrelevant signatures.
            // This is not an error.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } },
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_3_4.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // Multiple 1-of-1 groups.
            // This is equivalent to one 2-of-2 group with the same signers.
            // All groups must have their threshold reached for the signature to be complete.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1_2.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // Multiple 1-of-1 groups.
            // When the threshold of one group is not reached, the signature is not complete.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 1
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
        ],
        "threshold": 1
      }
    ]
    "#,
                signatures_1_2.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, complete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_3_4.clone(),
                complete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, but sig3 covers other data
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_i3_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 4-of-4 groups, but sig3 covers other data
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 4
      }
    ]
    "#,
                signatures_1_2_i3_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, first group incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_3_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, second group incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2_4.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Two 2-of-2 groups, all groups incomplete
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY2_PLACEHOLDER" } }
        ],
        "threshold": 2
      },
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY3_PLACEHOLDER" } }
          ,{ "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY4_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_3.clone(),
                incomplete,
            ),
            //------------------------------------------------------------
            // Empty group never complete
            (
                r#"
    [

    ]
    "#,
                signatures_1_3.clone(),
                incomplete,
            ),
        ];

        // ------------------------------------------------------------
        // Run all defined tests
        // ------------------------------------------------------------
        test_groups
            .iter()
            .for_each(|g| check_validity(g.0.to_string(), &g.1, g.2));

        // Empty groups are always incomplete
        assert!(!check_groups(
            &[],
            &HashMap::<AsfaloadPublicKey<_>, AsfaloadSignature<_>>::new(),
            &data
        ));
        assert!(!check_groups(&[], &signatures_1_2_3_4, &data));
        Ok(())
    }

    #[test]
    fn test_determine_file_type() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        //  Regular file (should be Artifact)
        let regular_file = temp_path.join("regular_file.txt");
        fs::write(&regular_file, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&regular_file),
            FileType::Artifact
        );

        //  File in a regular directory (should be Artifact)
        let regular_dir = temp_path.join("regular_dir");
        fs::create_dir(&regular_dir).unwrap();
        let file_in_regular_dir = regular_dir.join("some_file.json");
        fs::write(&file_in_regular_dir, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&file_in_regular_dir),
            FileType::Artifact
        );

        //  File in "asfaload.signers.pending" but not named "index.json" (should be Artifact)
        let pending_signers_dir = temp_path.join(PENDING_SIGNERS_DIR);
        fs::create_dir(&pending_signers_dir).unwrap();
        let other_file = pending_signers_dir.join("other_file.json");
        fs::write(&other_file, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&other_file),
            FileType::Artifact
        );

        //  File named "index.json" but not in "asfaload.signers.pending" (should be Artifact)
        let index_in_regular_dir = regular_dir.join(SIGNERS_FILE);
        fs::write(&index_in_regular_dir, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&index_in_regular_dir),
            FileType::Artifact
        );

        //  File named "index.json" in "asfaload.signers.pending" (should be Signers)
        let index_file = pending_signers_dir.join(SIGNERS_FILE);
        fs::write(&index_file, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&index_file),
            FileType::InitialSigners
        );

        //  Nested "asfaload.signers.pending" directory (should still work)
        let nested_dir = temp_path.join("nested").join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&nested_dir).unwrap();
        let nested_index = nested_dir.join(SIGNERS_FILE);
        fs::write(&nested_index, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&nested_index),
            FileType::InitialSigners
        );

        //  Directory named similarly but not exactly "asfaload.signers.pending" (should be Artifact)
        let similar_dir = temp_path.join(format!("{}.{}", PENDING_SIGNERS_DIR, "backup"));
        fs::create_dir(&similar_dir).unwrap();
        let similar_index = similar_dir.join(SIGNERS_FILE);
        fs::write(&similar_index, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&similar_index),
            FileType::Artifact
        );

        //  Case sensitivity check (should be Artifact since exact match is required)
        let case_dir = temp_path.join(PENDING_SIGNERS_DIR.to_uppercase());
        fs::create_dir(&case_dir).unwrap();
        let case_index = case_dir.join(SIGNERS_FILE);
        fs::write(&case_index, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&case_index),
            FileType::Artifact
        );

        //  File named "INDEX.JSON" (uppercase) in "asfaload.signers.pending" (should be Artifact)
        let upper_index = pending_signers_dir.join("INDEX.JSON");
        fs::write(&upper_index, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&upper_index),
            FileType::Artifact
        );

        // Create a current signers file, and validate that tests that
        // previously returned initial signers now return signers.
        let current_signers_dir = temp_path.join(SIGNERS_DIR);
        fs::create_dir(&current_signers_dir).unwrap();
        let file_in_regular_dir = current_signers_dir.join("index.json");
        fs::write(
            &file_in_regular_dir,
            "dummy signers content ok as only presence is checked",
        )
        .unwrap();

        //  File named "index.json" in "asfaload.signers.pending" (should be Signers)
        let index_file = pending_signers_dir.join(SIGNERS_FILE);
        fs::write(&index_file, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&index_file),
            FileType::Signers
        );

        //  Nested "asfaload.signers.pending" directory (should still work)
        let nested_dir = temp_path.join("nested").join(PENDING_SIGNERS_DIR);
        fs::create_dir_all(&nested_dir).unwrap();
        let nested_index = nested_dir.join(SIGNERS_FILE);
        fs::write(&nested_index, "content").unwrap();
        assert_eq!(
            SignedFile::determine_file_type(&nested_index),
            FileType::Signers
        );
    }

    #[test]
    fn test_find_signers_file() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   project/
        //     asfaload.signers/
        //       index.json
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let signers_dir = project_dir.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        let signers_file = signers_dir.join(SIGNERS_FILE);
        fs::write(&signers_file, "{}").unwrap();

        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();

        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "content").unwrap();

        // Test finding signers file from the file
        let found = find_global_signers_for(&test_file).unwrap();
        assert_eq!(found, signers_file);

        // We only look for signers for a file, not a directory
        let result = find_global_signers_for(&project_dir);
        assert!(result.is_err());
        assert!(matches!(result, Err(AggregateSignatureError::Io(_))));

        // Test when no signers file exists
        let no_signers_dir = root.join("no_signers");
        fs::create_dir_all(&no_signers_dir).unwrap();
        let result = find_global_signers_for(&no_signers_dir);
        assert!(matches!(result, Err(AggregateSignatureError::Io(_))));
    }

    #[test]
    fn test_is_aggregate_signature_complete() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   file.txt
        //   file.txt.signatures.json
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create a test file
        let test_file = root.join("file.txt");
        let file_content = b"test content";
        fs::write(&test_file, file_content).unwrap();
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;

        // Generate keys for testing
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap();
        let seckey2 = test_keys.sec_key(1).unwrap();

        // Create signers configuration with threshold 2
        let signers_config = SignersConfig {
            version: 1,
            initial_version: InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers: vec![SignerGroup {
                signers: vec![
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: pubkey1.clone(),
                        },
                    },
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: pubkey2.clone(),
                        },
                    },
                ],
                threshold: 2,
            }],
            master_keys: vec![],
            admin_keys: None,
        };

        // Write signers configuration
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create signatures
        let sig1 = seckey1.sign(&hash_for_content).unwrap();
        let sig2 = seckey2.sign(&hash_for_content).unwrap();

        // Copy global signers file to local
        let result = create_local_signers_for(&test_file);
        assert!(result.is_ok());

        // Test incomplete signature (only one signature)
        let sig_file_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));

        let mut incomplete_sigs = HashMap::new();
        incomplete_sigs.insert(pubkey1.clone().to_base64(), sig1.to_base64());
        let incomplete_json = serde_json::to_string_pretty(&incomplete_sigs).unwrap();
        fs::write(&sig_file_path, incomplete_json).unwrap();

        let result = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, false);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // Test complete signature (both signatures)
        let mut complete_sigs = HashMap::new();
        complete_sigs.insert(pubkey1.to_base64(), sig1.to_base64());
        complete_sigs.insert(pubkey2.to_base64(), sig2.to_base64());
        let complete_json = serde_json::to_string_pretty(&complete_sigs).unwrap();
        fs::write(&sig_file_path, complete_json).unwrap();

        assert!(
            is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, false).unwrap()
        );

        // Test when signature file doesn't exist
        fs::remove_file(&sig_file_path).unwrap();
        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, false);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );

        // Test invalid signature (wrong content)
        let mut invalid_sigs = HashMap::new();
        invalid_sigs.insert(
            pubkey1.to_base64(),
            seckey1
                .sign(&common::sha512_for_content(b"wrong content".to_vec())?)
                .unwrap()
                .to_base64(),
        );
        invalid_sigs.insert(pubkey2.to_base64(), sig2.to_base64());
        let invalid_json = serde_json::to_string_pretty(&invalid_sigs).unwrap();
        fs::write(&sig_file_path, invalid_json).unwrap();

        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, false);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap().to_string(),
            AggregateSignatureError::MissingSignaturesInCompleteSignature.to_string()
        );
        Ok(())
    }

    #[test]
    fn test_create_local_signers_for_success() {
        // Create a temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   project/
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create global signers file
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let global_content = r#"{
            "version": 1,
            "initial_version": {
                "permalink": "https://example.com",
                "mirrors": []
            },
            "artifact_signers": [],
            "master_keys": [],
            "admin_keys": null
        }"#;
        fs::write(&global_signers_file, global_content).unwrap();

        // Create a test file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Call the function to create local signers
        let local_signers_path = create_local_signers_for(&test_file).unwrap();

        // Verify the local signers file was created in the correct location
        let expected_local_path = test_file.with_file_name(format!("file.txt.{}", SIGNERS_SUFFIX));
        assert_eq!(local_signers_path, expected_local_path);
        assert!(local_signers_path.exists());

        // Verify the content matches the global signers file
        let local_content = fs::read_to_string(&local_signers_path).unwrap();
        assert_eq!(local_content, global_content);
    }

    #[test]
    fn test_create_local_signers_for_directory_input() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Try to create local signers for a directory - should fail
        let result = create_local_signers_for(dir_path);
        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
                assert!(
                    e.to_string()
                        .contains("Not creating local signers for a directory")
                );
            }
            _ => panic!("Expected IO error 'Not creating local signers for a directory'"),
        }
    }

    #[test]
    fn test_create_local_signers_for_existing_local_signers() {
        // Create a temporary directory structure
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();
        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   project/
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create global signers file
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let global_content = r#"{
            "version": 1,
            "initial_version": {
                "permalink": "https://example.com",
                "mirrors": []
            },
            "artifact_signers": [],
            "master_keys": [],
            "admin_keys": null
        }"#;
        fs::write(&global_signers_file, global_content).unwrap();

        // Create a test file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        let existing_local_signers = src_dir.join(format!("file.txt.{}", SIGNERS_SUFFIX));
        fs::write(
            &existing_local_signers,
            "content does not matter, only existence",
        )
        .unwrap();

        // Try to create local signers - should fail because local file already exists
        let result = create_local_signers_for(&test_file);
        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
                assert!(
                    e.to_string()
                        .contains("Not overwriting existing local signers file")
                );
            }
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_create_local_signers_for_no_global_signers() {
        // Create a temporary directory structure without global signers
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   project/
        //     src/
        //       file.txt
        let project_dir = root.join("project");
        fs::create_dir_all(&project_dir).unwrap();

        // Create a test file
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Try to create local signers - should fail because no global signers found
        let result = create_local_signers_for(&test_file);
        assert!(result.is_err());
        match result.unwrap_err() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                assert!(
                    e.to_string()
                        .contains("No signers file found in parent directories")
                );
            }
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_create_local_signers_for_nested_project() {
        // Create a temporary directory structure with nested projects
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   project/
        //     submodule/
        //       src/
        //         file.txt
        let project_dir = root.join("project").join("submodule");
        fs::create_dir_all(&project_dir).unwrap();

        // Create global signers file at root
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let global_signers_file = signers_dir.join(SIGNERS_FILE);
        let global_content = r#"{"version": 1, "initial_version": {"permalink": "https://example.com", "mirrors": []}}"#;
        fs::write(&global_signers_file, global_content).unwrap();

        // Create a test file in the nested project
        let src_dir = project_dir.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let test_file = src_dir.join("file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Call the function to create local signers
        let local_signers_path = create_local_signers_for(&test_file).unwrap();

        // Verify the local signers file was created in the nested project directory
        let expected_local_path = src_dir.join(format!("file.txt.{}", SIGNERS_SUFFIX));
        assert_eq!(local_signers_path, expected_local_path);
        assert!(local_signers_path.exists());

        // Verify the content matches the global signers file
        let local_content = fs::read_to_string(&local_signers_path).unwrap();
        assert_eq!(local_content, global_content);
    }

    #[test]
    fn test_transition_to_complete_success() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file with content
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        fs::write(&test_file, file_content).unwrap();

        // Generate a keypair for signing
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();

        // Create a signature for the file content
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a signers configuration with threshold 1
        let signers_config = SignersConfig {
            version: 1,
            initial_version: InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers: vec![SignerGroup {
                signers: vec![Signer {
                    kind: SignerKind::Key,
                    data: SignerData {
                        format: KeyFormat::Minisign,
                        pubkey: pubkey.clone(),
                    },
                }],
                threshold: 1,
            }],
            master_keys: vec![],
            admin_keys: None,
        };

        // Create global signers directory and file
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create local signers file
        create_local_signers_for(&test_file).unwrap();

        // Create a pending signatures file with the signature
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        let mut signatures_map = HashMap::new();
        signatures_map.insert(pubkey.to_base64(), signature.to_base64());
        let signatures_json = serde_json::to_string_pretty(&signatures_map).unwrap();
        fs::write(&pending_sig_path, signatures_json).unwrap();

        // Create an AggregateSignature in Pending state
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures,
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Transition to complete
        let complete_sig = agg_sig.try_transition_to_complete().unwrap();

        // Verify the pending file is gone
        assert!(!pending_sig_path.exists());

        // Verify the complete file exists
        let complete_sig_path = signatures_path_for(&test_file).unwrap();
        assert!(complete_sig_path.exists());

        // Verify the content is preserved
        let content = fs::read_to_string(&complete_sig_path).unwrap();
        let parsed_content: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.len(), 1);
        assert!(parsed_content.contains_key(&pubkey.to_base64()));
        assert_eq!(parsed_content[&pubkey.to_base64()], signature.to_base64());

        // Verify the returned signature is in Complete state
        assert_eq!(complete_sig.signatures.len(), 1);
        assert_eq!(complete_sig.origin, test_file.to_string_lossy().to_string());
        assert_eq!(complete_sig.subject.kind, FileType::Artifact);
        assert_eq!(complete_sig.subject.path, test_file);
        Ok(())
    }

    #[test]
    fn test_transition_to_complete_no_pending_file() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file but no pending signature file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Create an AggregateSignature in Pending state
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures: HashMap::new(),
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Attempt to transition to complete
        let result = agg_sig.try_transition_to_complete();

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                assert!(e.to_string().contains("Pending signatures not found"));
            }
            _ => panic!("Expected IO error of kind NotFound"),
        }
    }

    #[test]
    fn test_transition_to_complete_complete_file_exists() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Create both pending and complete signature files
        let pending_sig_path = pending_signatures_path_for(&test_file).unwrap();
        fs::write(&pending_sig_path, r#"{"key": "value"}"#).unwrap();

        let complete_sig_path = signatures_path_for(&test_file).unwrap();
        fs::write(&complete_sig_path, r#"{"existing": "content"}"#).unwrap();

        // Create an AggregateSignature in Pending state
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures: HashMap::new(),
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Attempt to transition to complete
        let result = agg_sig.try_transition_to_complete();

        // Verify the error
        assert!(result.is_err());
        match result.err().unwrap() {
            AggregateSignatureError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
                assert!(
                    e.to_string()
                        .contains("Not overwriting existing complete aggregate signature")
                );
            }
            _ => panic!("Expected IO error of kind AlreadyExists"),
        }

        // Verify the pending file still exists
        assert!(pending_sig_path.exists());

        // Verify the complete file is unchanged
        let content = fs::read_to_string(&complete_sig_path).unwrap();
        assert_eq!(content, r#"{"existing": "content"}"#);
    }
    #[test]
    fn test_is_aggregate_signature_complete_pending() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create directory structure:
        // root/
        //   asfaload.signers/
        //     index.json
        //   file.txt
        //   file.txt.pending_signatures.json
        let signers_dir = root.join(SIGNERS_DIR);
        fs::create_dir_all(&signers_dir).unwrap();

        // Create a test file
        let test_file = root.join("file.txt");
        let file_content = b"test content";
        fs::write(&test_file, file_content).unwrap();
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;

        // Generate keys for testing
        let test_keys = TestKeys::new(2);
        let pubkey1 = test_keys.pub_key(0).unwrap();
        let seckey1 = test_keys.sec_key(0).unwrap();
        let pubkey2 = test_keys.pub_key(1).unwrap();
        let seckey2 = test_keys.sec_key(1).unwrap();

        // Create signers configuration with threshold 2
        let signers_config = SignersConfig {
            version: 1,
            initial_version: InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers: vec![SignerGroup {
                signers: vec![
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: pubkey1.clone(),
                        },
                    },
                    Signer {
                        kind: SignerKind::Key,
                        data: SignerData {
                            format: KeyFormat::Minisign,
                            pubkey: pubkey2.clone(),
                        },
                    },
                ],
                threshold: 2,
            }],
            master_keys: vec![],
            admin_keys: None,
        };

        // Write signers configuration
        let signers_file = signers_dir.join(SIGNERS_FILE);
        let config_json = serde_json::to_string_pretty(&signers_config).unwrap();
        fs::write(&signers_file, config_json).unwrap();

        // Create signatures
        let sig1 = seckey1.sign(&hash_for_content).unwrap();
        let sig2 = seckey2.sign(&hash_for_content).unwrap();

        // Copy global signers file to local
        let result = create_local_signers_for(&test_file);
        assert!(result.is_ok());

        // Test when pending signature file doesn't exist
        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, true);
        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should be incomplete when no pending file exists

        // Create pending signature file path
        let pending_sig_file_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));

        // Test incomplete signature (only one signature)
        let mut incomplete_sigs = HashMap::new();
        incomplete_sigs.insert(pubkey1.clone().to_base64(), sig1.to_base64());
        let incomplete_json = serde_json::to_string_pretty(&incomplete_sigs).unwrap();
        fs::write(&pending_sig_file_path, &incomplete_json).unwrap();

        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, true);
        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should be incomplete with only one signature

        // Test complete signature (both signatures)
        let mut complete_sigs = HashMap::new();
        complete_sigs.insert(pubkey1.to_base64(), sig1.to_base64());
        complete_sigs.insert(pubkey2.to_base64(), sig2.to_base64());
        let complete_json = serde_json::to_string_pretty(&complete_sigs).unwrap();
        fs::write(&pending_sig_file_path, complete_json).unwrap();

        assert!(
            is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, true).unwrap()
        ); // Should be complete with both signatures

        // Test invalid signature (wrong content)
        let mut invalid_sigs = HashMap::new();
        invalid_sigs.insert(
            pubkey1.to_base64(),
            seckey1
                .sign(&common::sha512_for_content(b"wrong content".to_vec())?)
                .unwrap()
                .to_base64(),
        );
        invalid_sigs.insert(pubkey2.to_base64(), sig2.to_base64());
        let invalid_json = serde_json::to_string_pretty(&invalid_sigs).unwrap();
        fs::write(&pending_sig_file_path, invalid_json).unwrap();

        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, true);
        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should be incomplete with invalid signature

        // Test with threshold 1 (should be complete with just one valid signature)
        let mut low_threshold_config = signers_config.clone();
        low_threshold_config.artifact_signers[0].threshold = 1;

        let config_json = serde_json::to_string_pretty(&low_threshold_config).unwrap();
        fs::write(local_signers_path_for(&test_file).unwrap(), config_json).unwrap();

        // Reset to pending signatures with one valid signature
        fs::write(&pending_sig_file_path, incomplete_json).unwrap();

        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, true);
        assert!(res.is_ok());
        assert!(res.unwrap()); // Should be complete with threshold 1 and one valid signature

        // Test with empty signatures file
        let empty_sigs: HashMap<String, String> = HashMap::new();
        let empty_json = serde_json::to_string_pretty(&empty_sigs).unwrap();
        fs::write(&pending_sig_file_path, empty_json).unwrap();

        let res = is_aggregate_signature_complete::<_, AsfaloadPublicKey<_>>(&test_file, true);
        assert!(!res.unwrap()); // Should be incomplete with empty signatures
        Ok(())
    }
    #[test]
    fn test_check_all_signers() -> Result<()> {
        // Create test keys and data
        let test_keys = TestKeys::new(5);
        let data = common::sha512_for_content(b"test data".to_vec())?;

        // Get public and secret keys
        let pubkey0 = test_keys.pub_key(0).unwrap();
        let seckey0 = test_keys.sec_key(0).unwrap();
        let pubkey1 = test_keys.pub_key(1).unwrap();
        let seckey1 = test_keys.sec_key(1).unwrap();
        let pubkey2 = test_keys.pub_key(2).unwrap();
        let seckey2 = test_keys.sec_key(2).unwrap();
        let pubkey3 = test_keys.pub_key(3).unwrap();
        let seckey3 = test_keys.sec_key(3).unwrap();
        let pubkey4 = test_keys.pub_key(4).unwrap();
        let seckey4 = test_keys.sec_key(4).unwrap();

        // Create signatures
        let sig0 = seckey0.sign(&data).unwrap();
        let sig1 = seckey1.sign(&data).unwrap();
        let sig2 = seckey2.sign(&data).unwrap();
        let sig3 = seckey3.sign(&data).unwrap();
        let sig4 = seckey4.sign(&data).unwrap();

        // Helper function to create a Signer
        let create_signer = |pubkey: AsfaloadPublicKey<minisign::PublicKey>| Signer {
            kind: SignerKind::Key,
            data: SignerData {
                format: KeyFormat::Minisign,
                pubkey,
            },
        };

        // Helper function to create a SignerGroup
        let create_group =
            |signers: Vec<Signer<_>>, threshold: u32| SignerGroup { signers, threshold };

        // Scenario 1: Only artifact_signers group
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![create_group(vec![create_signer(pubkey0.clone())], 1)],
                master_keys: vec![],
                admin_keys: None,
            };

            // Test with valid signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with irrelevant signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey4.clone(), sig4.clone());
            assert!(!check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let signatures = HashMap::new();
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 2: Artifact_signers with 2 subgroups
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![
                    create_group(vec![create_signer(pubkey0.clone())], 1),
                    create_group(vec![create_signer(pubkey1.clone())], 1),
                ],
                master_keys: vec![],
                admin_keys: None,
            };

            // Test with valid signatures for both groups
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with signature missing for one group
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 3: Admin_keys present
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![create_group(vec![create_signer(pubkey1.clone())], 1)],
                master_keys: vec![],
                admin_keys: Some(vec![create_group(vec![create_signer(pubkey0.clone())], 1)]),
            };

            // Test with valid signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 4: Master_keys present
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![create_group(vec![create_signer(pubkey1.clone())], 1)],
                master_keys: vec![create_group(vec![create_signer(pubkey0.clone())], 1)],
                admin_keys: None,
            };

            // Test with valid signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 5: Key in both artifact_signers and admin_keys
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![create_group(vec![create_signer(pubkey0.clone())], 1)],
                master_keys: vec![],
                admin_keys: Some(vec![create_group(vec![create_signer(pubkey0.clone())], 1)]),
            };

            // Test with valid signature (should satisfy both groups)
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature
            let signatures = HashMap::new();
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 6: Complex scenario with all key types and overlapping keys
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![
                    create_group(vec![create_signer(pubkey0.clone())], 1),
                    create_group(vec![create_signer(pubkey1.clone())], 1),
                ],
                master_keys: vec![create_group(vec![create_signer(pubkey2.clone())], 1)],
                admin_keys: Some(vec![
                    create_group(vec![create_signer(pubkey0.clone())], 1),
                    create_group(vec![create_signer(pubkey3.clone())], 1),
                ]),
            };

            // Test with overlapping key (pubkey0) satisfying both artifact and admin groups
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone()); // Covers both artifact group 1 and admin group 1
            signatures.insert(pubkey1.clone(), sig1.clone()); // Covers artifact group 2
            signatures.insert(pubkey2.clone(), sig2.clone()); // Covers master_keys
            signatures.insert(pubkey3.clone(), sig3.clone()); // Covers admin group 2
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with missing signature for one group
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            signatures.insert(pubkey2.clone(), sig2.clone());
            // Missing signature for pubkey3 (admin_keys group)
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 7: Test with threshold > 1
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![create_group(
                    vec![
                        create_signer(pubkey0.clone()),
                        create_signer(pubkey1.clone()),
                    ],
                    2,
                )],
                master_keys: vec![],
                admin_keys: None,
            };

            // Test with both signatures
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(check_all_signers(&signatures, &config, &data));

            // Test with only one signature
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 8: Test with empty configuration
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![],
                master_keys: vec![],
                admin_keys: None,
            };

            // Even with signatures, should return false for empty config
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), sig0.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }

        // Scenario 9: Test with invalid signature
        {
            let config = SignersConfig {
                version: 1,
                initial_version: InitialVersion {
                    permalink: "https://example.com".to_string(),
                    mirrors: vec![],
                },
                artifact_signers: vec![create_group(
                    vec![
                        create_signer(pubkey0.clone()),
                        create_signer(pubkey1.clone()),
                    ],
                    1,
                )],
                master_keys: vec![],
                admin_keys: None,
            };

            // Test with invalid signature (signed for different data)
            let other_data = common::sha512_for_content(b"other data".to_vec())?;
            let invalid_sig = seckey0.sign(&other_data).unwrap();
            let mut signatures = HashMap::new();
            signatures.insert(pubkey0.clone(), invalid_sig);
            signatures.insert(pubkey1.clone(), sig1.clone());
            assert!(!check_all_signers(&signatures, &config, &data));
        }
        Ok(())
    }
    // ------------------------------------
    // saving aggregate signature to a file
    // ------------------------------------
    #[test]
    fn test_save_to_file_pending_signature() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        fs::write(&test_file, file_content)?;

        // Generate keypairs
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();

        // Create a signature
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a pending aggregate signature
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures,
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the pending signature file exists
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify the content
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.len(), 1);
        assert!(parsed_content.contains_key(&pubkey.to_base64()));
        assert_eq!(parsed_content[&pubkey.to_base64()], signature.to_base64());

        Ok(())
    }

    #[test]
    fn test_save_to_file_complete_signature() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        fs::write(&test_file, file_content)?;

        // Generate keypairs
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();

        // Create a signature
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a complete aggregate signature
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            CompleteSignature,
        > = AggregateSignature {
            signatures,
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the complete signature file exists
        let complete_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            SIGNATURES_SUFFIX
        ));
        assert!(complete_sig_path.exists());

        // Verify the content
        let content = fs::read_to_string(&complete_sig_path)?;
        let parsed_content: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.len(), 1);
        assert!(parsed_content.contains_key(&pubkey.to_base64()));
        assert_eq!(parsed_content[&pubkey.to_base64()], signature.to_base64());

        Ok(())
    }

    #[test]
    fn test_save_to_file_multiple_signatures() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        let file_content = b"test content for signing";
        fs::write(&test_file, file_content)?;

        // Generate two keypairs
        let keypair1 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey1 = keypair1.public_key();
        let seckey1 = keypair1.secret_key("password").unwrap();
        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let seckey2 = keypair2.secret_key("password").unwrap();

        // Create signatures
        let hash_for_content = common::sha512_for_content(file_content.to_vec())?;
        let signature1 = seckey1.sign(&hash_for_content).unwrap();
        let signature2 = seckey2.sign(&hash_for_content).unwrap();

        // Create a pending aggregate signature with multiple signatures
        let mut signatures = HashMap::new();
        signatures.insert(pubkey1.clone(), signature1.clone());
        signatures.insert(pubkey2.clone(), signature2.clone());
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures,
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the pending signature file exists
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify the content contains both signatures
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.len(), 2);
        assert!(parsed_content.contains_key(&pubkey1.to_base64()));
        assert!(parsed_content.contains_key(&pubkey2.to_base64()));
        assert_eq!(parsed_content[&pubkey1.to_base64()], signature1.to_base64());
        assert_eq!(parsed_content[&pubkey2.to_base64()], signature2.to_base64());

        Ok(())
    }

    #[test]
    fn test_save_to_file_empty_signatures() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, b"test content")?;

        // Create an empty pending aggregate signature
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures: HashMap::new(),
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Save the signature to file
        agg_sig.save_to_file()?;

        // Verify the pending signature file exists
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        assert!(pending_sig_path.exists());

        // Verify the content is an empty JSON object
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.len(), 0);

        Ok(())
    }

    #[test]
    fn test_save_to_file_overwrites_existing() -> Result<()> {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path();

        // Create a test file
        let test_file = root.join("test_file.txt");
        fs::write(&test_file, b"test content")?;

        // Create an existing signature file with different content
        let pending_sig_path = test_file.with_file_name(format!(
            "{}.{}",
            test_file.file_name().unwrap().to_string_lossy(),
            PENDING_SIGNATURES_SUFFIX
        ));
        let existing_content = r#"{"old_key": "old_signature"}"#;
        fs::write(&pending_sig_path, existing_content)?;

        // Generate a keypair
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();

        // Create a signature
        let hash_for_content = common::sha512_for_content(b"test content".to_vec())?;
        let signature = seckey.sign(&hash_for_content).unwrap();

        // Create a pending aggregate signature
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature.clone());
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
            PendingSignature,
        > = AggregateSignature {
            signatures,
            origin: test_file.to_string_lossy().to_string(),
            subject: SignedFile::new(&test_file),
            marker: PhantomData,
        };

        // Save the signature to file (should overwrite)
        agg_sig.save_to_file()?;

        // Verify the content was overwritten
        let content = fs::read_to_string(&pending_sig_path)?;
        let parsed_content: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed_content.len(), 1);
        assert!(parsed_content.contains_key(&pubkey.to_base64()));
        assert_eq!(parsed_content[&pubkey.to_base64()], signature.to_base64());

        Ok(())
    }
}
