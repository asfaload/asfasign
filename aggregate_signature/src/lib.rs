use base64::{Engine as _, prelude::BASE64_STANDARD};
use minisign::SignatureBox;
use signatures::keys::{
    AsfaloadPublicKey, AsfaloadPublicKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
};
use signers_file::{KeyFormat, SignerGroup, SignerKind, SignersConfig};
use std::collections::HashMap;
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
    #[error("No signatures found")]
    NoSignatures,
    #[error("Threshold not met for group")]
    ThresholdNotMet,
}

pub struct AggregateSignature<P, S>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    signatures: HashMap<P, S>,
    path: PathBuf,
}

impl<P, S> AggregateSignature<P, S>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    /// Load signatures from a directory where each filename is a base64-encoded public key
    pub fn load_from_dir(path: &Path) -> Result<Self, AggregateSignatureError> {
        let mut signatures = HashMap::new();

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                // Decode filename to get public key
                let filename = path
                    .file_name()
                    .ok_or_else(|| {
                        AggregateSignatureError::PublicKey("Invalid filename".to_string())
                    })?
                    .to_string_lossy()
                    .into_owned();

                let pubkey_bytes = BASE64_STANDARD.decode(filename)?;
                let pubkey_str = String::from_utf8(pubkey_bytes)?;
                let pubkey = P::from_base64(pubkey_str)
                    .map_err(|e| AggregateSignatureError::PublicKey(format!("{}", e)))?;

                // Read and parse signature
                let sig_content = std::fs::read_to_string(&path)?;
                let signature = S::from_string(&sig_content)
                    .map_err(|e| AggregateSignatureError::Signature(e.to_string()))?;

                signatures.insert(pubkey, signature);
            }
        }

        if signatures.is_empty() {
            return Err(AggregateSignatureError::NoSignatures);
        }

        Ok(Self {
            signatures,
            path: path.to_path_buf(),
        })
    }

    /// Check if aggregate signature meets all thresholds in signers config
    pub fn is_complete(&self, signers_config: &SignersConfig<P>) -> bool {
        // Check artifact_signers groups
        if !Self::check_groups(&signers_config.artifact_signers, &self.signatures) {
            return false;
        }

        // Check master_keys groups
        if !Self::check_groups(&signers_config.master_keys, &self.signatures) {
            return false;
        }

        // Check admin_keys groups if present
        if let Some(admin_keys) = &signers_config.admin_keys {
            if !Self::check_groups(admin_keys, &self.signatures) {
                return false;
            }
        }

        true
    }

    /// Check if all groups in a category meet their thresholds
    fn check_groups(groups: &[SignerGroup<P>], signatures: &HashMap<P, S>) -> bool {
        groups.iter().all(|group| {
            let count = group
                .signers
                .iter()
                .filter(|signer| signatures.contains_key(&signer.data.pubkey))
                .count();
            count >= group.threshold as usize
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signatures::keys::{AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait};
    use tempfile::TempDir;

    #[test]
    fn test_load_and_complete() {
        // Create temp directory
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Generate keypairs
        let keypair = AsfaloadKeyPair::new("password").unwrap();
        let pubkey = keypair.public_key();
        let seckey = keypair.secret_key("password").unwrap();

        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let _seckey2 = keypair2.secret_key("password").unwrap();

        // Create signature
        let data = b"test data";
        let signature = seckey.sign(data).unwrap();

        // Write signature file (base64-encoded pubkey filename)
        let pubkey_b64 = BASE64_STANDARD.encode(pubkey.to_base64());
        let sig_file_path = dir_path.join(pubkey_b64);
        std::fs::write(&sig_file_path, signature.to_string()).unwrap();

        // Load aggregate signature
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
        > = AggregateSignature::load_from_dir(dir_path).unwrap();

        // Create signers config with threshold 1
        let signer = signers_file::Signer {
            kind: SignerKind::Key,
            data: signers_file::SignerData {
                format: KeyFormat::Minisign,
                pubkey: pubkey.clone(),
            },
        };
        let signer2 = signers_file::Signer {
            kind: SignerKind::Key,
            data: signers_file::SignerData {
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
            initial_version: signers_file::InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers: vec![group.clone()],
            master_keys: vec![],
            admin_keys: None,
        };

        // Should be complete with threshold 1
        assert!(agg_sig.is_complete(&signers_config));

        // Should be incomplete with threshold 2
        let mut high_threshold_group = group.clone();
        high_threshold_group.threshold = 2;
        let high_threshold_config = SignersConfig {
            artifact_signers: vec![high_threshold_group],
            ..signers_config.clone()
        };
        assert!(!agg_sig.is_complete(&high_threshold_config));
    }

    #[test]
    fn test_multiple_groups() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Generate two keypairs
        let keypair1 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey1 = keypair1.public_key();
        let seckey1 = keypair1.secret_key("password").unwrap();

        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let seckey2 = keypair2.secret_key("password").unwrap();

        // Create signatures
        let data = b"test data";
        let sig1 = seckey1.sign(data).unwrap();
        let sig2 = seckey2.sign(data).unwrap();

        // Write signature files
        let pubkey1_b64 = BASE64_STANDARD.encode(pubkey1.to_base64());
        std::fs::write(dir_path.join(pubkey1_b64), sig1.to_string()).unwrap();

        let pubkey2_b64 = BASE64_STANDARD.encode(pubkey2.to_base64());
        std::fs::write(dir_path.join(pubkey2_b64), sig2.to_string()).unwrap();

        // Load aggregate signature
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
        > = AggregateSignature::load_from_dir(dir_path).unwrap();

        // Create signers
        let signer1 = signers_file::Signer {
            kind: SignerKind::Key,
            data: signers_file::SignerData {
                format: KeyFormat::Minisign,
                pubkey: pubkey1.clone(),
            },
        };
        let signer2 = signers_file::Signer {
            kind: SignerKind::Key,
            data: signers_file::SignerData {
                format: KeyFormat::Minisign,
                pubkey: pubkey2.clone(),
            },
        };

        // Create groups with threshold 1
        let group1 = SignerGroup {
            signers: vec![signer1.clone()],
            threshold: 1,
        };
        let group2 = SignerGroup {
            signers: vec![signer2.clone()],
            threshold: 1,
        };

        // Config with both groups in artifact_signers
        let signers_config = SignersConfig {
            version: 1,
            initial_version: signers_file::InitialVersion {
                permalink: "https://example.com".to_string(),
                mirrors: vec![],
            },
            artifact_signers: vec![group1.clone(), group2.clone()],
            master_keys: vec![],
            admin_keys: None,
        };

        // Should be complete
        assert!(agg_sig.is_complete(&signers_config));

        // Config with one group in artifact_signers and one in master_keys
        let signers_config_mixed = SignersConfig {
            artifact_signers: vec![group1],
            master_keys: vec![group2],
            ..signers_config.clone()
        };
        assert!(agg_sig.is_complete(&signers_config_mixed));
    }
}
