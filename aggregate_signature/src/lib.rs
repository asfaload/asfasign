use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
use signers_file::{SignerGroup, SignersConfig};
use std::collections::HashMap;
use std::path::Path;
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
}

pub struct AggregateSignature<P, S>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    signatures: HashMap<P, S>,
    // The origin is a String. I originally wanted to make it a Url, but
    // then the path must be absolute, and I didn't want to set that restriction right now
    origin: String,
}

impl<P, S> AggregateSignature<P, S>
where
    P: AsfaloadPublicKeyTrait + Eq + std::hash::Hash + Clone,
    S: AsfaloadSignatureTrait,
{
    /// Load signatures from a directory where each filename is a base64-encoded public key
    pub fn load_from_dir(dir_path: &Path) -> Result<Self, AggregateSignatureError> {
        let mut signatures = HashMap::new();

        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let signature_path = entry.path();
            if signature_path.is_file() {
                // Decode filename to get public key
                let filename = signature_path
                    .file_name()
                    .ok_or_else(|| {
                        AggregateSignatureError::PublicKey("Invalid filename".to_string())
                    })?
                    .to_string_lossy()
                    .into_owned();

                let pubkey = P::from_filename(filename)
                    .map_err(|e| AggregateSignatureError::PublicKey(format!("{}", e)))?;

                // Read and parse signature
                let sig_content = std::fs::read_to_string(&signature_path)?;
                let signature = S::from_string(&sig_content)
                    .map_err(|e| AggregateSignatureError::Signature(e.to_string()))?;

                signatures.insert(pubkey, signature);
            }
        }

        Ok(Self {
            signatures,
            origin: dir_path.to_string_lossy().to_string(),
        })
    }

    /// Check if aggregate signature meets all thresholds in signers config
    pub fn is_artifact_complete(&self, signers_config: &SignersConfig<P>) -> bool {
        // Check artifact_signers groups
        Self::check_groups(&signers_config.artifact_signers, &self.signatures)
    }
    pub fn is_master_complete(&self, signers_config: &SignersConfig<P>) -> bool {
        // Check master_keys groups
        Self::check_groups(&signers_config.master_keys, &self.signatures)
    }

    pub fn is_admin_complete(&self, signers_config: &SignersConfig<P>) -> bool {
        // Check admin_keys groups if present
        signers_config
            .admin_keys
            .as_ref()
            .is_some_and(|keys| Self::check_groups(keys, &self.signatures))
    }

    /// Check if all groups in a category meet their thresholds
    pub fn check_groups(groups: &[SignerGroup<P>], signatures: &HashMap<P, S>) -> bool {
        !groups.is_empty()
            && groups.iter().all(|group| {
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
    use minisign::SignatureBox;
    use signatures::keys::{AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait};
    use signatures::keys::{AsfaloadPublicKey, AsfaloadSignature};
    use signers_file::{KeyFormat, SignerKind};
    use tempfile::TempDir;

    #[test]
    fn test_load_and_complete() {
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

        // Create signatures map manually
        let mut signatures = HashMap::new();
        signatures.insert(pubkey.clone(), signature);

        // Create aggregate signature manually
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
        > = AggregateSignature {
            signatures,
            origin: "test_origin".to_string(),
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
            signers_file::parse_signers_config(&json_config).unwrap();

        // Should be complete with threshold 1
        assert!(agg_sig.is_artifact_complete(&signers_config));

        // Should be incomplete with threshold 2
        let high_threshold_config =
            json_config_template.replace("PUBKEY1_PLACEHOLDER", &pubkey.to_base64());
        let high_threshold_config =
            high_threshold_config.replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());
        let high_threshold_config = high_threshold_config.replace("THRESHOLD_PLACEHOLDER", "2");
        let signers_config: SignersConfig<AsfaloadPublicKey<minisign::PublicKey>> =
            signers_file::parse_signers_config(&high_threshold_config).unwrap();
        assert!(!agg_sig.is_artifact_complete(&signers_config));

        assert_eq!(agg_sig.origin, "test_origin");
    }

    // This test illustrates how a signers config can be defined programmatically. This
    // will not be the usual case, but could be handy.
    #[test]
    fn test_load_and_complete_programmatically() {
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
        let pubkey_b64 = pubkey.to_filename();
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
        assert!(agg_sig.is_artifact_complete(&signers_config));

        // Should be incomplete with threshold 2
        let mut high_threshold_group = group.clone();
        high_threshold_group.threshold = 2;
        let high_threshold_config = SignersConfig {
            artifact_signers: vec![high_threshold_group],
            ..signers_config.clone()
        };
        assert!(!agg_sig.is_artifact_complete(&high_threshold_config));

        assert_eq!(agg_sig.origin, dir_path.to_string_lossy().to_string());
    }

    #[test]
    fn test_multiple_groups() {
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

        // Create signatures map manually
        let mut signatures = HashMap::new();
        signatures.insert(pubkey1.clone(), sig1);
        signatures.insert(pubkey2.clone(), sig2);

        // Create aggregate signature manually
        let agg_sig: AggregateSignature<
            AsfaloadPublicKey<minisign::PublicKey>,
            AsfaloadSignature<minisign::SignatureBox>,
        > = AggregateSignature {
            signatures,
            origin: "test_origin".to_string(),
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
            signers_file::parse_signers_config(&json_config).unwrap();

        // Should be complete with both groups
        assert!(agg_sig.is_artifact_complete(&signers_config));

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
            signers_file::parse_signers_config(&json_config_mixed).unwrap();

        // Should be complete with mixed configuration
        assert!(agg_sig.is_artifact_complete(&signers_config_mixed));
        assert!(agg_sig.is_master_complete(&signers_config_mixed));
        // Check an null admin group is not comsidered as complete
        assert!(!agg_sig.is_admin_complete(&signers_config_mixed));
        // Empty admin_keys array is never complete
        let mut signers_config_empty_admin = signers_config_mixed.clone();
        signers_config_empty_admin.admin_keys = Some([].to_vec());
        assert!(!agg_sig.is_admin_complete(&signers_config_empty_admin));

        assert_eq!(agg_sig.origin, "test_origin");
    }

    #[test]
    fn test_check_groups_from_json_minimal() {
        // Generate keypairs
        let keypair1 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey1 = keypair1.public_key();
        let seckey1 = keypair1.secret_key("password").unwrap();
        let keypair2 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey2 = keypair2.public_key();
        let seckey2 = keypair2.secret_key("password").unwrap();
        let keypair3 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey3 = keypair3.public_key();
        let seckey3 = keypair3.secret_key("password").unwrap();
        let keypair4 = AsfaloadKeyPair::new("password").unwrap();
        let pubkey4 = keypair4.public_key();
        let seckey4 = keypair4.secret_key("password").unwrap();

        let substitute_keys = |tpl: String| {
            let res = tpl.replace("PUBKEY1_PLACEHOLDER", &pubkey1.to_base64());
            let res = res.replace("PUBKEY2_PLACEHOLDER", &pubkey2.to_base64());
            let res = res.replace("PUBKEY3_PLACEHOLDER", &pubkey3.to_base64());
            res.replace("PUBKEY4_PLACEHOLDER", &pubkey4.to_base64())
        };

        let build_groups = |tpl: String| {
            let json = substitute_keys(tpl);

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
                assert!(AggregateSignature::<_, _>::check_groups(
                    &groups, signatures
                ))
            } else {
                assert!(!AggregateSignature::<_, _>::check_groups(
                    &groups, signatures
                ))
            }
        };
        // Create signatures for pubkey1 and pubkey2 only
        let data = b"test data";
        let sig1 = seckey1.sign(data).unwrap();
        let sig2 = seckey2.sign(data).unwrap();
        let sig3 = seckey3.sign(data).unwrap();
        let sig4 = seckey4.sign(data).unwrap();

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
            // 2-of-1: this will never be complete, even if we have the signature from the
            // signer and an additional one.
            // FIXME: this json should raise an error when parsed to build our rust object.
            (
                r#"
    [
      {
        "signers": [
          { "kind": "key", "data": { "format": "minisign", "pubkey": "PUBKEY1_PLACEHOLDER" } }
        ],
        "threshold": 2
      }
    ]
    "#,
                signatures_1_2.clone(),
                incomplete,
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
        ];

        // ------------------------------------------------------------
        // Run all defined tests
        // ------------------------------------------------------------
        test_groups
            .iter()
            .for_each(|g| check_validity(g.0.to_string(), &g.1, g.2));

        // Empty groups are always incomplete
        assert!(!AggregateSignature::<_, _>::check_groups(
            &[],
            &HashMap::<AsfaloadPublicKey<minisign::PublicKey>, AsfaloadSignature<SignatureBox>>::new(),
        ));
        assert!(!AggregateSignature::<_, _>::check_groups(
            &[],
            &signatures_1_2_3_4
        ));
    }
}
