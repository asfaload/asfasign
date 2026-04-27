use crate::keys::KeyFormat;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A signature entry tagged with its algorithm format.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaggedSignature {
    pub format: KeyFormat,
    pub signature: String,
}

/// The envelope for signatures files (*.signatures.json, *.signatures.json.pending).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignaturesFile {
    pub entries: HashMap<String, TaggedSignature>,
}

impl SignaturesFile {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl Default for SignaturesFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_signatures_file_serialization() {
        let sig_file = SignaturesFile::new();
        let json = serde_json::to_string(&sig_file).unwrap();
        assert_eq!(json, r#"{"entries":{}}"#);
    }

    #[test]
    fn test_empty_signatures_file_roundtrip() {
        let sig_file = SignaturesFile::new();
        let json = serde_json::to_string_pretty(&sig_file).unwrap();
        let parsed: SignaturesFile = serde_json::from_str(&json).unwrap();
        assert_eq!(sig_file, parsed);
    }

    #[test]
    fn test_signatures_file_with_entries_roundtrip() {
        let mut sig_file = SignaturesFile::new();
        sig_file.entries.insert(
            "RWTqI2MWePubKeyBase64".to_string(),
            TaggedSignature {
                format: KeyFormat::Minisign,
                signature: "RWQD4YGXRSignatureBase64".to_string(),
            },
        );

        let json = serde_json::to_string_pretty(&sig_file).unwrap();
        let parsed: SignaturesFile = serde_json::from_str(&json).unwrap();
        assert_eq!(sig_file, parsed);
    }

    #[test]
    fn test_signatures_file_deserialization_with_entries() {
        let json = r#"{
            "entries": {
                "pubkey1": {
                    "format": "asfaload",
                    "signature": "sig1"
                },
                "pubkey2": {
                    "format": "asfaload",
                    "signature": "sig2"
                }
            }
        }"#;

        let sig_file: SignaturesFile = serde_json::from_str(json).unwrap();
        assert_eq!(sig_file.entries.len(), 2);
        assert!(sig_file.entries.contains_key("pubkey1"));
        assert!(sig_file.entries.contains_key("pubkey2"));

        let entry1 = &sig_file.entries["pubkey1"];
        assert_eq!(entry1.format, KeyFormat::Minisign);
        assert_eq!(entry1.signature, "sig1");
    }

    #[test]
    fn test_default_is_empty() {
        let sig_file = SignaturesFile::default();
        assert!(sig_file.entries.is_empty());
    }

    #[test]
    fn test_tagged_signature_clone() {
        let tagged = TaggedSignature {
            format: KeyFormat::Minisign,
            signature: "test_sig".to_string(),
        };
        let cloned = tagged.clone();
        assert_eq!(tagged, cloned);
    }
}
