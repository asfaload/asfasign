use crate::{AsfaloadLibResult, ClientLibError};
use features_lib::{
    AsfaloadHashes, AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSignatures,
    SignersConfig,
    aggregate_signature_helpers::{check_groups, get_individual_signatures_from_bytes},
};
use std::collections::HashMap;

pub fn verify_signatures(
    signatures_content: Vec<u8>,
    signers_config: &SignersConfig,
    data: &AsfaloadHashes,
) -> AsfaloadLibResult<(usize, usize)> {
    let artifact_groups = signers_config.artifact_signers();
    if artifact_groups.is_empty() {
        return Err(ClientLibError::MissingArtifactSigners);
    }

    let mut typed_signatures: HashMap<AsfaloadPublicKeys, AsfaloadSignatures> = HashMap::new();
    let mut invalid_count = 0;

    let parsed_signatures = get_individual_signatures_from_bytes(signatures_content)
        .map_err(|e| ClientLibError::SignaturesParseError(e.to_string()))?;

    for (pubkey, signature) in parsed_signatures {
        if pubkey.verify(&signature, data).is_err() {
            invalid_count += 1;
            continue;
        }

        typed_signatures.insert(pubkey, signature);
    }

    let is_complete = check_groups(artifact_groups, &typed_signatures, data);

    if !is_complete {
        return Err(ClientLibError::SignatureThresholdNotMet {
            required: artifact_groups.len(),
            found: typed_signatures.len(),
        });
    }

    let valid_count = typed_signatures.len();
    Ok((valid_count, invalid_count))
}

/// Get hash algorithm and expected hash for a file from the index
pub fn get_file_hash_info(
    index: &AsfaloadIndex,
    filename: &str,
) -> AsfaloadLibResult<(features_lib::HashAlgorithm, String)> {
    let file_entry = index
        .published_files
        .iter()
        .find(|f| f.file_name == filename)
        .ok_or_else(|| ClientLibError::FileNotInIndex(filename.to_string()))?;

    Ok((file_entry.algo.clone(), file_entry.hash.clone()))
}

pub fn verify_file_hash(
    algo: &features_lib::HashAlgorithm,
    expected_hash: &str,
    computed_hash: &str,
) -> AsfaloadLibResult<()> {
    use features_lib::HashAlgorithm;

    match algo {
        HashAlgorithm::Sha1 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(
                HashAlgorithm::Sha1,
            ));
        }
        HashAlgorithm::Md5 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Md5));
        }
        _ => {} // Sha256 and Sha512 are supported
    }

    if expected_hash.to_lowercase() != computed_hash.to_lowercase() {
        return Err(ClientLibError::HashMismatch {
            expected: expected_hash.to_lowercase(),
            computed: computed_hash.to_lowercase(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use features_lib::HashAlgorithm;

    #[test]
    fn verify_file_hash_sha256_matching() {
        let hash = "abc123def456";
        let result = verify_file_hash(&HashAlgorithm::Sha256, hash, hash);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_file_hash_sha512_matching() {
        let hash = "abc123def456";
        let result = verify_file_hash(&HashAlgorithm::Sha512, hash, hash);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_file_hash_case_insensitive() {
        let result = verify_file_hash(&HashAlgorithm::Sha256, "ABC123DEF", "abc123def");
        assert!(result.is_ok());
    }

    #[test]
    fn verify_file_hash_mismatch() {
        let result = verify_file_hash(&HashAlgorithm::Sha256, "abc123", "def456");
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::HashMismatch { expected, computed } => {
                assert_eq!(expected, "abc123");
                assert_eq!(computed, "def456");
            }
            e => panic!("Expected HashMismatch, got: {e:?}"),
        }
    }

    #[test]
    fn verify_file_hash_sha1_unsupported() {
        let result = verify_file_hash(&HashAlgorithm::Sha1, "abc", "abc");
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Sha1) => {}
            e => panic!("Expected UnsupportedHashAlgorithm(Sha1), got: {e:?}"),
        }
    }

    #[test]
    fn verify_file_hash_md5_unsupported() {
        let result = verify_file_hash(&HashAlgorithm::Md5, "abc", "abc");
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Md5) => {}
            e => panic!("Expected UnsupportedHashAlgorithm(Md5), got: {e:?}"),
        }
    }
}
