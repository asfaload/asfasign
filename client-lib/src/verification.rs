use crate::{ClientLibError, Result};
use features_lib::{
    aggregate_signature_helpers::{check_groups, get_individual_signatures_from_bytes},
    AsfaloadHashes, AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSignatures,
    SignersConfig,
};
use std::collections::HashMap;

pub fn verify_signatures(
    signatures_content: Vec<u8>,
    signers_config: &SignersConfig,
    data: &AsfaloadHashes,
) -> Result<(usize, usize)> {
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
) -> Result<(features_lib::HashAlgorithm, String)> {
    let file_entry = index
        .published_files
        .iter()
        .find(|f| f.file_name == filename)
        .ok_or_else(|| ClientLibError::FileNotInIndex(filename.to_string()))?;

    Ok((file_entry.algo.clone(), file_entry.hash.clone()))
}

pub fn verify_file_hash(
    index: &AsfaloadIndex,
    filename: &str,
    computed_hash: &str,
) -> Result<features_lib::HashAlgorithm> {
    use features_lib::HashAlgorithm;

    let file_entry = index
        .published_files
        .iter()
        .find(|f| f.file_name == filename)
        .ok_or_else(|| ClientLibError::FileNotInIndex(filename.to_string()))?;

    let expected_hash_str = &file_entry.hash;

    match file_entry.algo {
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

    if expected_hash_str.to_lowercase() != computed_hash.to_lowercase() {
        return Err(ClientLibError::HashMismatch {
            expected: expected_hash_str.to_lowercase(),
            computed: computed_hash.to_lowercase(),
        });
    }

    Ok(file_entry.algo.clone())
}
