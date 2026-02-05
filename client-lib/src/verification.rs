use crate::{ClientLibError, Result};
use features_lib::{
    aggregate_signature_helpers::{check_groups, get_individual_signatures_from_bytes},
    sha512_for_content, AsfaloadHashes, AsfaloadIndex, AsfaloadPublicKeyTrait, AsfaloadPublicKeys,
    AsfaloadSignatures, SignersConfig,
};
use sha2::{Digest, Sha256};
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

pub fn verify_file_hash(
    index: &AsfaloadIndex,
    filename: &str,
    file_content: &[u8],
) -> Result<features_lib::HashAlgorithm> {
    use features_lib::HashAlgorithm;

    let file_entry = index
        .published_files
        .iter()
        .find(|f| f.file_name == filename)
        .ok_or_else(|| ClientLibError::FileNotInIndex(filename.to_string()))?;

    let expected_hash_str = &file_entry.hash;

    let computed_hash = match file_entry.algo {
        HashAlgorithm::Sha256 => {
            let result = Sha256::digest(file_content);
            hex::encode(result)
        }
        HashAlgorithm::Sha512 => {
            let hash = sha512_for_content(file_content)?;
            match hash {
                AsfaloadHashes::Sha512(bytes) => hex::encode(bytes),
            }
        }
        HashAlgorithm::Sha1 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(
                HashAlgorithm::Sha1,
            ));
        }
        HashAlgorithm::Md5 => {
            return Err(ClientLibError::UnsupportedHashAlgorithm(HashAlgorithm::Md5));
        }
    };

    if expected_hash_str.to_lowercase() != computed_hash.to_lowercase() {
        return Err(ClientLibError::HashMismatch {
            expected: expected_hash_str.to_lowercase(),
            computed: computed_hash.to_lowercase(),
        });
    }

    Ok(file_entry.algo.clone())
}

pub fn sha256_for_content<T: std::borrow::Borrow<[u8]>>(content_in: T) -> Result<String> {
    let content = content_in.borrow();
    if content.is_empty() {
        Err(ClientLibError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "We don't compute the sha of an empty value",
        )))
    } else {
        let result = Sha256::digest(content);
        Ok(hex::encode(result))
    }
}
