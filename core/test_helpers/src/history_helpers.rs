use anyhow::Result;
use chrono::{DateTime, Utc};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};
use signatures::signatures_file::{SignaturesFile, TaggedSignature};
use signers_file_types::{Forge, ForgeOrigin, HistoryEntry, SignersConfig, SignersConfigMetadata};

use crate::TestKeys;

/// Build a `SignersConfig` with keys 0 and 1 as artifact signers, threshold 2.
/// Uses `with_keys` (includes all key categories: admin, master, revocation all None).
pub fn create_test_signers_config(test_keys: &TestKeys) -> SignersConfig {
    SignersConfig::with_keys(
        1,
        (
            vec![
                test_keys.pub_key(0).unwrap().clone(),
                test_keys.pub_key(1).unwrap().clone(),
            ],
            2,
        ),
        None,
        None,
        None,
    )
    .unwrap()
}

/// Build a `SignaturesFile` with mock (non-cryptographic) signature strings.
/// Useful for tests that don't need real signature verification.
pub fn create_test_signatures(test_keys: &TestKeys) -> SignaturesFile {
    let mut sig_file = SignaturesFile::new();
    sig_file.entries.insert(
        test_keys.pub_key(0).unwrap().to_base64(),
        TaggedSignature {
            format: test_keys.pub_key(0).unwrap().key_format(),
            signature: "test_signature_0".to_string(),
        },
    );
    sig_file.entries.insert(
        test_keys.pub_key(1).unwrap().to_base64(),
        TaggedSignature {
            format: test_keys.pub_key(1).unwrap().key_format(),
            signature: "test_signature_1".to_string(),
        },
    );
    sig_file
}

/// Build a complete `HistoryEntry` with mock (non-cryptographic) signatures.
/// Uses `create_test_signers_config` and `create_test_signatures` internally.
/// The metadata uses `test_metadata()` (hardcoded Github forge URL).
pub fn create_test_history_entry(test_keys: &TestKeys, timestamp: DateTime<Utc>) -> HistoryEntry {
    HistoryEntry {
        obsoleted_at: timestamp,
        signers_file: create_test_signers_config(test_keys).to_json().unwrap(),
        signatures: create_test_signatures(test_keys),
        metadata: crate::test_metadata(),
    }
}

/// Sign arbitrary JSON bytes with the given secret keys and return a `SignaturesFile`.
/// Computes SHA-512 hash of the bytes, then signs with each key at the given indices.
pub fn sign_json_bytes(
    json_bytes: &[u8],
    keys: &TestKeys,
    indices: &[usize],
) -> Result<SignaturesFile> {
    let hash = common::sha512_for_content(json_bytes.to_vec())?;
    let mut sig_file = SignaturesFile::new();
    for &i in indices {
        let pubkey = keys.pub_key(i).unwrap();
        let seckey = keys.sec_key(i).unwrap();
        let signature = seckey.sign(&hash)?;
        sig_file.entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: signature.to_base64(),
            },
        );
    }
    Ok(sig_file)
}

/// Sign a `SignersConfig`'s JSON with the given secret keys.
/// Returns the JSON string that was signed and the corresponding `SignaturesFile`.
pub fn sign_config(
    config: &SignersConfig,
    keys: &TestKeys,
    indices: &[usize],
) -> Result<(String, SignaturesFile)> {
    let json = serde_json::to_string_pretty(config)?;
    let sig_file = sign_json_bytes(json.as_bytes(), keys, indices)?;
    Ok((json, sig_file))
}

/// Build a fully valid `HistoryEntry` with real cryptographic signatures
/// and a custom forge URL in metadata.
///
/// This is the primary helper for `validate_first_entry` tests.
/// The `forge_url` is embedded in the entry's metadata so the test can
/// point it at a mockito server.
pub fn make_history_entry(
    config: &SignersConfig,
    keys: &TestKeys,
    signer_indices: &[usize],
    forge_url: &str,
    timestamp: DateTime<Utc>,
) -> Result<HistoryEntry> {
    let (json, sig_file) = sign_config(config, keys, signer_indices)?;
    let metadata = SignersConfigMetadata::from_forge(ForgeOrigin::new(
        Forge::Github,
        forge_url.to_string(),
        Utc::now(),
    ));
    Ok(HistoryEntry {
        obsoleted_at: timestamp,
        signers_file: json,
        signatures: sig_file,
        metadata,
    })
}
