//! On-disk byte layout for asfaload-priv encrypted private keys.
//!
//! Layout (143 bytes total):
//!
//! | offset   | field                          | len |
//! |----------|--------------------------------|-----|
//! |   0-  7  | magic "ASFALOAD"               |  8  |
//! |   8      | version (u8) = 1               |  1  |
//! |   9- 40  | public_key (ed25519, 32 bytes) | 32  |
//! |  41      | kdf_id (u8) = 1 (argon2id)     |  1  |
//! |  42- 45  | argon2_m_cost (u32 BE, KiB)    |  4  |
//! |  46- 49  | argon2_t_cost (u32 BE)         |  4  |
//! |  50- 53  | argon2_p_cost (u32 BE)         |  4  |
//! |  54- 69  | salt                           | 16  |
//! |  70      | aead_id (u8) = 1 (XChaCha20P1) |  1  |
//! |  71- 94  | aead_nonce                     | 24  |
//! |  95-126  | ciphertext (ed25519 seed)      | 32  |
//! | 127-142  | AEAD tag                       | 16  |
//!
//! Associated data for the AEAD = bytes 0..=70 (magic through aead_id).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

pub const MAGIC: [u8; 8] = *b"ASFALOAD";
pub const VERSION: u8 = 1;
pub const KDF_ID_ARGON2ID: u8 = 1;
pub const AEAD_ID_XCHACHA20POLY1305: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const SEED_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Offset of the 32-byte ed25519 public key within the encrypted blob.
/// The public key lives in the unencrypted-but-AEAD-authenticated portion.
pub const PK_OFFSET: usize = 9;
/// Length of the ed25519 public-key field embedded in the AEAD-authenticated header.
pub const PK_LEN: usize = 32;
/// Offset of the single-byte KDF identifier.
pub const KDF_ID_OFFSET: usize = PK_OFFSET + PK_LEN;
/// Offset of the 4-byte Argon2id m_cost (KiB, big-endian).
pub const ARGON2_M_COST_OFFSET: usize = KDF_ID_OFFSET + 1;
/// Offset of the 4-byte Argon2id t_cost (big-endian).
pub const ARGON2_T_COST_OFFSET: usize = ARGON2_M_COST_OFFSET + 4;
/// Offset of the 4-byte Argon2id p_cost (big-endian).
pub const ARGON2_P_COST_OFFSET: usize = ARGON2_T_COST_OFFSET + 4;
/// Offset of the KDF salt.
pub const SALT_OFFSET: usize = ARGON2_P_COST_OFFSET + 4;
/// Offset of the single-byte AEAD identifier.
pub const AEAD_ID_OFFSET: usize = SALT_OFFSET + SALT_LEN;
/// Offset of the AEAD nonce.
pub const NONCE_OFFSET: usize = AEAD_ID_OFFSET + 1;
pub const AD_LEN: usize = 71; // bytes 0..=70
pub const TOTAL_LEN: usize = 143;

/// Here are uppr bounds of argon2id parameters we accept. These are
/// not the default value we use,but we will refuse to decode keys with
/// values higher than these.
/// Upper bound on argon2id memory cost (KiB). ~1 GiB. Prevents OOM on
/// tampered blobs with extreme cost parameters.
pub const MAX_M_COST: u32 = 1_048_576;
/// Upper bound on argon2id time cost (iterations).
pub const MAX_T_COST: u32 = 1_000;
/// Upper bound on argon2id parallelism lanes.
pub const MAX_P_COST: u32 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    /// Production defaults per spec: 64 MiB / 3 passes / 1 lane.
    /// Owasp recommendations:
    /// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub const PRODUCTION: Self = Self {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 1,
    };
    /// Test-mode parameters per spec: 8 KiB / 1 pass / 1 lane. Sub-millisecond.
    ///
    /// Gated behind the `test-utils` feature (and always available in `cfg(test)`
    /// for this crate's own tests) so that weak parameters cannot be used in
    /// production builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub const TEST: Self = Self {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("not an asfaload key (bad magic)")]
    BadMagic,
    #[error("unsupported asfaload version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported KDF id: {0}")]
    UnsupportedKdf(u8),
    #[error("unsupported AEAD id: {0}")]
    UnsupportedAead(u8),
    #[error("argon2id parameter out of range (m_cost={0}, t_cost={1}, p_cost={2})")]
    ParamsOutOfRange(u32, u32, u32),
    #[error("blob has wrong length: got {got} bytes, expected {TOTAL_LEN}")]
    BadLength { got: usize },
    #[error("argon2id derivation failed: {0}")]
    Kdf(String),
    #[error("AEAD decryption failed (wrong password or tampered blob)")]
    AeadDecrypt,
    #[error("AEAD encryption failed: {0}")]
    AeadEncrypt(String),
}

impl From<FormatError> for common::errors::keys::KeyError {
    fn from(err: FormatError) -> Self {
        common::errors::keys::KeyError::AsfaloadFormat(err.to_string())
    }
}

/// Encode an encrypted private key blob.
///
/// Inputs:
/// - `seed`: the 32-byte ed25519 seed to protect.
/// - `public_key`: the 32-byte ed25519 public key (stored unencrypted but AEAD-authenticated).
/// - `password`: the user passphrase.
/// - `params`: argon2id cost parameters.
/// - `salt`, `nonce`: caller-supplied random bytes (so the function stays pure).
///
/// Returns the 143-byte on-disk representation.
pub fn encode(
    seed: &[u8; SEED_LEN],
    public_key: &[u8; PK_LEN],
    password: &[u8],
    params: Argon2Params,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<[u8; TOTAL_LEN], FormatError> {
    // Build the associated data (header through aead_id) first.
    let mut ad = [0u8; AD_LEN];
    ad[0..8].copy_from_slice(&MAGIC);
    ad[8] = VERSION;
    ad[PK_OFFSET..PK_OFFSET + PK_LEN].copy_from_slice(public_key);
    ad[KDF_ID_OFFSET] = KDF_ID_ARGON2ID;
    ad[ARGON2_M_COST_OFFSET..ARGON2_T_COST_OFFSET].copy_from_slice(&params.m_cost.to_be_bytes());
    ad[ARGON2_T_COST_OFFSET..ARGON2_P_COST_OFFSET].copy_from_slice(&params.t_cost.to_be_bytes());
    ad[ARGON2_P_COST_OFFSET..SALT_OFFSET].copy_from_slice(&params.p_cost.to_be_bytes());
    ad[SALT_OFFSET..AEAD_ID_OFFSET].copy_from_slice(salt);
    ad[AEAD_ID_OFFSET] = AEAD_ID_XCHACHA20POLY1305;

    // Derive the AEAD key from password via argon2id.
    let key = derive_key(password, params, salt)?;

    // Encrypt the seed with AD binding.
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ct_and_tag = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: seed.as_ref(),
                aad: &ad,
            },
        )
        .map_err(|e| FormatError::AeadEncrypt(e.to_string()))?;
    debug_assert_eq!(ct_and_tag.len(), SEED_LEN + TAG_LEN);

    // Assemble the final blob.
    let mut out = [0u8; TOTAL_LEN];
    out[0..AD_LEN].copy_from_slice(&ad);
    out[AD_LEN..AD_LEN + NONCE_LEN].copy_from_slice(nonce);
    out[AD_LEN + NONCE_LEN..].copy_from_slice(&ct_and_tag);
    Ok(out)
}

/// Decode an encrypted private key blob. Returns the 32-byte seed.
pub fn decode(blob: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, FormatError> {
    if blob.len() != TOTAL_LEN {
        return Err(FormatError::BadLength { got: blob.len() });
    }
    if blob[0..8] != MAGIC {
        return Err(FormatError::BadMagic);
    }
    if blob[8] != VERSION {
        return Err(FormatError::UnsupportedVersion(blob[8]));
    }
    if blob[KDF_ID_OFFSET] != KDF_ID_ARGON2ID {
        return Err(FormatError::UnsupportedKdf(blob[KDF_ID_OFFSET]));
    }
    let m_cost = u32::from_be_bytes(
        blob[ARGON2_M_COST_OFFSET..ARGON2_T_COST_OFFSET]
            .try_into()
            .unwrap(),
    );
    let t_cost = u32::from_be_bytes(
        blob[ARGON2_T_COST_OFFSET..ARGON2_P_COST_OFFSET]
            .try_into()
            .unwrap(),
    );
    let p_cost = u32::from_be_bytes(blob[ARGON2_P_COST_OFFSET..SALT_OFFSET].try_into().unwrap());
    // Reject zero params (invalid) and unreasonably large params (would OOM or take forever).
    if m_cost == 0
        || t_cost == 0
        || p_cost == 0
        || m_cost > MAX_M_COST
        || t_cost > MAX_T_COST
        || p_cost > MAX_P_COST
    {
        return Err(FormatError::ParamsOutOfRange(m_cost, t_cost, p_cost));
    }
    if blob[AEAD_ID_OFFSET] != AEAD_ID_XCHACHA20POLY1305 {
        return Err(FormatError::UnsupportedAead(blob[AEAD_ID_OFFSET]));
    }

    let salt: [u8; SALT_LEN] = blob[SALT_OFFSET..AEAD_ID_OFFSET].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]
        .try_into()
        .unwrap();
    let ad = &blob[0..AD_LEN];
    let ct_and_tag = &blob[AD_LEN + NONCE_LEN..];

    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    let key = derive_key(password, params, &salt)?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ct_and_tag,
                    aad: ad,
                },
            )
            .map_err(|_| FormatError::AeadDecrypt)?,
    );
    debug_assert_eq!(plaintext.len(), SEED_LEN);

    let mut seed: Zeroizing<[u8; SEED_LEN]> = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

fn derive_key(
    password: &[u8],
    params: Argon2Params,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, FormatError> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| FormatError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| FormatError::Kdf(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; SEED_LEN] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const TEST_SALT: [u8; SALT_LEN] = [0x5au8; SALT_LEN];
    const TEST_NONCE: [u8; NONCE_LEN] = [0xa5u8; NONCE_LEN];
    const TEST_PASSWORD: &[u8] = b"hunter2";

    fn test_pk() -> [u8; PK_LEN] {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(&TEST_SEED)
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn roundtrip_yields_seed() {
        let blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        let seed = decode(&blob, TEST_PASSWORD).expect("decode");
        assert_eq!(*seed, TEST_SEED);
    }

    #[test]
    fn header_fields_have_expected_values() {
        let pk = test_pk();
        let blob = encode(
            &TEST_SEED,
            &pk,
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        assert_eq!(&blob[0..8], &MAGIC);
        assert_eq!(blob[8], VERSION);
        assert_eq!(&blob[PK_OFFSET..PK_OFFSET + PK_LEN], &pk);
        assert_eq!(blob[KDF_ID_OFFSET], KDF_ID_ARGON2ID);
        assert_eq!(
            u32::from_be_bytes(
                blob[ARGON2_M_COST_OFFSET..ARGON2_T_COST_OFFSET]
                    .try_into()
                    .unwrap()
            ),
            8
        );
        assert_eq!(
            u32::from_be_bytes(
                blob[ARGON2_T_COST_OFFSET..ARGON2_P_COST_OFFSET]
                    .try_into()
                    .unwrap()
            ),
            1
        );
        assert_eq!(
            u32::from_be_bytes(blob[ARGON2_P_COST_OFFSET..SALT_OFFSET].try_into().unwrap()),
            1
        );
        assert_eq!(&blob[SALT_OFFSET..AEAD_ID_OFFSET], &TEST_SALT);
        assert_eq!(blob[AEAD_ID_OFFSET], AEAD_ID_XCHACHA20POLY1305);
        assert_eq!(&blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN], &TEST_NONCE);
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        let err = decode(&blob, b"wrong password").unwrap_err();
        assert!(matches!(err, FormatError::AeadDecrypt));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        blob[0] = b'X';
        assert!(matches!(
            decode(&blob, TEST_PASSWORD),
            Err(FormatError::BadMagic)
        ));
    }

    #[test]
    fn bad_version_rejected() {
        let mut blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        blob[8] = 2;
        assert!(matches!(
            decode(&blob, TEST_PASSWORD),
            Err(FormatError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn bad_version_zero_rejected() {
        let mut blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        blob[8] = 0;
        assert!(matches!(
            decode(&blob, TEST_PASSWORD),
            Err(FormatError::UnsupportedVersion(0))
        ));
    }

    #[test]
    fn bad_kdf_id_rejected() {
        let mut blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        blob[KDF_ID_OFFSET] = 99;
        assert!(matches!(
            decode(&blob, TEST_PASSWORD),
            Err(FormatError::UnsupportedKdf(99))
        ));
    }

    #[test]
    fn bad_aead_id_rejected() {
        let mut blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        blob[AEAD_ID_OFFSET] = 42;
        assert!(matches!(
            decode(&blob, TEST_PASSWORD),
            Err(FormatError::UnsupportedAead(42))
        ));
    }

    #[test]
    fn zero_params_rejected() {
        let mut blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        blob[ARGON2_M_COST_OFFSET..ARGON2_T_COST_OFFSET].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            decode(&blob, TEST_PASSWORD),
            Err(FormatError::ParamsOutOfRange(0, 1, 1))
        ));
    }

    #[test]
    fn tamper_sweep_ciphertext_and_tag() {
        let blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        for i in (AD_LEN + NONCE_LEN)..TOTAL_LEN {
            let mut tampered = blob;
            tampered[i] ^= 0xff;
            let err = decode(&tampered, TEST_PASSWORD).unwrap_err();
            assert!(
                matches!(err, FormatError::AeadDecrypt),
                "tamper at offset {i} should fail AEAD, got {err:?}"
            );
        }
    }

    #[test]
    fn tamper_sweep_associated_data_and_nonce() {
        let blob = encode(
            &TEST_SEED,
            &test_pk(),
            TEST_PASSWORD,
            Argon2Params::TEST,
            &TEST_SALT,
            &TEST_NONCE,
        )
        .expect("encode");
        for i in 0..(AD_LEN + NONCE_LEN) {
            let mut tampered = blob;
            tampered[i] ^= 0xff;
            assert!(
                decode(&tampered, TEST_PASSWORD).is_err(),
                "tamper at offset {i} should cause a decode error"
            );
        }
    }

    #[test]
    fn wrong_length_rejected() {
        let err = decode(&[0u8; 50], TEST_PASSWORD).unwrap_err();
        assert!(matches!(err, FormatError::BadLength { .. }));
    }

    #[test]
    fn known_answer_vector() {
        use ed25519_dalek::SigningKey;
        let seed = [0x11u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let salt = [0x22u8; SALT_LEN];
        let nonce = [0x33u8; NONCE_LEN];
        let password = b"test-password";
        let params = Argon2Params::TEST;

        let blob = encode(&seed, &pk, password, params, &salt, &nonce).unwrap();

        let expected_hex = "415346414c4f414401d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737010000000800000001000000012222222222222222222222222222222201333333333333333333333333333333333333333333333333750de95ea4b3758ce19825d5e11cf7ed184829e9a99bdee7cdb7543cc317885e294ffea47bd90e19fe76423eda126d3e";
        let actual_hex: String = blob.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(actual_hex, expected_hex);
    }
}
