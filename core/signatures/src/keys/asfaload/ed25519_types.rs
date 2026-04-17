//! Concrete ed25519 types shared between the asfaload native format and the
//! OpenSSH importer. Verification and signature bytes are format-agnostic.

use crate::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
    AsfaloadSignatureTrait, KeyFormat, asfaload::format::TOTAL_LEN,
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use common::{AsfaloadHashes, errors::keys::*};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

use super::format::{PK_LEN, PK_OFFSET, decode};

/// Prefix for asfaload-format public keys (distinct from asfaload-priv for private keys).
pub const ASFALOAD_PUB_PREFIX: &str = "asfaload-pub:";
/// Wire prefix for OpenSSH ed25519 public keys.
pub const SSH_ED25519_PREFIX: &str = "ssh-ed25519 ";

/// Encrypted ed25519 key material, regardless of on-disk format.
/// Used by `AsfaloadKeyPair<AsfaloadKeysBlob>` and `AsfaloadKeyPair<SshEncryptedKey>`
/// to share the decryption and public-key-extraction paths.
pub trait EncryptedEd25519Key {
    /// Extract the unencrypted ed25519 public key. No password required.
    fn public_key(&self) -> VerifyingKey;

    /// Decrypt the encrypted seed and return the usable signing key.
    fn decrypt(&self, password: &str) -> Result<SigningKey, KeyError>;
}

/// The asfaload-format encrypted ed25519 keypair blob. 143 bytes,
/// self-describing: magic + version + public_key + KDF params + salt +
/// AEAD params + nonce + ciphertext + tag. See `format.rs` for the layout.
#[derive(Debug, Clone)]
pub struct AsfaloadKeysBlob(pub(crate) [u8; TOTAL_LEN]);

impl EncryptedEd25519Key for AsfaloadKeysBlob {
    fn public_key(&self) -> VerifyingKey {
        // No KDF or AEAD work here: the pk bytes sit in the unencrypted-but-
        // AEAD-authenticated header and are read directly.
        let pk_bytes: [u8; PK_LEN] = self.0[PK_OFFSET..PK_OFFSET + PK_LEN]
            .try_into()
            .expect("slice of exactly PK_LEN bytes");
        VerifyingKey::from_bytes(&pk_bytes).expect(
            "AsfaloadKeysBlob invariant: pk bytes were written by format::encode with a \
             valid VerifyingKey",
        )
    }

    fn decrypt(&self, password: &str) -> Result<SigningKey, KeyError> {
        let seed = decode(&self.0, password.as_bytes())?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

/// An ed25519 public key used by the asfaload native format and the OpenSSH
/// importer. Newtype wrapper over `ed25519_dalek::VerifyingKey`.
#[derive(Debug, Clone)]
pub struct AsfaloadEd25519PublicKey(pub(crate) VerifyingKey);

/// An ed25519 secret key. Newtype wrapper over `ed25519_dalek::SigningKey`,
/// which zeroizes its buffer on drop.
/// The SigningKey is decrypted, and can be obtained from a ssh-format saved key (encrypted or not)
/// or from a asfaload-format saved key (Argon2id + XChaCha20-Poly1305).
#[derive(Debug, Clone)]
pub struct AsfaloadEd25519SecretKey(pub(crate) SigningKey);

/// An ed25519 signature. Newtype wrapper over `ed25519_dalek::Signature`.
#[derive(Debug, Clone)]
pub struct AsfaloadEd25519Signature(pub(crate) ed25519_dalek::Signature);

// --- PublicKey ---

impl PartialEq for AsfaloadEd25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}
impl Eq for AsfaloadEd25519PublicKey {}
impl std::hash::Hash for AsfaloadEd25519PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl AsfaloadPublicKeyTrait for AsfaloadEd25519PublicKey {
    type Signature = AsfaloadEd25519Signature;
    type KeyType = VerifyingKey;
    type SecretKeyType = AsfaloadEd25519SecretKey;

    fn verify(
        &self,
        signature: &Self::Signature,
        data: &AsfaloadHashes,
    ) -> Result<(), VerifyError> {
        let hash_bytes = match data {
            AsfaloadHashes::Sha512(d) => d.as_ref(),
        };
        self.0.verify(hash_bytes, &signature.0)?;
        Ok(())
    }

    fn to_base64(&self) -> String {
        format!(
            "{}{}",
            ASFALOAD_PUB_PREFIX,
            STANDARD_NO_PAD.encode(self.0.as_bytes())
        )
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| KeyError::CreationFailed("ed25519 public key must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&bytes)?;
        Ok(Self(vk))
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        // Multi-prefix detection: asfaload-pub:<b64> or ssh-ed25519 <b64> [comment]
        if let Some(rest) = s.strip_prefix(ASFALOAD_PUB_PREFIX) {
            let bytes = STANDARD_NO_PAD
                .decode(rest.trim())
                .map_err(|e| KeyError::CreationFailed(format!("base64 decode failed: {}", e)))?;
            return Self::from_bytes(&bytes);
        }
        if let Some(rest) = s.strip_prefix(SSH_ED25519_PREFIX) {
            return parse_ssh_ed25519_wire(rest.trim());
        }
        Err(KeyError::CreationFailed(format!(
            "unrecognised public-key prefix: expected '{}' or '{}', got input starting with '{}'",
            ASFALOAD_PUB_PREFIX,
            SSH_ED25519_PREFIX,
            s.chars().take(32).collect::<String>(),
        )))
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let content = fs::read_to_string(path)?.trim().to_string();
        Self::from_base64(&content)
    }

    fn from_secret_key(sk: &Self::SecretKeyType) -> Result<Self, KeyError> {
        Ok(Self(sk.0.verifying_key()))
    }

    fn key_format(&self) -> KeyFormat {
        KeyFormat::Asfaload
    }
    fn key(&self) -> VerifyingKey {
        self.0
    }

    fn to_filename(&self) -> String {
        // Only transform the base64 body; the prefix uses '-' as a literal separator
        // marker, so it must survive round-trip unchanged.
        let b64 = STANDARD_NO_PAD.encode(self.0.as_bytes());
        format!(
            "{}{}",
            ASFALOAD_PUB_PREFIX,
            b64.replace('+', "-").replace('/', "_")
        )
    }

    fn from_filename(n: String) -> Result<Self, KeyError> {
        let rest = n.strip_prefix(ASFALOAD_PUB_PREFIX).ok_or_else(|| {
            KeyError::CreationFailed(format!(
                "expected '{}' prefix on filename",
                ASFALOAD_PUB_PREFIX
            ))
        })?;
        let restored = rest.replace('-', "+").replace('_', "/");
        let full = format!("{}{}", ASFALOAD_PUB_PREFIX, restored);
        Self::from_base64(&full)
    }
}

/// Parse an OpenSSH ed25519 public-key wire line: `<base64> [comment]`.
/// The `<base64>` decodes to an SSH wire-format blob: `u32(key-type-len)`,
/// `ssh-ed25519` (11 bytes), `u32(key-len)`, then 32 key bytes.
fn parse_ssh_ed25519_wire(s: &str) -> Result<AsfaloadEd25519PublicKey, KeyError> {
    let b64 = s
        .split_whitespace()
        .next()
        .ok_or_else(|| KeyError::CreationFailed("empty ssh-ed25519 public key line".into()))?;
    // SSH public keys use standard base64 with padding.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| KeyError::CreationFailed(format!("ssh key base64 decode failed: {}", e)))?;
    const TYPE_TAG: &[u8] = b"ssh-ed25519";
    if bytes.len() < 4 + TYPE_TAG.len() + 4 + 32 {
        return Err(KeyError::CreationFailed(
            "ssh-ed25519 wire blob too short".into(),
        ));
    }
    let type_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if type_len != TYPE_TAG.len() {
        return Err(KeyError::CreationFailed("not an ssh-ed25519 key".into()));
    }
    // type_len == TYPE_TAG.len() == 11; 4 + 11 = 15, well within the 51-byte minimum verified above
    if &bytes[4..4 + type_len] != TYPE_TAG {
        return Err(KeyError::CreationFailed("not an ssh-ed25519 key".into()));
    }
    let after_type = 4 + type_len;
    // after_type + 4 + 32 <= bytes.len() guaranteed by the initial length check above
    let key_len =
        u32::from_be_bytes(bytes[after_type..after_type + 4].try_into().unwrap()) as usize;
    if key_len != 32 {
        return Err(KeyError::CreationFailed(format!(
            "ssh-ed25519 key must be 32 bytes, got {}",
            key_len
        )));
    }
    let key_bytes: [u8; 32] = bytes[after_type + 4..after_type + 4 + 32]
        .try_into()
        .unwrap();
    let vk = VerifyingKey::from_bytes(&key_bytes)?;
    Ok(AsfaloadEd25519PublicKey(vk))
}

// --- SecretKey ---

impl AsfaloadSecretKeyTrait for AsfaloadEd25519SecretKey {
    type SecretKey = SigningKey;
    type Signature = AsfaloadEd25519Signature;

    fn sign(&self, data: &AsfaloadHashes) -> Result<Self::Signature, SignError> {
        let hash_bytes = match data {
            AsfaloadHashes::Sha512(d) => d.as_ref(),
        };
        Ok(AsfaloadEd25519Signature(self.0.sign(hash_bytes)))
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| KeyError::CreationFailed("ed25519 secret key must be 32 bytes".into()))?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    /// Load an ed25519 secret key from a file of either supported format.
    /// Detects the format via `KeyFormat::from_file` and delegates decryption to
    /// the format-specific keypair type, discarding its wrapper state.
    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        match KeyFormat::from_file(&path)? {
            KeyFormat::Asfaload => {
                let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::from_file(&path)?;
                kp.secret_key(password)
            }
            KeyFormat::OpenSsh => {
                let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_file(&path)?;
                kp.secret_key(password)
            }
            KeyFormat::Minisign => Err(KeyError::CreationFailed(
                "AsfaloadEd25519SecretKey cannot load a minisign key; \
                 use AsfaloadSecretKey::<minisign::SecretKey> instead"
                    .into(),
            )),
        }
    }
}

// --- Signature ---

impl AsfaloadSignatureTrait for AsfaloadEd25519Signature {
    type PublicKeyType = AsfaloadEd25519PublicKey;

    fn to_string(&self) -> String {
        self.to_base64()
    }
    fn from_string(s: &str) -> Result<Self, SignatureError> {
        Self::from_base64(s)
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError> {
        fs::write(path, self.to_string())?;
        Ok(self)
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError> {
        let content = fs::read_to_string(path)?.trim().to_string();
        Self::from_base64(&content)
    }

    fn from_base64(s: &str) -> Result<Self, SignatureError> {
        let bytes = STANDARD_NO_PAD.decode(s.trim())?;
        let sig_bytes: [u8; 64] = bytes.try_into().map_err(|_| {
            SignatureError::FormatError("ed25519 signature must be 64 bytes".into())
        })?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(&sig_bytes)))
    }

    fn to_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.0.to_bytes())
    }
}

/// Extract the `nkeys` field from an openssh-key-v1 PEM without relying on
/// the full ssh-key parser. Returns the count if recognisable, else errors.
///
/// openssh-key-v1 wire layout:
///   "openssh-key-v1\0" (15 bytes + NUL = 16 bytes)
///   string cipher, string kdf, string kdfopts  (each length-prefixed)
///   u32 nkeys
///   ...
fn count_keys_in_openssh_pem(pem: &str) -> Result<u32, KeyError> {
    // Collect the base64 body between the BEGIN/END markers, stripping any
    // in-line whitespace (stray spaces, tabs, or leftover CR). The strict
    // STANDARD base64 engine rejects whitespace inside the input, so we do
    // not rely on input formatting being perfectly canonical.
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| KeyError::CreationFailed(format!("pem body not valid base64: {}", e)))?;
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
        return Err(KeyError::CreationFailed("not an openssh-key-v1 PEM".into()));
    }
    let mut cursor = MAGIC.len();
    // Skip three length-prefixed strings: cipher, kdf, kdfopts.
    for _ in 0..3 {
        if cursor + 4 > bytes.len() {
            return Err(KeyError::CreationFailed("openssh-key-v1 truncated".into()));
        }
        let len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor.saturating_add(len) > bytes.len() {
            return Err(KeyError::CreationFailed("openssh-key-v1 truncated".into()));
        }
        cursor += len;
    }
    if cursor + 4 > bytes.len() {
        return Err(KeyError::CreationFailed(
            "openssh-key-v1 nkeys field missing".into(),
        ));
    }
    Ok(u32::from_be_bytes(
        bytes[cursor..cursor + 4].try_into().unwrap(),
    ))
}

/// An encrypted ed25519 keypair read from an openssh-key-v1 PEM file.
/// The PEM bytes are stored verbatim so the user's bcrypt-pbkdf parameters,
/// cipher choice, and passphrase are never transformed.
#[derive(Debug, Clone)]
pub struct SshEncryptedKey {
    pem: String,
    public_key: VerifyingKey,
}

impl SshEncryptedKey {
    /// Parse an openssh-key-v1 PEM, extract the ed25519 public key from the
    /// unencrypted header, and store the raw PEM for later `decrypt(pw)`.
    /// Rejects non-ed25519 keys and multi-key files.
    pub fn from_pem(pem: impl Into<String>) -> Result<Self, KeyError> {
        let pem = pem.into();

        let count = count_keys_in_openssh_pem(&pem)?;
        if count != 1 {
            return Err(KeyError::CreationFailed(format!(
                "multi-key OpenSSH files are not supported (found {count} keys)"
            )));
        }

        let parsed = ssh_key::PrivateKey::from_openssh(&pem)
            .map_err(|e| KeyError::CreationFailed(format!("openssh-key-v1 parse failed: {e}")))?;

        // Extract the ed25519 public key from the unencrypted header.
        // The openssh-key-v1 format stores the public key in cleartext even
        // for encrypted private keys, so no password is required here.
        let public_key = match parsed.public_key().key_data() {
            ssh_key::public::KeyData::Ed25519(pk) => VerifyingKey::from_bytes(&pk.0)
                .map_err(|e| KeyError::CreationFailed(format!("ed25519 pk invalid: {e}")))?,
            _ => {
                return Err(KeyError::CreationFailed(
                    "OpenSSH key is not ed25519".into(),
                ));
            }
        };

        Ok(SshEncryptedKey { pem, public_key })
    }
}

impl EncryptedEd25519Key for SshEncryptedKey {
    fn public_key(&self) -> VerifyingKey {
        self.public_key
    }

    fn decrypt(&self, password: &str) -> Result<SigningKey, KeyError> {
        let mut private = ssh_key::PrivateKey::from_openssh(&self.pem).map_err(|e| {
            KeyError::CreationFailed(format!("openssh-key-v1 re-parse failed: {e}"))
        })?;
        if private.is_encrypted() {
            private = private
                .decrypt(password.as_bytes())
                .map_err(|e| KeyError::CreationFailed(format!("ssh key decryption failed: {e}")))?;
        }
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(match private.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => kp.private.to_bytes(),
            _ => {
                return Err(KeyError::CreationFailed(
                    "decrypted ssh key is not ed25519".into(),
                ));
            }
        });
        Ok(SigningKey::from_bytes(&seed))
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::asfaload::format::{self, Argon2Params, NONCE_LEN, SALT_LEN};

    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn random_keypair() -> (AsfaloadEd25519PublicKey, AsfaloadEd25519SecretKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        (AsfaloadEd25519PublicKey(pk), AsfaloadEd25519SecretKey(sk))
    }

    #[test]
    fn public_key_base64_roundtrip() {
        let (pk, _) = random_keypair();
        let s = pk.to_base64();
        assert!(s.starts_with(ASFALOAD_PUB_PREFIX));
        let pk2 = AsfaloadEd25519PublicKey::from_base64(&s).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_from_base64_rejects_padding() {
        let (pk, _) = random_keypair();
        let body = base64::engine::general_purpose::STANDARD.encode(pk.0.as_bytes());
        let padded = format!("{}{}", ASFALOAD_PUB_PREFIX, body);
        assert!(AsfaloadEd25519PublicKey::from_base64(&padded).is_err());
    }

    #[test]
    fn public_key_from_ssh_ed25519_wire() {
        let (pk, _) = random_keypair();
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(pk.0.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let ssh_line = format!("ssh-ed25519 {} user@host", b64);
        let parsed = AsfaloadEd25519PublicKey::from_base64(&ssh_line).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn public_key_rejects_unknown_prefix() {
        let err = AsfaloadEd25519PublicKey::from_base64("ed25519:somebase64").unwrap_err();
        match err {
            KeyError::CreationFailed(_) => {}
            other => panic!("expected CreationFailed, got {other:?}"),
        }
    }

    #[test]
    fn sign_and_verify() {
        let (pk, sk) = random_keypair();
        let data = common::sha512_for_content(b"hello".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        pk.verify(&sig, &data).unwrap();
    }

    #[test]
    fn signature_base64_roundtrip() {
        let (_, sk) = random_keypair();
        let data = common::sha512_for_content(b"payload".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        let s = sig.to_base64();
        assert!(!s.contains('='), "unpadded base64 expected, got {s}");
        let sig2 = AsfaloadEd25519Signature::from_base64(&s).unwrap();
        assert_eq!(sig.0.to_bytes(), sig2.0.to_bytes());
    }

    #[test]
    fn signature_from_base64_rejects_padding() {
        let (_, sk) = random_keypair();
        let data = common::sha512_for_content(b"x".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        let padded = base64::engine::general_purpose::STANDARD.encode(sig.0.to_bytes());
        assert!(AsfaloadEd25519Signature::from_base64(&padded).is_err());
    }

    #[test]
    fn public_key_from_secret_key_matches() {
        let (pk, sk) = random_keypair();
        let derived = AsfaloadEd25519PublicKey::from_secret_key(&sk).unwrap();
        assert_eq!(pk, derived);
    }

    #[test]
    fn public_key_filename_roundtrip() {
        let (pk, _) = random_keypair();
        let name = pk.to_filename();
        assert!(name.starts_with(ASFALOAD_PUB_PREFIX));
        // No '+' or '/' in the filename (these are forbidden in paths on some OSes)
        assert!(!name.contains('+'));
        assert!(!name.contains('/'));
        // Round-trip back
        let pk2 = AsfaloadEd25519PublicKey::from_filename(name).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn asfaload_keys_blob_public_key_matches_seed() {
        use rand::RngCore;

        let sk = SigningKey::generate(&mut OsRng);
        let seed = sk.to_bytes();
        let expected_pk = sk.verifying_key();

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let bytes = format::encode(
            &seed,
            expected_pk.as_bytes(),
            b"pw",
            Argon2Params::TEST,
            &salt,
            &nonce,
        )
        .unwrap();
        let blob = AsfaloadKeysBlob(bytes);

        assert_eq!(blob.public_key(), expected_pk);
    }

    #[test]
    fn asfaload_keys_blob_decrypt_returns_original_seed() {
        use rand::RngCore;

        let sk = SigningKey::generate(&mut OsRng);
        let seed = sk.to_bytes();
        let pk = sk.verifying_key();

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let bytes = format::encode(
            &seed,
            pk.as_bytes(),
            b"correct-pw",
            Argon2Params::TEST,
            &salt,
            &nonce,
        )
        .unwrap();
        let blob = AsfaloadKeysBlob(bytes);

        let recovered = blob.decrypt("correct-pw").unwrap();
        assert_eq!(recovered.to_bytes(), seed);
    }

    #[test]
    fn asfaload_keys_blob_decrypt_fails_on_wrong_password() {
        use common::errors::keys::KeyError;
        use rand::RngCore;

        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let bytes = format::encode(
            &sk.to_bytes(),
            pk.as_bytes(),
            b"right",
            Argon2Params::TEST,
            &salt,
            &nonce,
        )
        .unwrap();
        let blob = AsfaloadKeysBlob(bytes);

        match blob.decrypt("wrong") {
            Err(KeyError::AsfaloadFormat(_)) => {}
            Err(other) => panic!("expected AsfaloadFormat error, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn ssh_encrypted_key_public_key_parity() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use ssh_key::LineEnding;
        use ssh_key::private::{Ed25519Keypair, KeypairData};

        let sk = SigningKey::generate(&mut OsRng);
        let expected_pk = sk.verifying_key();
        let seed = sk.to_bytes();
        let ssh_ed = Ed25519Keypair::from_seed(&seed);
        let private = ssh_key::PrivateKey::new(KeypairData::Ed25519(ssh_ed), "test")
            .expect("PrivateKey::new");

        // Unencrypted roundtrip.
        let pem_plain = private.to_openssh(LineEnding::LF).unwrap().to_string();
        let plain = SshEncryptedKey::from_pem(pem_plain).unwrap();
        assert_eq!(plain.public_key(), expected_pk);

        // Encrypted roundtrip.
        let encrypted = private.encrypt(&mut OsRng, b"pw").expect("encrypt");
        let pem_enc = encrypted.to_openssh(LineEnding::LF).unwrap().to_string();
        let enc = SshEncryptedKey::from_pem(pem_enc).unwrap();
        assert_eq!(enc.public_key(), expected_pk);
    }

    #[test]
    fn ssh_encrypted_key_decrypt_happy_and_wrong() {
        use common::errors::keys::KeyError;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use ssh_key::LineEnding;
        use ssh_key::private::{Ed25519Keypair, KeypairData};

        let sk = SigningKey::generate(&mut OsRng);
        let seed = sk.to_bytes();
        let ssh_ed = Ed25519Keypair::from_seed(&seed);
        let private = ssh_key::PrivateKey::new(KeypairData::Ed25519(ssh_ed), "test")
            .expect("PrivateKey::new");
        let encrypted = private.encrypt(&mut OsRng, b"right").expect("encrypt");
        let pem = encrypted.to_openssh(LineEnding::LF).unwrap().to_string();
        let key = SshEncryptedKey::from_pem(pem).unwrap();

        let recovered = key.decrypt("right").unwrap();
        assert_eq!(recovered.to_bytes(), seed);

        match key.decrypt("wrong") {
            Err(KeyError::CreationFailed(msg)) => {
                assert!(msg.contains("decryption") || msg.contains("password"));
            }
            Err(other) => panic!("expected CreationFailed, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn ssh_encrypted_key_rejects_non_ed25519() {
        let pem_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ssh/rsa_key");
        let pem =
            std::fs::read_to_string(&pem_path).expect("fixture tests/fixtures/ssh/rsa_key missing");

        match SshEncryptedKey::from_pem(pem) {
            Err(common::errors::keys::KeyError::CreationFailed(msg)) => {
                assert!(msg.contains("not ed25519"), "got: {msg}");
            }
            Err(other) => panic!("expected CreationFailed, got {other:?}"),
            Ok(_) => panic!("expected rejection"),
        }
    }
}
