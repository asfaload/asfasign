//! AsfaloadKeyPair impls for asfaload-blob and SSH-encrypted ed25519 keys.

use super::ed25519_types::{
    AsfaloadEd25519PublicKey, AsfaloadEd25519SecretKey, AsfaloadKeysBlob, EncryptedEd25519Key,
    SshEncryptedKey,
};
// EncryptedEd25519Key is imported for trait method resolution: self.key_pair.decrypt() and
// self.key_pair.public_key() both require it in scope. Removing it breaks compilation
// despite no textual reference to the name in the file body.
use super::format::{self, Argon2Params};
use crate::keys::{AsfaloadKeyPair, AsfaloadKeyPairTrait, resolve_save_paths};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use common::errors::keys::KeyError;
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// Prefix used in private-key files.
pub const ASFALOAD_PRIV_PREFIX: &str = "asfaload-priv:";

impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPair<AsfaloadKeysBlob> {
    type PublicKey = AsfaloadEd25519PublicKey;
    type SecretKey = AsfaloadEd25519SecretKey;

    fn new(password: &str) -> Result<Self, KeyError> {
        Self::new_with_argon2_params_inner(password, Argon2Params::PRODUCTION)
    }

    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, KeyError> {
        let (sk_path, pk_path) = resolve_save_paths(&p)?;

        let body = STANDARD_NO_PAD.encode(self.key_pair.0);
        let sk_line = format!("{}{}", ASFALOAD_PRIV_PREFIX, body);
        fs::write(&sk_path, sk_line)?;

        let pk = self.public_key();
        use crate::keys::AsfaloadPublicKeyTrait;
        fs::write(&pk_path, pk.to_base64())?;

        Ok(self)
    }

    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError> {
        Ok(self.key_pair.decrypt(password)?.into())
    }

    fn public_key(&self) -> Self::PublicKey {
        self.key_pair.public_key().into()
    }
}

impl AsfaloadKeyPair<AsfaloadKeysBlob> {
    /// Generate + encrypt with the supplied Argon2id parameters.
    /// Shared implementation for `new` (PRODUCTION) and the test-utils-gated
    /// `new_with_argon2_params`.
    fn new_with_argon2_params_inner(
        password: &str,
        params: Argon2Params,
    ) -> Result<Self, KeyError> {
        // signing_key is zeroized on drop via ed25519-dalek's zeroize feature (enabled in Cargo.toml).
        let signing_key = SigningKey::generate(&mut OsRng);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
        let pk_bytes = signing_key.verifying_key().to_bytes();

        let mut salt = [0u8; format::SALT_LEN];
        let mut nonce = [0u8; format::NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let bytes = format::encode(&seed, &pk_bytes, password.as_bytes(), params, &salt, &nonce)?;

        Ok(AsfaloadKeyPair {
            key_pair: AsfaloadKeysBlob(bytes),
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_with_argon2_params(password: &str, params: Argon2Params) -> Result<Self, KeyError> {
        Self::new_with_argon2_params_inner(password, params)
    }

    /// Parse an `asfaload-priv:<base64>` string into a keypair.
    /// No password is required at load time; decryption happens later in
    /// `secret_key(pw)`. Wrong passwords are caught then.
    pub fn from_string(s: &str) -> Result<Self, KeyError> {
        let trimmed = s.trim();
        let body = trimmed.strip_prefix(ASFALOAD_PRIV_PREFIX).ok_or_else(|| {
            KeyError::CreationFailed(format!(
                "not an asfaload private key (missing '{ASFALOAD_PRIV_PREFIX}' prefix)"
            ))
        })?;
        let blob_vec = STANDARD_NO_PAD
            .decode(body.trim())
            .map_err(|e| KeyError::CreationFailed(format!("base64 decode failed: {e}")))?;
        let bytes: [u8; format::TOTAL_LEN] = blob_vec.as_slice().try_into().map_err(|_| {
            KeyError::CreationFailed(format!(
                "asfaload-priv blob must be {} bytes, got {}",
                format::TOTAL_LEN,
                blob_vec.len()
            ))
        })?;
        Ok(AsfaloadKeyPair {
            key_pair: AsfaloadKeysBlob(bytes),
        })
    }

    /// Read an `asfaload-priv:<base64>` file and parse it. Default impl for
    /// the file-loading path; delegates to `from_string`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let content = fs::read_to_string(path.as_ref())?;
        Self::from_string(&content)
    }
}

impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPair<SshEncryptedKey> {
    type PublicKey = AsfaloadEd25519PublicKey;
    type SecretKey = AsfaloadEd25519SecretKey;

    fn new(_password: &str) -> Result<Self, KeyError> {
        Err(KeyError::CreationFailed(
            "cannot generate an openssh-format keypair; asfaload is read-only for SSH".into(),
        ))
    }

    fn save<T: AsRef<Path>>(&self, _p: T) -> Result<&Self, KeyError> {
        Err(KeyError::CreationFailed(
            "cannot save an openssh-format keypair; asfaload does not write SSH format".into(),
        ))
    }

    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError> {
        Ok(self.key_pair.decrypt(password)?.into())
    }

    fn public_key(&self) -> Self::PublicKey {
        self.key_pair.public_key().into()
    }
}

impl AsfaloadKeyPair<SshEncryptedKey> {
    /// Parse an openssh-key-v1 PEM string into a keypair.
    /// No password is required at load time; decryption happens later in
    /// `secret_key(pw)`. Wrong passwords are caught then.
    pub fn from_string(s: &str) -> Result<Self, KeyError> {
        let inner = SshEncryptedKey::from_pem(s)?;
        Ok(AsfaloadKeyPair { key_pair: inner })
    }

    /// Read an openssh-key-v1 PEM file and parse it. Delegates to `from_string`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let pem = fs::read_to_string(path.as_ref())?;
        Self::from_string(&pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_asfaload_keypair_roundtrip() {
        use crate::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait};
        use common::sha512_for_content;

        let kp =
            AsfaloadKeyPair::<AsfaloadKeysBlob>::new_with_argon2_params("pw", Argon2Params::TEST)
                .unwrap();
        let pk = kp.public_key();
        let sk = kp.secret_key("pw").unwrap();

        let data = sha512_for_content(b"payload".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        pk.verify(&sig, &data).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mykey");
        kp.save(&key_path).unwrap();
        let loaded = AsfaloadKeyPair::<AsfaloadKeysBlob>::from_file(&key_path).unwrap();
        assert_eq!(loaded.public_key(), pk);
        let sk2 = loaded.secret_key("pw").unwrap();
        let sig2 = sk2.sign(&data).unwrap();
        pk.verify(&sig2, &data).unwrap();
    }

    #[test]
    fn generic_ssh_keypair_roundtrip() {
        use crate::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait};
        use common::sha512_for_content;
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
        let encrypted = private.encrypt(&mut OsRng, b"pw").expect("encrypt");
        let pem = encrypted.to_openssh(LineEnding::LF).unwrap().to_string();

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("id_ed25519");
        std::fs::write(&path, &pem).unwrap();

        let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_file(&path).unwrap();
        assert_eq!(kp.public_key().key, expected_pk);

        let loaded_sk = kp.secret_key("pw").unwrap();
        let data = sha512_for_content(b"payload".to_vec()).unwrap();
        let sig = loaded_sk.sign(&data).unwrap();

        let pk = kp.public_key();
        pk.verify(&sig, &data).unwrap();
    }

    #[test]
    fn generic_ssh_keypair_save_refuses() {
        use crate::keys::AsfaloadKeyPairTrait;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use ssh_key::LineEnding;
        use ssh_key::private::{Ed25519Keypair, KeypairData};

        let sk = SigningKey::generate(&mut OsRng);
        let ssh_ed = Ed25519Keypair::from_seed(&sk.to_bytes());
        let private = ssh_key::PrivateKey::new(KeypairData::Ed25519(ssh_ed), "test").unwrap();
        let encrypted = private.encrypt(&mut OsRng, b"pw").unwrap();
        let pem = encrypted.to_openssh(LineEnding::LF).unwrap().to_string();

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("id_ed25519");
        std::fs::write(&path, &pem).unwrap();

        let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_file(&path).unwrap();
        let err = kp.save(tmp.path().join("copy")).unwrap_err();
        match err {
            KeyError::CreationFailed(msg) => {
                assert!(msg.contains("openssh") || msg.contains("SSH"));
            }
            other => panic!("expected CreationFailed, got {other:?}"),
        }
    }
}
