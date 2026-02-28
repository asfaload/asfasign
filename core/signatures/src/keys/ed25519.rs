use crate::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKey, AsfaloadPublicKeyTrait,
    AsfaloadSecretKey, AsfaloadSecretKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
    KeyFormat, append_pub_extension,
};
use crate::signatures_file::{SignaturesFile, TaggedSignature};
use base64::{Engine, prelude::BASE64_STANDARD};
use common::{
    AsfaloadHashes,
    errors::keys::*,
    fs::names::{pending_signatures_path_for, revocation_path_for, signatures_path_for},
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::der::pem::PemLabel;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncryptedPrivateKeyInfo};
use std::fs::{self, File};
use std::path::Path;

/// Wrapper holding the signing key and its encrypted PKCS#8 PEM for storage.
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
    encrypted_pem: String,
}

pub type Ed25519PublicKey = VerifyingKey;
pub type Ed25519SecretKey = SigningKey;
pub type Ed25519Signature = ed25519_dalek::Signature;

/// Scrypt log_n for production ed25519 key encryption.
const SCRYPT_LOG_N: u8 = 15;

/// Encrypt a signing key to PKCS#8 PEM with custom scrypt parameters.
fn encrypt_signing_key(
    signing_key: &SigningKey,
    password: &str,
    scrypt_log_n: u8,
) -> Result<String, KeyError> {
    let der = signing_key
        .to_pkcs8_der()
        .map_err(|e| KeyError::CreationFailed(format!("PKCS#8 DER encoding failed: {}", e)))?;

    let pki = pkcs8::PrivateKeyInfo::try_from(der.as_bytes())
        .map_err(|e| KeyError::CreationFailed(format!("PKCS#8 parsing failed: {}", e)))?;

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);

    let scrypt_params = scrypt::Params::new(scrypt_log_n, 8, 1, 32)
        .map_err(|e| KeyError::CreationFailed(format!("Invalid scrypt params: {}", e)))?;
    let pbes2_params = pkcs8::pkcs5::pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv)
        .map_err(|e| KeyError::CreationFailed(format!("PBES2 params failed: {}", e)))?;

    let encrypted_doc = pki
        .encrypt_with_params(pbes2_params, password.as_bytes())
        .map_err(|e| KeyError::CreationFailed(format!("PKCS#8 encryption failed: {}", e)))?;

    let pem = encrypted_doc
        .to_pem(EncryptedPrivateKeyInfo::PEM_LABEL, pkcs8::LineEnding::LF)
        .map_err(|e| KeyError::CreationFailed(format!("PEM encoding failed: {}", e)))?;

    Ok(pem.to_string())
}

// --- KeyPair ---

impl AsfaloadKeyPair<Ed25519KeyPair> {
    /// Create a new ed25519 keypair with custom scrypt cost for key encryption.
    pub fn new_with_scrypt_log_n(password: &str, scrypt_log_n: u8) -> Result<Self, KeyError> {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let encrypted_pem = encrypt_signing_key(&signing_key, password, scrypt_log_n)?;
        Ok(AsfaloadKeyPair {
            key_pair: Ed25519KeyPair {
                signing_key,
                encrypted_pem,
            },
        })
    }
}

impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPair<Ed25519KeyPair> {
    type PublicKey = AsfaloadPublicKey<Ed25519PublicKey>;
    type SecretKey = AsfaloadSecretKey<Ed25519SecretKey>;

    fn new(password: &str) -> Result<Self, KeyError> {
        Self::new_with_scrypt_log_n(password, SCRYPT_LOG_N)
    }

    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, KeyError> {
        let path = p.as_ref();

        let (sk_path, pk_path) = if path.is_dir() {
            let sk = path.join("key");
            let pk = path.join("key.pub");
            (sk, pk)
        } else {
            (path.to_path_buf(), append_pub_extension(&path))
        };

        if sk_path.exists() || pk_path.exists() {
            return Err(KeyError::NotOverwriting(
                "Refusing to write key to existing file!".to_string(),
            ));
        }

        // Write encrypted PKCS#8 PEM secret key
        fs::write(&sk_path, &self.key_pair.encrypted_pem)?;

        // Write public key as plain base64
        let pk_b64 = BASE64_STANDARD.encode(self.key_pair.signing_key.verifying_key().as_bytes());
        fs::write(&pk_path, &pk_b64)?;

        Ok(self)
    }

    fn public_key(&self) -> Self::PublicKey {
        AsfaloadPublicKey {
            key: self.key_pair.signing_key.verifying_key(),
        }
    }

    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError> {
        let signing_key =
            SigningKey::from_pkcs8_encrypted_pem(&self.key_pair.encrypted_pem, password.as_bytes())
                .map_err(|e| {
                    KeyError::CreationFailed(format!("PKCS#8 decryption failed: {}", e))
                })?;

        Ok(AsfaloadSecretKey { key: signing_key })
    }
}

// --- SecretKey ---

impl AsfaloadSecretKeyTrait for AsfaloadSecretKey<Ed25519SecretKey> {
    type SecretKey = Ed25519SecretKey;
    type Signature = AsfaloadSignature<Ed25519Signature>;

    fn sign(&self, data: &AsfaloadHashes) -> Result<Self::Signature, SignError> {
        let hash_bytes = match data {
            AsfaloadHashes::Sha512(data) => data.as_ref(),
        };
        let sig = self.key.sign(hash_bytes);
        Ok(AsfaloadSignature { signature: sig })
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| KeyError::CreationFailed("Ed25519 secret key must be 32 bytes".into()))?;
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(AsfaloadSecretKey { key: signing_key })
    }

    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        let pem_content = fs::read_to_string(path)?;
        let signing_key = SigningKey::from_pkcs8_encrypted_pem(&pem_content, password.as_bytes())
            .map_err(|e| {
            KeyError::CreationFailed(format!("PKCS#8 decryption failed: {}", e))
        })?;
        Ok(AsfaloadSecretKey { key: signing_key })
    }
}

// --- PublicKey ---

impl AsfaloadPublicKeyTrait for AsfaloadPublicKey<Ed25519PublicKey> {
    type Signature = AsfaloadSignature<Ed25519Signature>;
    type KeyType = Ed25519PublicKey;
    type SecretKeyType = AsfaloadSecretKey<Ed25519SecretKey>;

    fn verify(
        &self,
        signature: &Self::Signature,
        data: &AsfaloadHashes,
    ) -> Result<(), VerifyError> {
        let hash_bytes = match data {
            AsfaloadHashes::Sha512(data) => data.as_ref(),
        };
        self.key.verify(hash_bytes, &signature.signature)?;
        Ok(())
    }

    fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.key.as_bytes())
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = data
            .try_into()
            .map_err(|_| KeyError::CreationFailed("Ed25519 public key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)?;
        Ok(AsfaloadPublicKey { key: verifying_key })
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        let bytes = BASE64_STANDARD
            .decode(s)
            .map_err(|e| KeyError::CreationFailed(format!("Base64 decode failed: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let content = fs::read_to_string(path)?.trim().to_string();
        Self::from_base64(&content)
    }

    fn from_secret_key(sk: &Self::SecretKeyType) -> Result<Self, KeyError> {
        Ok(AsfaloadPublicKey {
            key: sk.key.verifying_key(),
        })
    }

    fn key_format(&self) -> KeyFormat {
        KeyFormat::Ed25519
    }

    fn key(&self) -> Ed25519PublicKey {
        self.key
    }
}

impl PartialEq for AsfaloadPublicKey<Ed25519PublicKey> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for AsfaloadPublicKey<Ed25519PublicKey> {}

impl std::hash::Hash for AsfaloadPublicKey<Ed25519PublicKey> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.as_bytes().hash(state);
    }
}

// --- Signature ---

impl AsfaloadSignatureTrait for AsfaloadSignature<Ed25519Signature> {
    type PublicKeyType = AsfaloadPublicKey<Ed25519PublicKey>;

    fn to_string(&self) -> String {
        BASE64_STANDARD.encode(self.signature.to_bytes())
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
        let bytes = BASE64_STANDARD.decode(s)?;
        let sig_bytes: [u8; 64] = bytes.try_into().map_err(|_| {
            SignatureError::FormatError("Ed25519 signature must be 64 bytes".into())
        })?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        Ok(AsfaloadSignature { signature })
    }

    fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.signature.to_bytes())
    }

    fn add_to_aggregate_for_file<P: AsRef<Path>>(
        &self,
        signed_file: P,
        pub_key: &Self::PublicKeyType,
    ) -> Result<(), SignatureError> {
        if signed_file.as_ref().is_dir() {
            return Err(SignatureError::IoError(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "Requires a file, cannot sign a directory",
            )));
        }
        let signed_file_path = signed_file.as_ref();
        let signatures_path = signatures_path_for(signed_file_path)?;

        if signatures_path.exists() && signatures_path.is_file() {
            return Err(SignatureError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Aggregate signature is already complete",
            )));
        }

        let revocation_path = revocation_path_for(signed_file_path)?;
        if revocation_path.exists() && revocation_path.is_file() {
            return Err(SignatureError::FileRevoked(signed_file_path.to_path_buf()));
        }

        let pending_sig_file_path = pending_signatures_path_for(signed_file_path)?;

        let mut sig_file: SignaturesFile = match File::open(&pending_sig_file_path) {
            Ok(file) => serde_json::from_reader(file)?,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => SignaturesFile::new(),
            Err(e) => return Err(e.into()),
        };

        let signed_data = common::sha512_for_file(signed_file_path)?;
        if pub_key.verify(self, &signed_data).is_ok() {
            let pubkey_b64 = format!("ed25519:{}", pub_key.to_base64());
            if sig_file.entries.contains_key(&pubkey_b64) {
                return Err(SignatureError::DuplicateSignature);
            }
            sig_file.entries.insert(
                pubkey_b64,
                TaggedSignature {
                    format: KeyFormat::Ed25519,
                    signature: self.to_base64(),
                },
            );

            let file = File::create(&pending_sig_file_path)?;
            serde_json::to_writer_pretty(file, &sig_file)?;

            Ok(())
        } else {
            Err(SignatureError::InvalidSignatureForAggregate(
                signed_file_path.to_path_buf(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::sha512_for_content;

    fn get_key_pair() -> Result<
        (
            AsfaloadPublicKey<Ed25519PublicKey>,
            AsfaloadSecretKey<Ed25519SecretKey>,
        ),
        KeyError,
    > {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("testpass")?;
        Ok((kp.public_key(), kp.secret_key("testpass")?))
    }

    #[test]
    fn test_keypair_generation_and_save() {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("testpass").unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        kp.save(&temp_dir).unwrap();
        assert!(temp_dir.path().join("key").exists());
        assert!(temp_dir.path().join("key.pub").exists());
    }

    #[test]
    fn test_sign_and_verify() {
        let (pk, sk) = get_key_pair().unwrap();
        let data = sha512_for_content(b"test data".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        pk.verify(&sig, &data).unwrap();
    }

    #[test]
    fn test_public_key_base64_roundtrip() {
        let (pk, _sk) = get_key_pair().unwrap();
        let b64 = pk.to_base64();
        let pk2 = AsfaloadPublicKey::<Ed25519PublicKey>::from_base64(&b64).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_signature_base64_roundtrip() {
        let (_pk, sk) = get_key_pair().unwrap();
        let data = sha512_for_content(b"test".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        let b64 = sig.to_base64();
        let sig2 = AsfaloadSignature::<Ed25519Signature>::from_base64(&b64).unwrap();
        assert_eq!(sig.signature, sig2.signature);
    }

    #[test]
    fn test_key_file_roundtrip() {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("mypass").unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("mykey");
        kp.save(&key_path).unwrap();

        let sk = AsfaloadSecretKey::<Ed25519SecretKey>::from_file(&key_path, "mypass").unwrap();
        let pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_file(append_pub_extension(&key_path))
            .unwrap();

        let data = sha512_for_content(b"roundtrip".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();
        pk.verify(&sig, &data).unwrap();
    }

    #[test]
    fn test_public_key_from_secret_key() {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("pass").unwrap();
        let pk = kp.public_key();
        let sk = kp.secret_key("pass").unwrap();
        let derived_pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_secret_key(&sk).unwrap();
        assert_eq!(pk.to_base64(), derived_pk.to_base64());
    }

    #[test]
    fn test_key_format() {
        let (pk, _) = get_key_pair().unwrap();
        assert_eq!(pk.key_format(), KeyFormat::Ed25519);
    }

    #[test]
    fn test_wrong_password_fails() {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("correct").unwrap();
        let result = kp.secret_key("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_save_refuses_overwrite() {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("pass").unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        kp.save(&temp_dir).unwrap();
        let kp2 = AsfaloadKeyPair::<Ed25519KeyPair>::new("pass").unwrap();
        let result = kp2.save(&temp_dir);
        assert!(matches!(result, Err(KeyError::NotOverwriting(_))));
    }

    #[test]
    fn test_signature_file_roundtrip() {
        let (pk, sk) = get_key_pair().unwrap();
        let data = sha512_for_content(b"file test".to_vec()).unwrap();
        let sig = sk.sign(&data).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let sig_path = temp_dir.path().join("sig");
        sig.to_file(&sig_path).unwrap();

        let sig_from_file = AsfaloadSignature::<Ed25519Signature>::from_file(&sig_path).unwrap();
        pk.verify(&sig_from_file, &data).unwrap();
    }

    #[test]
    fn test_save_to_named_file() {
        let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new("pass").unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("mykey");
        kp.save(&key_path).unwrap();
        assert!(temp_dir.path().join("mykey").exists());
        assert!(temp_dir.path().join("mykey.pub").exists());
    }
}
