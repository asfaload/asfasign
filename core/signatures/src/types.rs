// We defined here enum types implementing the Asfaload traits allowing to support mulitple signing
// algorithms. We have one enum per crypo element (public key, secret key, signature, keypair) and
// each enum hase one case per algorithm we support.
// These enum simply wrap the corresponding Asfaload type (eg AsfaloadPublicKey<_>), setting its
// generic type, and implement the same traits, delegating the action of the trait's functions to
// the wrapped value. For example, AsfaloadPublicKeys has one case Minisign which wrap
// AsfaloadPublicKey<minisign::PublicKey>. It implements AsfaloadPublicKeyTrait.

use crate::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKey, AsfaloadPublicKeyTrait,
    AsfaloadSecretKey, AsfaloadSecretKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
    KeyFormat,
    ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature},
};
use common::{
    AsfaloadHashes,
    errors::keys::{KeyError, SignError, SignatureError, VerifyError},
};
use std::path::Path;
use std::str::FromStr;

#[cfg(test)]
mod tests;

pub enum AsfaloadKeyPairs {
    Minisign(AsfaloadKeyPair<minisign::KeyPair>),
    Ed25519(AsfaloadKeyPair<Ed25519KeyPair>),
}

impl AsfaloadKeyPairs {
    pub fn new_with_format(pw: &str, format: &KeyFormat) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Minisign => {
                let kp = AsfaloadKeyPair::<minisign::KeyPair>::new(pw)?;
                Ok(Self::Minisign(kp))
            }
            KeyFormat::Ed25519 => {
                let kp = AsfaloadKeyPair::<Ed25519KeyPair>::new(pw)?;
                Ok(Self::Ed25519(kp))
            }
        }
    }

    /// Generate keypair with custom scrypt cost (ed25519 only, ignored for minisign).
    pub fn new_with_format_and_scrypt_log_n(
        pw: &str,
        format: &KeyFormat,
        scrypt_log_n: u8,
    ) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Minisign => {
                let kp = AsfaloadKeyPair::<minisign::KeyPair>::new(pw)?;
                Ok(Self::Minisign(kp))
            }
            KeyFormat::Ed25519 => {
                let kp =
                    AsfaloadKeyPair::<Ed25519KeyPair>::new_with_scrypt_log_n(pw, scrypt_log_n)?;
                Ok(Self::Ed25519(kp))
            }
        }
    }
}

impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPairs {
    type PublicKey = AsfaloadPublicKeys;
    type SecretKey = AsfaloadSecretKeys;
    fn new(pw: &str) -> Result<Self, KeyError> {
        // Default to Minisign for backward compatibility.
        // Use new_with_format() for explicit algorithm selection.
        let minisign_key = AsfaloadKeyPair::<minisign::KeyPair>::new(pw)?;
        Ok(Self::Minisign(minisign_key))
    }
    fn save<T: AsRef<std::path::Path>>(&self, p: T) -> Result<&Self, KeyError> {
        match self {
            Self::Minisign(kp) => {
                kp.save(p)?;
            }
            Self::Ed25519(kp) => {
                kp.save(p)?;
            }
        };
        Ok(self)
    }

    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError> {
        match self {
            Self::Minisign(kp) => Ok(AsfaloadSecretKeys::Minisign(kp.secret_key(password)?)),
            Self::Ed25519(kp) => Ok(AsfaloadSecretKeys::Ed25519(kp.secret_key(password)?)),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            Self::Minisign(kp) => AsfaloadPublicKeys::Minisign(kp.public_key()),
            Self::Ed25519(kp) => AsfaloadPublicKeys::Ed25519(kp.public_key()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsfaloadPublicKeys {
    Minisign(AsfaloadPublicKey<minisign::PublicKey>),
    Ed25519(AsfaloadPublicKey<Ed25519PublicKey>),
}

impl serde::Serialize for AsfaloadPublicKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> serde::Deserialize<'de> for AsfaloadPublicKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        AsfaloadPublicKeys::from_base64(&s).map_err(|_e| {
            serde::de::Error::custom(format!("Problem parsing public key base64: {}", s))
        })
    }
}

impl AsfaloadPublicKeyTrait for AsfaloadPublicKeys {
    type Signature = AsfaloadSignatures;
    type KeyType = AsfaloadPublicKeys;
    type SecretKeyType = AsfaloadSecretKeys;

    fn verify(
        &self,
        signature: &Self::Signature,
        data: &AsfaloadHashes,
    ) -> Result<(), VerifyError> {
        match (self, signature) {
            (Self::Minisign(pk), AsfaloadSignatures::Minisign(sig)) => pk.verify(sig, data),
            (Self::Ed25519(pk), AsfaloadSignatures::Ed25519(sig)) => pk.verify(sig, data),
            _ => Err(VerifyError::VerificationFailed(
                "Algorithm mismatch between key and signature".to_string(),
            )),
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Minisign(pk) => format!("{}:{}", KeyFormat::Minisign, pk.to_base64()),
            Self::Ed25519(pk) => format!("{}:{}", KeyFormat::Ed25519, pk.to_base64()),
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        // Try minisign first for backward compatibility
        if let Ok(pk) = AsfaloadPublicKey::<minisign::PublicKey>::from_bytes(data) {
            return Ok(Self::Minisign(pk));
        }
        let pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_bytes(data)?;
        Ok(Self::Ed25519(pk))
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        // Try minisign first; if it fails, try ed25519
        if let Ok(pk) = AsfaloadPublicKey::<minisign::PublicKey>::from_file(&path) {
            return Ok(Self::Minisign(pk));
        }
        let pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_file(path)?;
        Ok(Self::Ed25519(pk))
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        let (format_str, key_b64) = s.split_once(':').ok_or_else(|| {
            KeyError::CreationFailed(format!(
                "Public key missing format prefix (expected 'format:base64'): {}",
                s
            ))
        })?;
        let format = KeyFormat::from_str(format_str)?;
        match format {
            KeyFormat::Minisign => {
                let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_base64(key_b64)?;
                Ok(Self::Minisign(pk))
            }
            KeyFormat::Ed25519 => {
                let pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_base64(key_b64)?;
                Ok(Self::Ed25519(pk))
            }
        }
    }

    fn from_base64_with_format(s: &str, format: &KeyFormat) -> Result<Self, KeyError> {
        // Strip prefix if present
        let key_b64 = s.split_once(':').map(|(_, b64)| b64).unwrap_or(s);
        match format {
            KeyFormat::Minisign => {
                let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_base64(key_b64)?;
                Ok(Self::Minisign(pk))
            }
            KeyFormat::Ed25519 => {
                let pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_base64(key_b64)?;
                Ok(Self::Ed25519(pk))
            }
        }
    }

    fn from_secret_key(sk_in: &AsfaloadSecretKeys) -> Result<Self, KeyError> {
        match sk_in {
            AsfaloadSecretKeys::Minisign(sk) => {
                let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_secret_key(sk)?;
                Ok(Self::Minisign(pk))
            }
            AsfaloadSecretKeys::Ed25519(sk) => {
                let pk = AsfaloadPublicKey::<Ed25519PublicKey>::from_secret_key(sk)?;
                Ok(Self::Ed25519(pk))
            }
        }
    }

    fn key_format(&self) -> KeyFormat {
        match self {
            Self::Minisign(pk) => pk.key_format(),
            Self::Ed25519(pk) => pk.key_format(),
        }
    }

    fn key(&self) -> Self::KeyType {
        self.to_owned()
    }
}

#[derive(Debug, Clone)]
pub enum AsfaloadSecretKeys {
    Minisign(AsfaloadSecretKey<minisign::SecretKey>),
    Ed25519(AsfaloadSecretKey<Ed25519SecretKey>),
}

impl AsfaloadSecretKeyTrait for AsfaloadSecretKeys {
    type SecretKey = AsfaloadSecretKeys;
    type Signature = AsfaloadSignatures;

    fn sign(&self, data: &AsfaloadHashes) -> Result<Self::Signature, SignError> {
        match self {
            Self::Minisign(sk) => {
                let sig = sk.sign(data)?;
                Ok(AsfaloadSignatures::Minisign(sig))
            }
            Self::Ed25519(sk) => {
                let sig = sk.sign(data)?;
                Ok(AsfaloadSignatures::Ed25519(sig))
            }
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        // Try minisign first for backward compatibility
        if let Ok(sk) = AsfaloadSecretKey::<minisign::SecretKey>::from_bytes(data) {
            return Ok(Self::Minisign(sk));
        }
        let sk = AsfaloadSecretKey::<Ed25519SecretKey>::from_bytes(data)?;
        Ok(Self::Ed25519(sk))
    }

    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        // Try minisign first; if it fails, try ed25519 (PKCS#8 PEM)
        if let Ok(sk) = AsfaloadSecretKey::<minisign::SecretKey>::from_file(&path, password) {
            return Ok(Self::Minisign(sk));
        }
        let sk = AsfaloadSecretKey::<Ed25519SecretKey>::from_file(path, password)?;
        Ok(Self::Ed25519(sk))
    }
}

pub enum AsfaloadSignatures {
    Minisign(AsfaloadSignature<minisign::SignatureBox>),
    Ed25519(AsfaloadSignature<Ed25519Signature>),
}

impl std::fmt::Debug for AsfaloadSignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minisign(sig) => write!(f, "AsfaloadSignatures::Minisign({})", sig.to_base64()),
            Self::Ed25519(sig) => write!(f, "AsfaloadSignatures::Ed25519({})", sig.to_base64()),
        }
    }
}

impl Clone for AsfaloadSignatures {
    fn clone(&self) -> Self {
        match self {
            Self::Minisign(sig) => Self::Minisign(sig.clone()),
            Self::Ed25519(sig) => Self::Ed25519(sig.clone()),
        }
    }
}

impl AsfaloadSignatureTrait for AsfaloadSignatures {
    type PublicKeyType = AsfaloadPublicKeys;
    fn to_string(&self) -> String {
        match self {
            Self::Minisign(sig) => sig.to_string(),
            Self::Ed25519(sig) => sig.to_string(),
        }
    }

    fn from_string(data: &str) -> Result<Self, SignatureError> {
        // Try minisign first; if it fails, try ed25519
        if let Ok(sig) = AsfaloadSignature::<minisign::SignatureBox>::from_string(data) {
            return Ok(Self::Minisign(sig));
        }
        let sig = AsfaloadSignature::<Ed25519Signature>::from_string(data)?;
        Ok(Self::Ed25519(sig))
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError> {
        match self {
            Self::Minisign(sig) => {
                sig.to_file(path)?;
            }
            Self::Ed25519(sig) => {
                sig.to_file(path)?;
            }
        }
        Ok(self)
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError> {
        // Try minisign first; if it fails, try ed25519
        if let Ok(sig) = AsfaloadSignature::<minisign::SignatureBox>::from_file(&path) {
            return Ok(Self::Minisign(sig));
        }
        let sig = AsfaloadSignature::<Ed25519Signature>::from_file(path)?;
        Ok(Self::Ed25519(sig))
    }

    fn from_base64(s: &str) -> Result<Self, SignatureError> {
        // Try minisign first; if it fails, try ed25519
        if let Ok(sig) = AsfaloadSignature::<minisign::SignatureBox>::from_base64(s) {
            return Ok(Self::Minisign(sig));
        }
        let sig = AsfaloadSignature::<Ed25519Signature>::from_base64(s)?;
        Ok(Self::Ed25519(sig))
    }

    fn from_base64_with_format(s: &str, format: &KeyFormat) -> Result<Self, SignatureError> {
        match format {
            KeyFormat::Minisign => {
                let sig = AsfaloadSignature::<minisign::SignatureBox>::from_base64(s)?;
                Ok(Self::Minisign(sig))
            }
            KeyFormat::Ed25519 => {
                let sig = AsfaloadSignature::<Ed25519Signature>::from_base64(s)?;
                Ok(Self::Ed25519(sig))
            }
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Minisign(sig) => sig.to_base64(),
            Self::Ed25519(sig) => sig.to_base64(),
        }
    }

    fn add_to_aggregate_for_file<P: AsRef<Path>>(
        &self,
        signed_file: P,
        pub_key: &AsfaloadPublicKeys,
    ) -> Result<(), SignatureError> {
        match (self, pub_key) {
            (Self::Minisign(sig), AsfaloadPublicKeys::Minisign(pk)) => {
                sig.add_to_aggregate_for_file(signed_file, pk)
            }
            (Self::Ed25519(sig), AsfaloadPublicKeys::Ed25519(pk)) => {
                sig.add_to_aggregate_for_file(signed_file, pk)
            }
            _ => Err(SignatureError::FormatError(
                "Algorithm mismatch between signature and public key".to_string(),
            )),
        }
    }
}
