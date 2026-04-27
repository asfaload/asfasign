// We defined here enum types implementing the Asfaload traits allowing to support mulitple signing
// algorithms. We have one enum per crypo element (public key, secret key, signature, keypair) and
// each enum hase one case per algorithm we support.
// These enum simply wrap the corresponding Asfaload type (eg AsfaloadPublicKey<_>), setting its
// generic type, and implement the same traits, delegating the action of the trait's functions to
// the wrapped value. For example, AsfaloadPublicKeys has one case Asfaload which wrap
// AsfaloadPublicKey<VerifyingKey>. It implements AsfaloadPublicKeyTrait.

use crate::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
    AsfaloadSignatureTrait, KeyFormat,
    asfaload::{
        ASFALOAD_PUB_PREFIX, AsfaloadEd25519PublicKey, AsfaloadEd25519SecretKey,
        AsfaloadEd25519Signature, AsfaloadKeysBlob, SSH_ED25519_PREFIX, SshEncryptedKey,
    },
};
use common::{
    AsfaloadHashes,
    errors::keys::{KeyError, SignError, SignatureError, VerifyError},
};
use std::path::Path;

#[cfg(test)]
mod tests;

pub enum AsfaloadKeyPairs {
    Asfaload(AsfaloadKeyPair<AsfaloadKeysBlob>),
    OpenSsh(AsfaloadKeyPair<SshEncryptedKey>),
}

impl std::fmt::Debug for AsfaloadKeyPairs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Asfaload(_) => write!(f, "AsfaloadKeyPairs::Asfaload(<redacted>)"),
            Self::OpenSsh(_) => write!(f, "AsfaloadKeyPairs::OpenSsh(<redacted>)"),
        }
    }
}

impl AsfaloadKeyPairs {
    pub fn new_with_format(pw: &str, format: &KeyFormat) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Asfaload => {
                let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new(pw)?;
                Ok(Self::Asfaload(kp))
            }
            KeyFormat::OpenSsh => Err(KeyError::ImportOnlyFormat(
                "cannot generate an openssh-format keypair; asfaload is read-only for SSH".into(),
            )),
        }
    }

    /// Generate keypair with custom argon2id cost (asfaload only; ignored for other formats).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_with_format_and_argon2_params(
        pw: &str,
        format: &KeyFormat,
        params: crate::keys::asfaload::format::Argon2Params,
    ) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Asfaload => {
                let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new_with_argon2_params(pw, params)?;
                Ok(Self::Asfaload(kp))
            }
            KeyFormat::OpenSsh => Err(KeyError::CreationFailed(
                "cannot generate an openssh-format keypair; asfaload is read-only for SSH".into(),
            )),
        }
    }
}

impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPairs {
    type PublicKey = AsfaloadPublicKeys;
    type SecretKey = AsfaloadSecretKeys;
    fn new(pw: &str) -> Result<Self, KeyError> {
        let asfaload_key = AsfaloadKeyPair::<AsfaloadKeysBlob>::new(pw)?;
        Ok(Self::Asfaload(asfaload_key))
    }
    fn save<T: AsRef<std::path::Path>>(&self, p: T) -> Result<&Self, KeyError> {
        match self {
            Self::Asfaload(kp) => {
                kp.save(p)?;
            }
            Self::OpenSsh(kp) => {
                kp.save(p)?;
            }
        };
        Ok(self)
    }

    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError> {
        match self {
            Self::Asfaload(kp) => Ok(AsfaloadSecretKeys::Asfaload(kp.secret_key(password)?)),
            Self::OpenSsh(kp) => Ok(AsfaloadSecretKeys::Asfaload(kp.secret_key(password)?)),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            Self::Asfaload(kp) => AsfaloadPublicKeys::Asfaload(kp.public_key()),
            Self::OpenSsh(kp) => AsfaloadPublicKeys::Asfaload(kp.public_key()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsfaloadPublicKeys {
    Asfaload(AsfaloadEd25519PublicKey),
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
            (Self::Asfaload(pk), AsfaloadSignatures::Asfaload(sig)) => pk.verify(sig, data),
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Asfaload(pk) => pk.to_base64(),
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let pk = AsfaloadEd25519PublicKey::from_bytes(data)?;
        Ok(Self::Asfaload(pk))
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        match KeyFormat::from_file(&path)? {
            KeyFormat::Asfaload | KeyFormat::OpenSsh => {
                let content = std::fs::read_to_string(&path)?;
                let pk = AsfaloadEd25519PublicKey::from_base64(content.trim_start())?;
                Ok(Self::Asfaload(pk))
            }
        }
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        if s.starts_with(ASFALOAD_PUB_PREFIX) || s.starts_with(SSH_ED25519_PREFIX) {
            let pk = AsfaloadEd25519PublicKey::from_base64(s)?;
            return Ok(Self::Asfaload(pk));
        }
        Err(KeyError::CreationFailed(format!(
            "unrecognised public-key prefix in input starting with: {}",
            s.chars().take(32).collect::<String>()
        )))
    }

    fn from_secret_key(sk_in: &AsfaloadSecretKeys) -> Result<Self, KeyError> {
        match sk_in {
            AsfaloadSecretKeys::Asfaload(sk) => {
                let pk = AsfaloadEd25519PublicKey::from_secret_key(sk)?;
                Ok(Self::Asfaload(pk))
            }
        }
    }

    fn key_format(&self) -> KeyFormat {
        match self {
            Self::Asfaload(pk) => pk.key_format(),
        }
    }

    fn key(&self) -> Self::KeyType {
        self.to_owned()
    }
}

#[derive(Debug, Clone)]
pub enum AsfaloadSecretKeys {
    Asfaload(AsfaloadEd25519SecretKey),
}

impl AsfaloadSecretKeys {
    /// Load a secret key and assert it is in the specified format.
    ///
    /// Use this when the caller wants to reject files that are not in the
    /// expected format. For permissive loading that auto-detects
    /// Asfaload, and OpenSSH ed25519 files, use `from_file`.
    pub fn from_file_for_format<P: AsRef<std::path::Path>>(
        path: P,
        password: &str,
        format: &KeyFormat,
    ) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Asfaload => {
                let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::from_file(path)?;
                Ok(Self::Asfaload(kp.secret_key(password)?))
            }
            KeyFormat::OpenSsh => {
                let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_file(path)?;
                Ok(Self::Asfaload(kp.secret_key(password)?))
            }
        }
    }
}

impl AsfaloadSecretKeyTrait for AsfaloadSecretKeys {
    type SecretKey = AsfaloadSecretKeys;
    type Signature = AsfaloadSignatures;

    fn sign(&self, data: &AsfaloadHashes) -> Result<Self::Signature, SignError> {
        match self {
            Self::Asfaload(sk) => {
                let sig = sk.sign(data)?;
                Ok(AsfaloadSignatures::Asfaload(sig))
            }
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let sk = AsfaloadEd25519SecretKey::from_bytes(data)?;
        Ok(Self::Asfaload(sk))
    }

    fn from_string(s: &str, password: &str) -> Result<Self, KeyError> {
        match KeyFormat::from_head(s.trim_start())? {
            KeyFormat::Asfaload => {
                let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::from_string(s)?;
                Ok(Self::Asfaload(kp.secret_key(password)?))
            }
            KeyFormat::OpenSsh => {
                let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_string(s)?;
                Ok(Self::Asfaload(kp.secret_key(password)?))
            }
        }
    }

    /// Overrides the trait default to preserve the path in the "unrecognised
    /// key format" error (the from_string path only sees the content).
    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Self::from_string(&content, password).map_err(|e| match e {
            KeyError::FormatError(msg) => {
                KeyError::FormatError(format!("{} in {}", msg, path.display()))
            }
            other => other,
        })
    }
}

pub enum AsfaloadSignatures {
    Asfaload(AsfaloadEd25519Signature),
}

impl std::fmt::Debug for AsfaloadSignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Asfaload(sig) => write!(f, "AsfaloadSignatures::Asfaload({})", sig.to_base64()),
        }
    }
}

impl Clone for AsfaloadSignatures {
    fn clone(&self) -> Self {
        match self {
            Self::Asfaload(sig) => Self::Asfaload(sig.clone()),
        }
    }
}

impl AsfaloadSignatureTrait for AsfaloadSignatures {
    type PublicKeyType = AsfaloadPublicKeys;
    fn to_string(&self) -> String {
        match self {
            Self::Asfaload(sig) => sig.to_string(),
        }
    }

    fn from_string(data: &str) -> Result<Self, SignatureError> {
        let sig = AsfaloadEd25519Signature::from_string(data)?;
        Ok(Self::Asfaload(sig))
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError> {
        match self {
            Self::Asfaload(sig) => {
                sig.to_file(path)?;
            }
        }
        Ok(self)
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError> {
        let sig = AsfaloadEd25519Signature::from_file(path)?;
        Ok(Self::Asfaload(sig))
    }

    fn from_base64(s: &str) -> Result<Self, SignatureError> {
        let sig = AsfaloadEd25519Signature::from_base64(s)?;
        Ok(Self::Asfaload(sig))
    }

    fn from_base64_with_format(s: &str, format: &KeyFormat) -> Result<Self, SignatureError> {
        match format {
            KeyFormat::Asfaload | KeyFormat::OpenSsh => {
                let sig = AsfaloadEd25519Signature::from_base64(s)?;
                Ok(Self::Asfaload(sig))
            }
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Asfaload(sig) => sig.to_base64(),
        }
    }

    fn add_to_aggregate_for_file<P: AsRef<Path>>(
        &self,
        signed_file: P,
        pub_key: &AsfaloadPublicKeys,
    ) -> Result<(), SignatureError> {
        match (self, pub_key) {
            (Self::Asfaload(sig), AsfaloadPublicKeys::Asfaload(pk)) => {
                sig.add_to_aggregate_for_file(signed_file, pk)
            }
        }
    }
}
