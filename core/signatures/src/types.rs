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
    Minisign(AsfaloadKeyPair<minisign::KeyPair>),
    Asfaload(AsfaloadKeyPair<AsfaloadKeysBlob>),
    OpenSsh(AsfaloadKeyPair<SshEncryptedKey>),
}

impl std::fmt::Debug for AsfaloadKeyPairs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minisign(_) => write!(f, "AsfaloadKeyPairs::Minisign(<redacted>)"),
            Self::Asfaload(_) => write!(f, "AsfaloadKeyPairs::Asfaload(<redacted>)"),
            Self::OpenSsh(_) => write!(f, "AsfaloadKeyPairs::OpenSsh(<redacted>)"),
        }
    }
}

impl AsfaloadKeyPairs {
    pub fn new_with_format(pw: &str, format: &KeyFormat) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Minisign => {
                let kp = AsfaloadKeyPair::<minisign::KeyPair>::new(pw)?;
                Ok(Self::Minisign(kp))
            }
            KeyFormat::Asfaload => {
                let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new(pw)?;
                Ok(Self::Asfaload(kp))
            }
            KeyFormat::OpenSsh => Err(KeyError::CreationFailed(
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
            KeyFormat::Minisign => {
                let kp = AsfaloadKeyPair::<minisign::KeyPair>::new(pw)?;
                Ok(Self::Minisign(kp))
            }
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
            Self::Minisign(kp) => Ok(AsfaloadSecretKeys::Minisign(kp.secret_key(password)?)),
            Self::Asfaload(kp) => Ok(AsfaloadSecretKeys::Asfaload(kp.secret_key(password)?)),
            Self::OpenSsh(kp) => Ok(AsfaloadSecretKeys::Asfaload(kp.secret_key(password)?)),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            Self::Minisign(kp) => AsfaloadPublicKeys::Minisign(kp.public_key()),
            Self::Asfaload(kp) => AsfaloadPublicKeys::Asfaload(kp.public_key()),
            Self::OpenSsh(kp) => AsfaloadPublicKeys::Asfaload(kp.public_key()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsfaloadPublicKeys {
    Minisign(AsfaloadPublicKey<minisign::PublicKey>),
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
            (Self::Minisign(pk), AsfaloadSignatures::Minisign(sig)) => pk.verify(sig, data),
            (Self::Asfaload(pk), AsfaloadSignatures::Asfaload(sig)) => pk.verify(sig, data),
            _ => Err(VerifyError::VerificationFailed(
                "Algorithm mismatch between key and signature".to_string(),
            )),
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Minisign(pk) => pk.to_base64(),
            Self::Asfaload(pk) => pk.to_base64(),
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        // Raw bytes carry no format marker, so we length/structure-sniff:
        // minisign public keys are ~42 bytes (sig-alg id + key id + 32 pk bytes),
        // asfaload ed25519 public keys are exactly 32 raw bytes. These are
        // mutually exclusive by length, so the sequence is unambiguous.
        if let Ok(pk) = AsfaloadPublicKey::<minisign::PublicKey>::from_bytes(data) {
            return Ok(Self::Minisign(pk));
        }
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
            KeyFormat::Minisign => {
                let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_file(&path)?;
                Ok(Self::Minisign(pk))
            }
        }
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        if s.starts_with(ASFALOAD_PUB_PREFIX) || s.starts_with(SSH_ED25519_PREFIX) {
            let pk = AsfaloadEd25519PublicKey::from_base64(s)?;
            return Ok(Self::Asfaload(pk));
        }
        if s.starts_with("minisign:") {
            let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_base64(s)?;
            return Ok(Self::Minisign(pk));
        }
        Err(KeyError::CreationFailed(format!(
            "unrecognised public-key prefix in input starting with: {}",
            s.chars().take(32).collect::<String>()
        )))
    }

    fn from_secret_key(sk_in: &AsfaloadSecretKeys) -> Result<Self, KeyError> {
        match sk_in {
            AsfaloadSecretKeys::Minisign(sk) => {
                let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_secret_key(sk)?;
                Ok(Self::Minisign(pk))
            }
            AsfaloadSecretKeys::Asfaload(sk) => {
                let pk = AsfaloadEd25519PublicKey::from_secret_key(sk)?;
                Ok(Self::Asfaload(pk))
            }
        }
    }

    fn key_format(&self) -> KeyFormat {
        match self {
            Self::Minisign(pk) => pk.key_format(),
            Self::Asfaload(pk) => pk.key_format(),
        }
    }

    fn key(&self) -> Self::KeyType {
        self.to_owned()
    }
}

#[derive(Debug, Clone)]
pub enum AsfaloadSecretKeys {
    Minisign(AsfaloadSecretKey<minisign::SecretKey>),
    Asfaload(AsfaloadEd25519SecretKey),
}

impl AsfaloadSecretKeys {
    /// Load a secret key by explicit format. Use this when you know the format
    /// (e.g., from CLI argument or config). The content-sniffing `from_file`
    /// does not handle OpenSSH files.
    pub fn from_file_for_format<P: AsRef<std::path::Path>>(
        path: P,
        password: &str,
        format: &KeyFormat,
    ) -> Result<Self, KeyError> {
        match format {
            KeyFormat::Minisign => Ok(Self::Minisign(
                AsfaloadSecretKey::<minisign::SecretKey>::from_file(path, password)?,
            )),
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
            Self::Minisign(sk) => {
                let sig = sk.sign(data)?;
                Ok(AsfaloadSignatures::Minisign(sig))
            }
            Self::Asfaload(sk) => {
                let sig = sk.sign(data)?;
                Ok(AsfaloadSignatures::Asfaload(sig))
            }
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        // Raw bytes carry no format marker, so we length/structure-sniff:
        // minisign secret keys are a structured binary blob (sig-alg + KDF
        // params + encrypted seed) much longer than 32 bytes; asfaload ed25519
        // secret keys are exactly a 32-byte raw seed. These are mutually
        // exclusive by length, so the sequence is unambiguous.
        if let Ok(sk) = AsfaloadSecretKey::<minisign::SecretKey>::from_bytes(data) {
            return Ok(Self::Minisign(sk));
        }
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
            KeyFormat::Minisign => Ok(Self::Minisign(
                AsfaloadSecretKey::<minisign::SecretKey>::from_string(s, password)?,
            )),
        }
    }

    /// Overrides the trait default to preserve the path in the "unrecognised
    /// key format" error (the from_string path only sees the content).
    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Self::from_string(&content, password).map_err(|e| match e {
            KeyError::CreationFailed(msg) if msg.contains("unrecognised key format") => {
                KeyError::CreationFailed(format!("unrecognised key format in {}", path.display()))
            }
            other => other,
        })
    }
}

pub enum AsfaloadSignatures {
    Minisign(AsfaloadSignature<minisign::SignatureBox>),
    Asfaload(AsfaloadEd25519Signature),
}

impl std::fmt::Debug for AsfaloadSignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minisign(sig) => write!(f, "AsfaloadSignatures::Minisign({})", sig.to_base64()),
            Self::Asfaload(sig) => write!(f, "AsfaloadSignatures::Asfaload({})", sig.to_base64()),
        }
    }
}

impl Clone for AsfaloadSignatures {
    fn clone(&self) -> Self {
        match self {
            Self::Minisign(sig) => Self::Minisign(sig.clone()),
            Self::Asfaload(sig) => Self::Asfaload(sig.clone()),
        }
    }
}

impl AsfaloadSignatureTrait for AsfaloadSignatures {
    type PublicKeyType = AsfaloadPublicKeys;
    fn to_string(&self) -> String {
        match self {
            Self::Minisign(sig) => sig.to_string(),
            Self::Asfaload(sig) => sig.to_string(),
        }
    }

    fn from_string(data: &str) -> Result<Self, SignatureError> {
        // Try minisign first; if it fails, try asfaload.
        if let Ok(sig) = AsfaloadSignature::<minisign::SignatureBox>::from_string(data) {
            return Ok(Self::Minisign(sig));
        }
        let sig = AsfaloadEd25519Signature::from_string(data)?;
        Ok(Self::Asfaload(sig))
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError> {
        match self {
            Self::Minisign(sig) => {
                sig.to_file(path)?;
            }
            Self::Asfaload(sig) => {
                sig.to_file(path)?;
            }
        }
        Ok(self)
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError> {
        // Try minisign first; if it fails, try asfaload.
        if let Ok(sig) = AsfaloadSignature::<minisign::SignatureBox>::from_file(&path) {
            return Ok(Self::Minisign(sig));
        }
        let sig = AsfaloadEd25519Signature::from_file(path)?;
        Ok(Self::Asfaload(sig))
    }

    fn from_base64(s: &str) -> Result<Self, SignatureError> {
        // Try minisign first; if it fails, try asfaload.
        if let Ok(sig) = AsfaloadSignature::<minisign::SignatureBox>::from_base64(s) {
            return Ok(Self::Minisign(sig));
        }
        let sig = AsfaloadEd25519Signature::from_base64(s)?;
        Ok(Self::Asfaload(sig))
    }

    fn from_base64_with_format(s: &str, format: &KeyFormat) -> Result<Self, SignatureError> {
        match format {
            KeyFormat::Minisign => {
                let sig = AsfaloadSignature::<minisign::SignatureBox>::from_base64(s)?;
                Ok(Self::Minisign(sig))
            }
            KeyFormat::Asfaload | KeyFormat::OpenSsh => {
                let sig = AsfaloadEd25519Signature::from_base64(s)?;
                Ok(Self::Asfaload(sig))
            }
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Minisign(sig) => sig.to_base64(),
            Self::Asfaload(sig) => sig.to_base64(),
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
            (Self::Asfaload(sig), AsfaloadPublicKeys::Asfaload(pk)) => {
                sig.add_to_aggregate_for_file(signed_file, pk)
            }
            _ => Err(SignatureError::FormatError(
                "Algorithm mismatch between signature and public key".to_string(),
            )),
        }
    }
}
