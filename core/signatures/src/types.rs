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
};
use common::fs::names::{pending_signatures_path_for, signatures_path_for};
use common::{
    AsfaloadHashes,
    errors::keys::{KeyError, SignError, SignatureError, VerifyError},
};
use std::fs::File;
use std::path::Path;

#[cfg(test)]
mod tests;

pub enum AsfaloadKeyPairs {
    Minisign(AsfaloadKeyPair<minisign::KeyPair>),
}
impl<'a> AsfaloadKeyPairTrait<'a> for AsfaloadKeyPairs {
    type PublicKey = AsfaloadPublicKeys;
    type SecretKey = AsfaloadSecretKeys;
    fn new(pw: &str) -> Result<Self, common::errors::keys::KeyError> {
        let minisign_key = AsfaloadKeyPair::<minisign::KeyPair>::new(pw)?;
        Ok(Self::Minisign(minisign_key))
    }
    fn save<T: AsRef<std::path::Path>>(
        &self,
        p: T,
    ) -> Result<&Self, common::errors::keys::KeyError> {
        match self {
            Self::Minisign(kp) => kp.save(p)?,
        };
        Ok(self)
    }

    fn secret_key(
        &self,
        password: &str,
    ) -> Result<Self::SecretKey, common::errors::keys::KeyError> {
        match self {
            Self::Minisign(kp) => Ok(AsfaloadSecretKeys::Minisign(kp.secret_key(password)?)),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            Self::Minisign(kp) => AsfaloadPublicKeys::Minisign(kp.public_key()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsfaloadPublicKeys {
    Minisign(AsfaloadPublicKey<minisign::PublicKey>),
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
        }
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Minisign(pk) => pk.to_base64(),
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_bytes(data)?;
        Ok(Self::Minisign(pk))
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_file(path)?;
        Ok(Self::Minisign(pk))
    }

    fn from_base64(s: &str) -> Result<Self, KeyError> {
        // With multiple backing algorithms, we could try one
        // after the other and return the corresponding one
        // if only one worked. If multiple attempts are successful
        // we don't know which one should be returned.
        let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_base64(s)?;
        Ok(Self::Minisign(pk))
    }

    fn from_secret_key(sk_in: &AsfaloadSecretKeys) -> Result<Self, KeyError> {
        match sk_in {
            AsfaloadSecretKeys::Minisign(sk) => {
                let pk = AsfaloadPublicKey::<minisign::PublicKey>::from_secret_key(sk)?;
                Ok(Self::Minisign(pk))
            }
        }
    }

    fn key_format(&self) -> KeyFormat {
        match self {
            Self::Minisign(pk) => pk.key_format(),
        }
    }

    fn key(&self) -> Self::KeyType {
        self.to_owned()
    }
}

#[derive(Debug, Clone)]
pub enum AsfaloadSecretKeys {
    Minisign(AsfaloadSecretKey<minisign::SecretKey>),
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
        }
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError> {
        let sk = AsfaloadSecretKey::<minisign::SecretKey>::from_bytes(data)?;
        Ok(Self::Minisign(sk))
    }

    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError> {
        let sk = AsfaloadSecretKey::<minisign::SecretKey>::from_file(path, password)?;
        Ok(Self::Minisign(sk))
    }
}

pub enum AsfaloadSignatures {
    Minisign(AsfaloadSignature<minisign::SignatureBox>),
}

impl std::fmt::Debug for AsfaloadSignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minisign(sig) => write!(f, "AsfaloadSignatures::Minisign({})", sig.to_base64()),
        }
    }
}

impl Clone for AsfaloadSignatures {
    fn clone(&self) -> Self {
        match self {
            Self::Minisign(sig) => Self::Minisign(sig.clone()),
        }
    }
}

impl AsfaloadSignatureTrait for AsfaloadSignatures {
    fn to_string(&self) -> String {
        match self {
            Self::Minisign(sig) => sig.to_string(),
        }
    }

    fn from_string(data: &str) -> Result<Self, SignatureError> {
        let sig = AsfaloadSignature::<minisign::SignatureBox>::from_string(data)?;
        Ok(Self::Minisign(sig))
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError> {
        match self {
            Self::Minisign(sig) => {
                sig.to_file(path)?;
            }
        }
        Ok(self)
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError> {
        let sig = AsfaloadSignature::<minisign::SignatureBox>::from_file(path)?;
        Ok(Self::Minisign(sig))
    }

    fn from_base64(s: &str) -> Result<Self, SignatureError> {
        let sig = AsfaloadSignature::<minisign::SignatureBox>::from_base64(s)?;
        Ok(Self::Minisign(sig))
    }

    fn to_base64(&self) -> String {
        match self {
            Self::Minisign(sig) => sig.to_base64(),
        }
    }

    fn add_to_aggregate_for_file<P: AsRef<Path>, PK: AsfaloadPublicKeyTrait<Signature = Self>>(
        &self,
        signed_file: P,
        pub_key: &PK,
    ) -> Result<(), SignatureError> {
        // Check if the path is a directory
        if signed_file.as_ref().is_dir() {
            return Err(SignatureError::IoError(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "Requires a file, cannot sign a directory",
            )));
        }

        let signed_file_path = signed_file.as_ref();

        // Check if aggregate signature is already complete
        let signatures_path = signatures_path_for(signed_file_path)?;
        if signatures_path.exists() && signatures_path.is_file() {
            return Err(SignatureError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Aggregate signature is already complete",
            )));
        }

        // Get the pending signatures file path
        let pending_sig_file_path = pending_signatures_path_for(signed_file_path)?;

        // Read existing signatures, or create a new map if the file doesn't exist
        let mut signatures_map: std::collections::HashMap<String, String> =
            match File::open(&pending_sig_file_path) {
                Ok(file) => serde_json::from_reader(file)?,
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::collections::HashMap::new()
                }
                Err(e) => return Err(e.into()),
            };

        // Verify the signature
        let signed_data = common::sha512_for_file(signed_file_path)?;
        if pub_key.verify(self, &signed_data).is_ok() {
            // Add the signature to the map
            let pubkey_b64 = pub_key.to_base64();
            signatures_map.insert(pubkey_b64, self.to_base64());

            // Write the updated map back to the file
            let file = File::create(&pending_sig_file_path)?;
            serde_json::to_writer_pretty(file, &signatures_map)?;

            Ok(())
        } else {
            Err(SignatureError::InvalidSignatureForAggregate(
                signed_file_path.to_path_buf(),
            ))
        }
    }
}
