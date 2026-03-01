pub mod ed25519;
pub mod minisign;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};

// Shared utility: append ".pub" to a key file path.
// Beware, if the path ends with /, the trailing slash is dropped before appending.
// See https://www.reddit.com/r/rust/comments/ooh5wn/damn_trailing_slash/
pub(crate) fn append_pub_extension<T: AsRef<Path>>(p: &T) -> PathBuf {
    let path = p.as_ref();
    let file_name = path.file_name().unwrap();
    let mut osstring: OsString = file_name.to_os_string();
    osstring.push(".pub");
    let mut pub_path_buf = path.to_path_buf();
    pub_path_buf.set_file_name(osstring.as_os_str());
    pub_path_buf
}

use crate::signatures_file::{SignaturesFile, TaggedSignature};
use common::errors::keys::{SignError, SignatureError, VerifyError};
use common::fs::names::{pending_signatures_path_for, revocation_path_for, signatures_path_for};
use common::{AsfaloadHashes, errors::keys::KeyError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyFormat {
    Minisign,
    Ed25519,
}

impl std::fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyFormat::Minisign => write!(f, "minisign"),
            KeyFormat::Ed25519 => write!(f, "ed25519"),
        }
    }
}

impl std::str::FromStr for KeyFormat {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minisign" => Ok(KeyFormat::Minisign),
            "ed25519" => Ok(KeyFormat::Ed25519),
            _ => Err(KeyError::CreationFailed(format!(
                "Unknown key format: {}",
                s
            ))),
        }
    }
}

// Trait that we will implement for keypairs we support. Initially only minisign::KeyPair
pub trait AsfaloadKeyPairTrait<'a>: Sized {
    type PublicKey;
    type SecretKey;
    fn new(pw: &str) -> Result<Self, KeyError>;
    // If the path is an existing directory, save the secret key in this directory in
    // file named 'key', and public key in 'key.pub'.
    // If the path is an inexisting file in an existing directory, save secret key
    // in this newly created file, and save the public key in the same filename with added suffx
    // '.pub'
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, KeyError>;
    // As we use minisign as the first (and initially only) signing scheme, our proposed API is
    // modelled after it. When we generate a minisign key pair, the private key is encrypted and
    // needs to be decrypted for use.
    // This method returns the decrypted secret key, and thus requires the decryption password as
    // argument.
    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, KeyError>;
    fn public_key(&self) -> Self::PublicKey;
}

#[derive(Debug)]
pub struct AsfaloadKeyPair<T> {
    key_pair: T,
}

// This trait should never give access to the private key it manages, as it is non-encrypted (for
// minisign)
pub trait AsfaloadSecretKeyTrait: Sized {
    type SecretKey;
    type Signature;
    fn sign(&self, data: &common::AsfaloadHashes) -> Result<Self::Signature, SignError>;
    fn from_bytes(data: &[u8]) -> Result<Self, KeyError>;
    fn from_string(s: &str) -> Result<Self, KeyError> {
        Self::from_bytes(s.as_bytes())
    }
    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError>;
}

// Struct to store a secret key immediately usable.
// This means that for minisign, it holds the non-encrypted secret key.
#[derive(Debug, Clone)]
pub struct AsfaloadSecretKey<K> {
    // Keep it private as for minisign it is the decrypted key, i.e. non password protected.
    key: K,
}
pub trait AsfaloadPublicKeyTrait: Sized + Eq + std::hash::Hash + Clone + std::fmt::Debug {
    type Signature: AsfaloadSignatureTrait;
    type KeyType;
    type SecretKeyType;

    fn verify(&self, signature: &Self::Signature, data: &AsfaloadHashes)
    -> Result<(), VerifyError>;
    fn to_base64(&self) -> String;
    fn to_filename(&self) -> String {
        self.to_base64().replace("+", "-").replace("/", "_")
    }
    fn from_filename(n: String) -> Result<Self, KeyError> {
        let b64 = n.replace("-", "+").replace("_", "/");
        Self::from_base64(&b64)
    }
    fn from_bytes(data: &[u8]) -> Result<Self, KeyError>;
    fn from_base64(s: &str) -> Result<Self, KeyError> {
        Self::from_bytes(s.as_bytes())
    }
    fn from_base64_with_format(s: &str, _format: &KeyFormat) -> Result<Self, KeyError> {
        Self::from_base64(s)
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError>;
    fn from_secret_key(sk: &Self::SecretKeyType) -> Result<Self, KeyError>;
    fn key_format(&self) -> KeyFormat;
    fn key(&self) -> Self::KeyType;
}

#[derive(Debug, Clone)]
pub struct AsfaloadPublicKey<K> {
    key: K,
}

impl<K> TryFrom<String> for AsfaloadPublicKey<K>
where
    AsfaloadPublicKey<K>: AsfaloadPublicKeyTrait,
{
    type Error = KeyError;
    fn try_from(value: String) -> Result<AsfaloadPublicKey<K>, KeyError> {
        Self::from_base64(&value)
    }
}

#[derive(Debug, Clone)]
pub struct AsfaloadSignature<S> {
    signature: S,
}

pub trait AsfaloadSignatureTrait: Sized {
    type PublicKeyType: AsfaloadPublicKeyTrait<Signature = Self>;
    fn to_string(&self) -> String;
    fn from_string(s: &str) -> Result<Self, SignatureError>;
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError>;
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError>;

    // As we need to serialise to json, and json does not support multiline strings, we support
    // the serialisation to base64 format.
    fn from_base64(s: &str) -> Result<Self, SignatureError>;
    fn from_base64_with_format(s: &str, _format: &KeyFormat) -> Result<Self, SignatureError> {
        Self::from_base64(s)
    }

    fn to_base64(&self) -> String;
    // Warning: this only adds the file to a pending signatures file, but it does not transition
    // to complete if needed. So the way to add a signature to an aggregate on the backend should be by
    // calling AggregateSignature::add_individual_signature.
    // This method is useful for use on the client though, where the signers file used to
    // evaluate completeness is not available.
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
            let key_format = pub_key.key_format();
            let pubkey_b64 = format!("{}:{}", key_format, pub_key.to_base64());
            if sig_file.entries.contains_key(&pubkey_b64) {
                return Err(SignatureError::DuplicateSignature);
            }
            sig_file.entries.insert(
                pubkey_b64,
                TaggedSignature {
                    format: key_format,
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
mod key_format_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_key_format_display() {
        assert_eq!(format!("{}", KeyFormat::Minisign), "minisign");
        assert_eq!(format!("{}", KeyFormat::Ed25519), "ed25519");
    }

    #[test]
    fn test_key_format_from_str() {
        assert_eq!(
            KeyFormat::from_str("minisign").unwrap(),
            KeyFormat::Minisign
        );
        assert_eq!(KeyFormat::from_str("ed25519").unwrap(), KeyFormat::Ed25519);
    }

    #[test]
    fn test_key_format_from_str_invalid() {
        assert!(KeyFormat::from_str("rsa").is_err());
        assert!(KeyFormat::from_str("").is_err());
    }

    #[test]
    fn test_key_format_roundtrip() {
        let formats = [KeyFormat::Minisign, KeyFormat::Ed25519];
        for fmt in &formats {
            let s = format!("{}", fmt);
            let parsed = KeyFormat::from_str(&s).unwrap();
            assert_eq!(*fmt, parsed);
        }
    }
}
