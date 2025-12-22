pub mod minisign;
use std::path::Path;

use common::errors::keys::{SignError, SignatureError, VerifyError};
use common::{AsfaloadHashes, errors::keys::KeyError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyFormat {
    Minisign,
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
    fn from_string(s: String) -> Result<Self, KeyError> {
        Self::from_bytes(&s.into_bytes())
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
        Self::from_base64(b64)
    }
    fn from_bytes(data: &[u8]) -> Result<Self, KeyError>;
    fn from_base64(s: String) -> Result<Self, KeyError> {
        Self::from_bytes(&s.into_bytes())
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyError>;
    fn from_secret_key(sk: Self::SecretKeyType) -> Result<Self, KeyError>;
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
        Self::from_base64(value)
    }
}

#[derive(Debug, Clone)]
pub struct AsfaloadSignature<S> {
    signature: S,
}

pub trait AsfaloadSignatureTrait: Sized {
    fn to_string(&self) -> String;
    fn from_string(s: &str) -> Result<Self, SignatureError>;
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<&Self, SignatureError>;
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SignatureError>;

    // As we need to serialise to json, and json does not support multiline strings, we support
    // the serialisation to base64 format.
    fn from_base64(s: &str) -> Result<Self, SignatureError>;

    fn to_base64(&self) -> String;
    // Warning: this only adds the file to a pending signatures file, but it does not transition
    // to complete if needed. So the way to add a signature to an aggregate on the backend should be by
    // calling AggregateSignature::add_individual_signature.
    // This method is useful for use on the client though, where the signers file used to
    // evaluate completeness is not available.
    fn add_to_aggregate_for_file<P: AsRef<Path>, PK: AsfaloadPublicKeyTrait<Signature = Self>>(
        &self,
        dir: P,
        pub_key: &PK,
    ) -> Result<(), SignatureError>;
}
