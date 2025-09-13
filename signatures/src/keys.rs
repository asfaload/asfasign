pub mod minisign;
use std::{fmt::Display, path::Path};

pub enum AsfaloadKeyPairs {
    Minisign(minisign::KeyPair),
}
pub mod errs {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum KeyError {
        #[error("Key creation failed: {0}")]
        CreationFailed(String),
        #[error("Keypair fs io error")]
        IOError(#[from] std::io::Error),
        #[error("Refusing to overwrite existing files")]
        NotOverwriting(String),
    }

    #[derive(Error, Debug)]
    pub enum SignError {
        #[error("Signature failed: {0}")]
        SignatureFailed(String),
    }

    #[derive(Error, Debug)]
    pub enum VerifyError {
        #[error("Verification failed: {0}")]
        VerificationFailed(String),
    }

    #[derive(Error, Debug)]
    pub enum SignatureError {
        #[error("Error reading signature: {0}")]
        FormatError(String),
        #[error("base64 decoding of signature failed")]
        Base64DecodeFailed(#[from] base64::DecodeError),
        #[error("Invalid Utf8 string")]
        Utf8DecodeFailed(#[from] std::str::Utf8Error),
        #[error("IO error: {0}")]
        IoError(#[from] std::io::Error),
        #[error("JSON error: {0}")]
        JsonError(#[from] serde_json::Error),
    }
}

// Trait that we will implement for keypairs we support. Inintially only minisign::KeyPair
pub trait AsfaloadKeyPairTrait<'a> {
    type PublicKey;
    type SecretKey;
    fn new(pw: &str) -> Result<Self, errs::KeyError>
    where
        Self: Sized;
    // If the path is an existing directory, save the secret key in this directory in
    // file named 'key', and public key in 'key.pub'.
    // If the path is an inexisting file in an existing directory, save secret key
    // in this newly created filr, and save the public key in the same filename with added suffx
    // '.pub'
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, errs::KeyError>;
    // As we use minisign as the first (and initially only) signing scheme, our proposed API is
    // modelled after it. When we generate a minisign key pai, the private key is encrypted and
    // needs to be decrypted for use.
    // This method returns the decrypted secret key, and thus requires the decryption password as
    // argument.
    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, errs::KeyError>;
    fn public_key(&self) -> Self::PublicKey;
}

#[derive(Debug)]
pub struct AsfaloadKeyPair<T> {
    key_pair: T,
}

// This trait should never give access to the private key it manages, as it is non-encrypted (for
// minisign)
pub trait AsfaloadSecretKeyTrait {
    type SecretKey;
    type Signature;
    type SignError: Display;
    type KeyError: Display;
    fn sign(&self, data: &[u8]) -> Result<Self::Signature, Self::SignError>;
    fn from_bytes(data: &[u8]) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
    fn from_string(s: String) -> Result<Self, Self::KeyError>
    where
        Self: Sized,
    {
        Self::from_bytes(&s.into_bytes())
    }
    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
}

// Struct to store a secret key immediately usable.
// This means that for minisign, it holds the non-encrypted secret key.
pub struct AsfaloadSecretKey<K> {
    // Keep it private as for minisign it is the decrypted key, i.e. non password protected.
    key: K,
}
pub trait AsfaloadPublicKeyTrait {
    type Signature;
    type VerifyError: Display;
    type KeyError: Display;

    fn verify(&self, signature: &Self::Signature, data: &[u8]) -> Result<(), Self::VerifyError>;
    fn to_base64(&self) -> String;
    fn to_filename(&self) -> String {
        self.to_base64().replace("+", "-").replace("/", "_")
    }
    fn from_filename(n: String) -> Result<Self, Self::KeyError>
    where
        Self: Sized,
    {
        let b64 = n.replace("-", "+").replace("_", "/");
        Self::from_base64(b64)
    }
    fn from_bytes(data: &[u8]) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
    fn from_base64(s: String) -> Result<Self, Self::KeyError>
    where
        Self: Sized,
    {
        Self::from_bytes(&s.into_bytes())
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
}

#[derive(Debug, Clone)]
pub struct AsfaloadPublicKey<K> {
    key: K,
}

#[derive(Debug, Clone)]
pub struct AsfaloadSignature<S> {
    signature: S,
}

pub trait AsfaloadSignatureTrait {
    type SignatureError: Display;
    fn to_string(&self) -> String;
    fn from_string(s: &str) -> Result<Self, Self::SignatureError>
    where
        Self: Sized;
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Self::SignatureError>
    where
        Self: Sized;

    // As we need to serialise to json, and json does not support multiline strings, we ssupport
    // the serialisation to base64 format.
    fn from_base64(s: &str) -> Result<Self, Self::SignatureError>
    where
        Self: Sized;

    fn to_base64(&self) -> String;
    fn add_to_aggregate_for_file<P: AsRef<Path>, PK: AsfaloadPublicKeyTrait>(
        &self,
        dir: P,
        pub_key: &PK,
    ) -> Result<(), Self::SignatureError>
    where
        Self: Sized;
}
