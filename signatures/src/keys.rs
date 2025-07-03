mod minisign;
use std::path::Path;

enum AsfaloadKeyPairs {
    Minisign(minisign::KeyPair),
}

// Trait that we will implement for keypairs we support. Inintially only minisign::KeyPair
trait AsfaloadKeyPairTrait<'a> {
    type PublicKey;
    type SecretKey;
    type KeyErr;
    fn new(pw: &str) -> Result<Self, Self::KeyErr>
    where
        Self: Sized;
    // If the path is an existing directory, save the secret key in this directory in
    // file named 'key', and public key in 'key.pub'.
    // If the path is an inexisting file in an existing directory, save secret key
    // in this newly created filr, and save the public key in the same filename with added suffx
    // '.pub'
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, Self::KeyErr>;
    // As we use minisign as the first (and initially only) signing scheme, our proposed API is
    // modelled after it. When we generate a minisign key pai, the private key is encrypted and
    // needs to be decrypted for use.
    // This method returns the decrypted secret key, and thus requires the decryption password as
    // argument.
    fn secret_key(&self, password: &str) -> Result<Self::SecretKey, Self::KeyErr>;
    fn public_key(&self) -> Self::PublicKey;
}

#[derive(Debug)]
struct AsfaloadKeyPair<T> {
    key_pair: T,
}

// This trait should never give access to the private key it manages, as it is non-encrypted (for
// minisign)
trait AsfaloadSecretKeyTrait {
    type SecretKey;
    type Signature;
    type SignError;
    type KeyError;
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
struct AsfaloadSecretKey<K> {
    // Keep it private as for minisign it is the decrypted key, i.e. non password protected.
    key: K,
}
trait AsfaloadPublicKeyTrait {
    type Signature;
    type VerifyError;
    type KeyError;
    fn verify(&self, signature: &Self::Signature, data: &[u8]) -> Result<(), Self::VerifyError>;
    fn from_bytes(data: &[u8]) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
    fn from_string(s: String) -> Result<Self, Self::KeyError>
    where
        Self: Sized,
    {
        Self::from_bytes(&s.into_bytes())
    }
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
}

struct AsfaloadPublicKey<K> {
    key: K,
}

#[derive(Debug)]
struct AsfaloadSignature<S> {
    signature: S,
}

trait AsfaloadSignatureTrait {
    type SignatureError;
    fn to_string(&self) -> String;
    fn from_string(s: &str) -> Result<Self, Self::SignatureError>
    where
        Self: Sized;
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Self::SignatureError>
    where
        Self: Sized;

    // As we need to serialise to json, and json does not support multiline strings, we ssupport
    // the serialisation to base64 format.
    fn from_b64(s: &str) -> Result<Self, Self::SignatureError>
    where
        Self: Sized;

    fn to_b64(&self) -> String;
}
