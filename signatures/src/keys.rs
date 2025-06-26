mod minisign;
use std::path::Path;

enum AsfaloadKeyPairs {
    Minisign(minisign::KeyPair),
}

// Trait that we will implement for keypairs we support. Inintially only minisign::KeyPair
trait AsfaloadKeyPair<'a> {
    type KeyErr;
    fn new(pw: &str) -> Result<Self, Self::KeyErr>
    where
        Self: Sized;
    fn save<T: AsRef<Path>>(&self, p: T) -> Result<&Self, Self::KeyErr>;
}

trait AsfaloadSecretKey {
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
    fn from_file<P: AsRef<Path>>(path: P, password: String) -> Result<Self, Self::KeyError>
    where
        Self: Sized;
}

trait AsfaloadPublicKey {
    type PublicKey;
    type Signature;
    type VerifyError;
    type KeyError;
    fn verify(&self, signature: Self::Signature, data: &[u8]) -> Result<(), Self::VerifyError>;
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
