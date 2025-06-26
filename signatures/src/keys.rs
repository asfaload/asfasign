mod minisign;
use std::path::Path;
use tap::prelude::*

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
    fn from_file<P: AsRef<Path>>(
        path: P,
        password: String,
    ) -> Result<Self, Self::KeyError>  where Self:Sized;
}
