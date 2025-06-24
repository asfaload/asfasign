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
