//! Native asfaload key format: on-disk byte layout (`format`), the shared
//! ed25519 trait implementations (`ed25519_types`) used by both the asfaload
//! format and the OpenSSH importer, and the `AsfaloadKeyPair<T>` impls.

pub mod ed25519_types;
pub mod format;
pub mod keypair;

pub use ed25519_types::{
    ASFALOAD_PUB_PREFIX, AsfaloadEd25519PublicKey, AsfaloadEd25519SecretKey,
    AsfaloadEd25519Signature, AsfaloadKeysBlob, EncryptedEd25519Key, SSH_ED25519_PREFIX,
    SshEncryptedKey,
};
pub use keypair::ASFALOAD_PRIV_PREFIX;
