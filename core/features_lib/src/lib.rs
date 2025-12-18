use std::path::{Path, PathBuf};

pub use common::errors;
pub use common::{
    ArtifactMarker, FileType, InitialSignersFileMarker, SignedFile, SignersFileMarker,
    errors::SignedFileError,
};
pub use common::{SignedFileLoader, SignedFileWithKind};
use common::{
    errors::keys::{KeyError, SignError},
    fs::names::{find_global_signers_for, pending_signers_file_in_dir},
};

pub use common::{AsfaloadHashes, sha512_for_content, sha512_for_file};

use signatures::keys::minisign;
use signatures::keys::{
    AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait,
};
use signatures::types::{
    AsfaloadKeyPairs, AsfaloadPublicKeys, AsfaloadSecretKeys, AsfaloadSignatures,
};

pub use signatures::keys::AsfaloadPublicKeyTrait as PublicKeyTrait;
pub use signatures::keys::AsfaloadSecretKeyTrait as SecretKeyTrait;
pub use signatures::keys::AsfaloadSignatureTrait as SignatureTrait;
pub use signatures::types::AsfaloadPublicKeys as PublicKey;
pub use signatures::types::AsfaloadSecretKeys as SecretKeyType;
pub use signatures::types::AsfaloadSignatures as Signature;

use signers_file::sign_signers_file;
pub use signers_file_types::SignersConfig;

// In this type argument we use AsfaloadPublicKeys and AsfaloadSignatures directly.
// This allows the user of this type to not specify any type arguments.
pub type SignatureWithState = aggregate_signature::SignatureWithState;

// We define and implement this trait in the user_lib as it depends on traits defined in other crates,
// which we want to avoid in common.
pub trait SignedFileTrait
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

//SignedFileTrait implementation for initial signers file and signers file updates
//are identical. The way to avoid duplicated code is to:
//* define an empty helper trait implemented by both marker types that lead to
//  the same implementation.
//* implement the SignefFileTrait once for all markers implementing that helper trait.
pub trait SignableFileMarker {}
impl SignableFileMarker for InitialSignersFileMarker {}
impl SignableFileMarker for SignersFileMarker {}

impl<T> SignedFileTrait for SignedFile<T>
where
    T: SignableFileMarker,
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        sign_signers_file(&self.location, &sig, &pubkey).map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl SignedFileTrait for SignedFile<ArtifactMarker>
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::load_for_file(&self.location)?;
        if let Some(pending_sig) = agg_sig_with_state.get_pending() {
            pending_sig
                .add_individual_signature(&sig, &pubkey)
                .map_err(|e| e.into())
        } else {
            Err(SignedFileError::AggregateSignatureError(
                common::errors::AggregateSignatureError::LogicError(
                    "Signature is already complete; cannot add another signature.".to_string(),
                ),
            ))
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

pub trait SignedFileWithKindTrait
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

impl SignedFileWithKindTrait for SignedFileWithKind
where
    AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
    AsfaloadSignatures: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignatures,
        pubkey: AsfaloadPublicKeys,
    ) -> Result<SignatureWithState, SignedFileError> {
        match self {
            SignedFileWithKind::InitialSignersFile(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::SignersFile(sf) => sf.add_signature(sig, pubkey),
            SignedFileWithKind::Artifact(sf) => sf.add_signature(sig, pubkey),
        }
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        match self {
            SignedFileWithKind::InitialSignersFile(sf) => sf.is_signed(),
            SignedFileWithKind::SignersFile(sf) => sf.is_signed(),
            SignedFileWithKind::Artifact(sf) => sf.is_signed(),
        }
    }
}

pub trait SignersFileTrait {
    fn find_for_path<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error>;
    fn find_pending_in_dir<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error>;
}

pub struct SignersFile;
impl SignersFileTrait for SignersFile {
    fn find_for_path<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
        find_global_signers_for(path_in.as_ref())
    }
    fn find_pending_in_dir<P: AsRef<Path>>(path_in: P) -> Result<PathBuf, std::io::Error> {
        pending_signers_file_in_dir(path_in)
    }
}

pub struct KeyPair {
    pub location: PathBuf,
    pub keypair: AsfaloadKeyPairs,
}
impl KeyPair {
    pub fn new<P: AsRef<Path>>(dir: P, name: &str, password: &str) -> Result<Self, KeyError> {
        let keypair = AsfaloadKeyPairs::new(password)?;
        let location = dir.as_ref().join(name);
        keypair.save(&location)?;
        Ok(KeyPair { keypair, location })
    }
}

pub struct SecretKey {
    pub location: PathBuf,
    pub key: AsfaloadSecretKeys,
}
impl SecretKey {
    pub fn from_file<P: AsRef<Path>>(location: P, password: &str) -> Result<Self, KeyError> {
        let key = AsfaloadSecretKeys::from_file(&location, password)?;
        Ok(SecretKey {
            key,
            location: location.as_ref().to_path_buf(),
        })
    }
}

// Implement SecretKeyTrait for SecretKey to make it compatible with AuthSignature::new
impl SecretKeyTrait for SecretKey {
    type SecretKey = minisign::SecretKey;
    type Signature = AsfaloadSignatures;

    fn sign(&self, data: &AsfaloadHashes) -> Result<Self::Signature, SignError> {
        self.key.sign(data)
    }

    fn from_bytes(data: &[u8]) -> Result<Self, KeyError>
    where
        Self: Sized,
    {
        let key = AsfaloadSecretKeys::from_bytes(data)?;
        Ok(SecretKey {
            key,
            location: PathBuf::new(), // Default location for bytes-based creation
        })
    }

    fn from_string(s: String) -> Result<Self, KeyError>
    where
        Self: Sized,
    {
        let key = AsfaloadSecretKeys::from_string(s)?;
        Ok(SecretKey {
            key,
            location: PathBuf::new(), // Default location for string-based creation
        })
    }

    fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, KeyError>
    where
        Self: Sized,
    {
        let path_ref = path.as_ref();
        let key = AsfaloadSecretKeys::from_file(path_ref, password)?;
        Ok(SecretKey {
            key,
            location: path_ref.to_path_buf(),
        })
    }
}

pub mod aggregate_signature_helpers {
    use std::{collections::HashMap, path::Path};

    use aggregate_signature::get_individual_signatures as get_individual_signatures_ori;
    pub use aggregate_signature::{check_groups, load_signers_config};
    use common::errors::AggregateSignatureError;
    use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
    use signatures::types::{AsfaloadPublicKeys, AsfaloadSignatures};

    pub fn get_individual_signatures<P: AsRef<Path>>(
        sig_file_path: P,
    ) -> Result<HashMap<AsfaloadPublicKeys, AsfaloadSignatures>, AggregateSignatureError>
    where
        AsfaloadPublicKeys: AsfaloadPublicKeyTrait<Signature = AsfaloadSignatures>,
        AsfaloadSignatures: AsfaloadSignatureTrait,
    {
        get_individual_signatures_ori::<AsfaloadPublicKeys, AsfaloadSignatures, _>(sig_file_path)
    }
}
