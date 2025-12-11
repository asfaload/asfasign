use std::path::{Path, PathBuf};

pub use common::errors;
pub use common::{
    ArtifactMarker, FileType, InitialSignersFileMarker, SignedFile, SignersFileMarker,
    errors::SignedFileError,
};
pub use common::{SignedFileLoader, SignedFileWithKind};
use common::{
    errors::keys::KeyError,
    fs::names::{find_global_signers_for, pending_signers_file_in_dir},
};

pub use common::{AsfaloadHashes, sha512_for_content, sha512_for_file};

use signatures::keys::{
    AsfaloadKeyPairTrait, AsfaloadPublicKey, AsfaloadPublicKeyTrait, AsfaloadSecretKey,
    AsfaloadSignature,
};

pub use signatures::keys::AsfaloadPublicKey as PublicKey;
pub use signatures::keys::AsfaloadPublicKeyTrait as PublicKeyTrait;
pub use signatures::keys::AsfaloadSecretKeyTrait as SecretKeyTrait;
pub use signatures::keys::AsfaloadSignature as Signature;
pub use signatures::keys::AsfaloadSignatureTrait as SignatureTrait;

pub use signers_file_types::SignersConfig;

use signatures::keys::AsfaloadKeyPair;
pub use signatures::keys::AsfaloadSignatureTrait;
use signers_file::sign_signers_file;

// In this type argument we constrain the type argument of the SignatureWithState type
// to AsfaloadPublicKey and AsfaloadSignature. Doing this allows the user of this
// type to not specify the type arguments, makeing the code more succint.
pub type SignatureWithState<MP, MS> =
    aggregate_signature::SignatureWithState<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>;

// We define and implement this trait in the user_lib as it depends on traits defined in other crates,
// which we want to avoid in common.
pub trait SignedFileTrait<MP, MS>
where
    AsfaloadPublicKey<MP>: AsfaloadPublicKeyTrait<Signature = AsfaloadSignature<MS>>,
    AsfaloadSignature<MS>: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignature<MS>,
        pubkey: AsfaloadPublicKey<MP>,
    ) -> Result<SignatureWithState<MP, MS>, SignedFileError>;
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

impl<MP, MS, T> SignedFileTrait<MP, MS> for SignedFile<T>
where
    T: SignableFileMarker,
    MP: Clone,
    MS: Clone,
    AsfaloadPublicKey<MP>: AsfaloadPublicKeyTrait<Signature = AsfaloadSignature<MS>>,
    AsfaloadSignature<MS>: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignature<MS>,
        pubkey: AsfaloadPublicKey<MP>,
    ) -> Result<SignatureWithState<MP, MS>, SignedFileError> {
        sign_signers_file(&self.location, &sig, &pubkey).map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = SignatureWithState::<MP, MS>::load_for_file(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl<MP, MS> SignedFileTrait<MP, MS> for SignedFile<ArtifactMarker>
where
    MP: Clone,
    MS: Clone,
    AsfaloadPublicKey<MP>: AsfaloadPublicKeyTrait<Signature = AsfaloadSignature<MS>>,
    AsfaloadSignature<MS>: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignature<MS>,
        pubkey: AsfaloadPublicKey<MP>,
    ) -> Result<SignatureWithState<MP, MS>, SignedFileError> {
        let agg_sig_with_state = SignatureWithState::<MP, MS>::load_for_file(&self.location)?;
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

pub trait SignedFileWithKindTrait<MP, MS>
where
    MP: Clone,
    MS: Clone,
    AsfaloadPublicKey<MP>: AsfaloadPublicKeyTrait<Signature = AsfaloadSignature<MS>>,
    AsfaloadSignature<MS>: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignature<MS>,
        pubkey: AsfaloadPublicKey<MP>,
    ) -> Result<SignatureWithState<MP, MS>, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

impl<MP, MS> SignedFileWithKindTrait<MP, MS> for SignedFileWithKind
where
    MP: Clone,
    MS: Clone,
    AsfaloadPublicKey<MP>: AsfaloadPublicKeyTrait<Signature = AsfaloadSignature<MS>>,
    AsfaloadSignature<MS>: AsfaloadSignatureTrait,
{
    fn add_signature(
        &self,
        sig: AsfaloadSignature<MS>,
        pubkey: AsfaloadPublicKey<MP>,
    ) -> Result<SignatureWithState<MP, MS>, SignedFileError> {
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

pub struct KeyPair<M> {
    pub location: PathBuf,
    pub keypair: AsfaloadKeyPair<M>,
}
impl<M> KeyPair<M>
where
    // This Higher-Rank Trait Bound states that AsfaloadKeyPair<M> must implement
    // AsfaloadKeyPairTrait for *any* lifetime 'a.
    AsfaloadKeyPair<M>: for<'a> AsfaloadKeyPairTrait<'a>,
{
    pub fn new<P: AsRef<Path>>(dir: P, name: &str, password: &str) -> Result<Self, KeyError> {
        let keypair = AsfaloadKeyPair::new(password)?;
        let location = dir.as_ref().join(name);
        keypair.save(&location)?;
        Ok(KeyPair::<M> { keypair, location })
    }
}

pub struct SecretKey<M> {
    pub location: PathBuf,
    pub key: AsfaloadSecretKey<M>,
}
impl<M> SecretKey<M>
where
    AsfaloadSecretKey<M>: SecretKeyTrait,
{
    pub fn from_file<P: AsRef<Path>>(location: P, password: &str) -> Result<Self, KeyError> {
        let key = AsfaloadSecretKey::from_file(&location, password)?;
        Ok(SecretKey::<M> {
            key,
            location: location.as_ref().to_path_buf(),
        })
    }
}

pub mod aggregate_signature_helpers {
    use std::{collections::HashMap, path::Path};

    use aggregate_signature::get_individual_signatures as get_individual_signatures_ori;
    pub use aggregate_signature::{check_groups, load_signers_config};
    use common::errors::AggregateSignatureError;
    use signatures::keys::{
        AsfaloadPublicKey, AsfaloadPublicKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
    };

    pub fn get_individual_signatures<P: AsRef<Path>, MP: Clone, MS: Clone>(
        sig_file_path: P,
    ) -> Result<HashMap<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>, AggregateSignatureError>
    where
        AsfaloadPublicKey<MP>: AsfaloadPublicKeyTrait<Signature = AsfaloadSignature<MS>>,
        AsfaloadSignature<MS>: AsfaloadSignatureTrait,
    {
        get_individual_signatures_ori::<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>, _>(
            sig_file_path,
        )
    }
}
