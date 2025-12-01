use aggregate_signature::{SignatureWithState, load_for_file};
use common::SignedFileWithKind;
pub use common::{
    ArtifactMarker, InitialSignersFileMarker, SignedFile, SignersFileMarker,
    errors::SignedFileError,
};
use signatures::keys::{
    AsfaloadPublicKey, AsfaloadPublicKeyTrait, AsfaloadSignature, AsfaloadSignatureTrait,
};
use signers_file::sign_signers_file;

// We define and implement this trait in the user_lib as it depends on traits defined in other crates,
// which we want to avoid in common.
pub trait SignedFileTrait<P, S>
where
    P: AsfaloadPublicKeyTrait,
    S: AsfaloadSignatureTrait,
{
    fn add_signature(&self, sig: S, pubkey: P)
    -> Result<SignatureWithState<P, S>, SignedFileError>;
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

impl<MP, MS, T> SignedFileTrait<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>> for SignedFile<T>
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
    ) -> Result<SignatureWithState<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>, SignedFileError>
    {
        sign_signers_file(&self.location, &sig, &pubkey).map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = load_for_file::<AsfaloadPublicKey<MP>, _, _>(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl<MP, MS> SignedFileTrait<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>
    for SignedFile<ArtifactMarker>
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
    ) -> Result<SignatureWithState<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>, SignedFileError>
    {
        let agg_sig_with_state =
            load_for_file::<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>, _>(&self.location)?;
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
        let r = load_for_file::<AsfaloadPublicKey<_>, AsfaloadSignature<_>, _>(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

pub trait SignedFileWithKindTrait<P, S>
where
    P: AsfaloadPublicKeyTrait,
    S: AsfaloadSignatureTrait,
{
    fn add_signature(&self, sig: S, pubkey: P)
    -> Result<SignatureWithState<P, S>, SignedFileError>;
    fn is_signed(&self) -> Result<bool, SignedFileError>;
}

impl<MP, MS> SignedFileWithKindTrait<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>
    for SignedFileWithKind
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
    ) -> Result<SignatureWithState<AsfaloadPublicKey<MP>, AsfaloadSignature<MS>>, SignedFileError>
    {
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
