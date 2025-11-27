use aggregate_signature::{SignatureWithState, load_for_file};
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

impl<P, S> SignedFileTrait<P, S> for SignedFile<InitialSignersFileMarker>
where
    P: AsfaloadPublicKeyTrait<Signature = S>,
    S: AsfaloadSignatureTrait + Clone,
{
    fn add_signature(
        &self,
        sig: S,
        pubkey: P,
    ) -> Result<SignatureWithState<P, S>, SignedFileError> {
        sign_signers_file(&self.location, &sig, &pubkey).map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = load_for_file::<P, S, _>(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}

impl<P, S> SignedFileTrait<P, S> for SignedFile<SignersFileMarker>
where
    P: AsfaloadPublicKeyTrait<Signature = S>,
    S: AsfaloadSignatureTrait + Clone,
{
    fn add_signature(
        &self,
        sig: S,
        pubkey: P,
    ) -> Result<SignatureWithState<P, S>, SignedFileError> {
        sign_signers_file(&self.location, &sig, &pubkey).map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = load_for_file::<P, S, _>(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}
impl<P, S> SignedFileTrait<P, S> for SignedFile<ArtifactMarker>
where
    P: AsfaloadPublicKeyTrait<Signature = S>,
    S: AsfaloadSignatureTrait + Clone,
{
    fn add_signature(
        &self,
        sig: S,
        pubkey: P,
    ) -> Result<SignatureWithState<P, S>, SignedFileError> {
        load_for_file::<P, S, _>(&self.location)?
            .get_pending()
            .expect("Expected pending agg sig here")
            .add_individual_signature(&sig, &pubkey)
            .map_err(|e| e.into())
    }

    fn is_signed(&self) -> Result<bool, SignedFileError> {
        let r = load_for_file::<AsfaloadPublicKey<_>, AsfaloadSignature<_>, _>(&self.location)?
            .get_complete()
            .is_some();
        Ok(r)
    }
}
