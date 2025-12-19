use std::path::Path;

use crate::error::Result;
use features_lib::sha512_for_file;
use features_lib::{AsfaloadPublicKeys, AsfaloadSignatures, AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};

pub fn handle_verify_sig_command<P: AsRef<Path>>(
    signed_file: &P,
    signature_file: &P,
    public_key_file: &P,
) -> Result<()> {
    // Load the public key
    let public_key = AsfaloadPublicKeys::from_file(public_key_file)?;

    // Load the signature
    let signature = AsfaloadSignatures::from_file(signature_file)?;

    // Compute the hash of the signed file
    let data_to_verify = sha512_for_file(signed_file)?;

    // Verify the signature
    public_key.verify(&signature, &data_to_verify)?;

    println!("Signature verification successful!");
    Ok(())
}

