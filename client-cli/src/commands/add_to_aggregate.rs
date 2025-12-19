use crate::error::Result;
use features_lib::sha512_for_file;
use features_lib::{AsfaloadPublicKeys, AsfaloadSecretKeys};
use signatures::keys::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};
use std::path::Path;

pub fn handle_add_to_aggregate_command<P: AsRef<Path>>(
    signed_file: &P,
    secret_key: &P,
    password: &str,
) -> Result<()> {
    // Load the secret key
    let secret_key = AsfaloadSecretKeys::from_file(&secret_key, password)?;

    // Compute the AsfaloadHash of the file
    let data_to_sign = sha512_for_file(signed_file)?;

    // Sign the data with the secret key
    let signature = secret_key.sign(&data_to_sign)?;

    let public_key = AsfaloadPublicKeys::from_secret_key(secret_key)?;

    // Add the signature to the aggregate for the file
    signature.add_to_aggregate_for_file(signed_file, &public_key)?;

    Ok(())
}
