use crate::error::Result;
use features_lib::sha512_for_file;
use features_lib::AsfaloadSignatureTrait;
use features_lib::SecretKey;
use features_lib::SecretKeyTrait;
use features_lib::{PublicKey, PublicKeyTrait};
use std::path::Path;

pub fn handle_add_to_aggregate_command<P: AsRef<Path>>(
    signed_file: &P,
    secret_key: &P,
    password: &str,
) -> Result<()> {
    // Load the secret key
    let secret_key = SecretKey::from_file(secret_key, password)?;

    // Compute the AsfaloadHash of the file
    let data_to_sign = sha512_for_file(signed_file)?;

    // Sign the data with the secret key
    let signature = secret_key.key.sign(&data_to_sign)?;

    // Derive the public key from the secret key
    let public_key = PublicKey::<minisign::PublicKey>::from_secret_key(secret_key.key)?;

    // Add the signature to the aggregate for the file
    signature.add_to_aggregate_for_file(signed_file, &public_key)?;

    Ok(())
}
