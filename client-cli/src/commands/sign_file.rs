use crate::error::Result;
use features_lib::sha512_for_file;
use features_lib::{AsfaloadSecretKeys, AsfaloadSecretKeyTrait, AsfaloadSignatureTrait};
use std::path::Path;

pub fn handle_sign_file_command<P: AsRef<Path>>(
    file_to_sign: &P,
    secret_key: &P,
    password: &str,
    output_file: &P,
) -> Result<()> {
    let secret_key = AsfaloadSecretKeys::from_file(&secret_key, password)?;
    let data_to_sign = sha512_for_file(file_to_sign)?;
    let signature = secret_key.sign(&data_to_sign)?;
    signature.to_file(output_file)?;
    Ok(())
}
