use crate::error::Result;
use features_lib::sha512_for_file;
use features_lib::AsfaloadSignatureTrait;
use features_lib::SecretKey;
use features_lib::SecretKeyTrait;
use std::path::Path;

pub fn handle_sign_file_command<P: AsRef<Path>>(
    file_to_sign: &P,
    secret_key: &P,
    password: &str,
    output_file: &P,
) -> Result<()> {
    let secret_key = SecretKey::from_file(secret_key, password)?;
    let data_to_sign = sha512_for_file(file_to_sign)?;
    let signature = secret_key.key.sign(&data_to_sign)?;
    let b64 = signature.to_base64();
    std::fs::write(output_file, b64)?;
    Ok(())
}
