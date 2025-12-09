use std::path::Path;

use crate::utils::{ensure_dir_exists, get_password};
use anyhow::Result;
use features_lib::KeyPair;

/// Handles the `keys` command.
///
/// # Arguments
/// * `name` - The name of the key
/// * `output_dir` - The directory to store the key
/// * `password` - Password to protect the secret key
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
pub fn handle_new_keys_command(
    name: &str,
    output_dir: &Path,
    password: Option<String>,
    password_file: Option<&Path>,
) -> Result<()> {
    ensure_dir_exists(output_dir)?;

    let password = get_password(
        password,
        password_file,
        "ASFALOAD_NEW_KEYS_PASSWORD",
        "ASFALOAD_NEW_KEYS_PASSWORD_FILE",
        "Enter password: ",
    )?;

    println!(
        "Generating keypair with name '{}' in directory {:?}",
        name, output_dir
    );
    let kp = KeyPair::new(output_dir, name, password.as_str())?;

    println!(
        "Public key saved at {}.pub and secret key at {}",
        kp.location.to_string_lossy(),
        kp.location.to_string_lossy()
    );
    Ok(())
}
