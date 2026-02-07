use std::path::Path;

use crate::output::NewKeysOutput;
use crate::utils::ensure_dir_exists;
use anyhow::Result;
use features_lib::{AsfaloadKeyPairTrait, AsfaloadKeyPairs};

/// Handles the `keys` command.
///
/// # Arguments
/// * `name` - The name of the key
/// * `output_dir` - The directory to store the key
/// * `password` - Password to protect the secret key
/// * `json` - Whether to output results as JSON
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
pub fn handle_new_keys_command(
    name: &str,
    output_dir: &Path,
    password: String,
    json: bool,
) -> Result<()> {
    ensure_dir_exists(output_dir)?;

    if !json {
        println!(
            "Generating keypair with name '{}' in directory {:?}",
            name, output_dir
        );
    }
    let kp = AsfaloadKeyPairs::new(password.as_str())?;
    let location = output_dir.join(name);
    kp.save(&location)?;

    if json {
        let output = NewKeysOutput {
            public_key_path: format!("{}.pub", location.to_string_lossy()),
            secret_key_path: location.to_string_lossy().to_string(),
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!(
            "Public key saved at {}.pub and secret key at {}",
            location.to_string_lossy(),
            location.to_string_lossy()
        );
    }
    Ok(())
}
