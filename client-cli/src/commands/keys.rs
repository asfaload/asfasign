use std::path::Path;

use crate::utils::ensure_dir_exists;
use anyhow::Result;

/// Handles the `keys` command.
///
/// # Arguments
/// * `name` - The name of the key
/// * `output_dir` - The directory to store the key
///
/// # Returns
/// * `Result<()>` - Ok if the command was handled successfully, Err otherwise
pub fn handle_new_keys_command(name: &str, output_dir: &Path) -> Result<()> {
    ensure_dir_exists(output_dir)?;

    // TODO: Implement key generation logic
    println!(
        "Generating key with name '{}' in directory {:?}",
        name, output_dir
    );

    Ok(())
}
