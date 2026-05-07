use crate::commands::keys_helpers::share_pub_key_message;
use crate::output::ShareKeyOutput;
use anstream::println;
use anyhow::{Context, Result};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use std::path::Path;

pub fn handle_share_key_command(name: &str, dir: &Path, json: bool) -> Result<()> {
    let full_path = dir.join(name).with_added_extension("pub");
    let pk = AsfaloadPublicKeys::from_file(&full_path).context(format!(
        "Error loading public key from {}",
        full_path.display()
    ))?;
    let pk_string = pk.to_base64();
    if json {
        // Message without ansi escape characters for json
        let message = share_pub_key_message(&pk_string, false)?;
        let output = ShareKeyOutput {
            public_key: pk_string.clone(),
            message,
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        let message = share_pub_key_message(&pk_string, true)?;
        println!("{}", message);
    }
    Ok(())
}
