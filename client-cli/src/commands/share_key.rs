use crate::commands::keys_helpers::share_pub_key_message;
use crate::output::ShareKeyOutput;
use anstream::println;
use anyhow::{Context, Result};
use features_lib::errors::keys::{KeyError, append_pub_extension};
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use std::path::Path;

pub fn handle_share_key_command(public_key: &Path, raw: bool, json: bool) -> Result<()> {
    let pk = match AsfaloadPublicKeys::from_file(public_key) {
        Ok(k) => k,
        Err(KeyError::ParseError(e)) => {
            // Even if we attempt a new .pub path, we report the original error
            let main_error = format!("Error loading public key from {}", public_key.display());
            let pub_path = append_pub_extension(public_key).with_context(|| main_error.clone())?;
            if pub_path.exists() {
                AsfaloadPublicKeys::from_file(pub_path).with_context(|| main_error)?
            } else {
                Err(KeyError::ParseError(e)).with_context(|| main_error)?
            }
        }
        Err(e) => return Err(e.into()),
    };
    let pk_string = pk.to_base64();
    match (raw, json) {
        (_, true) => {
            // Message without ansi escape characters for json
            let message = share_pub_key_message(&pk_string, false)?;
            let output = ShareKeyOutput {
                public_key: pk_string.clone(),
                message,
            };
            println!("{}", serde_json::to_string(&output)?);
        }
        (true, _) => {
            println!("{}", pk_string);
        }
        (_, _) => {
            let message = share_pub_key_message(&pk_string, true)?;
            println!("{}", message);
        }
    }
    Ok(())
}
