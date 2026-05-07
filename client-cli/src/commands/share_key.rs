use anyhow::Result;
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use std::path::Path;

use crate::output::ShareKeyOutput;

pub fn handle_share_key_command(name: &String, dir: &Path, json: bool) -> Result<()> {
    let full_path = dir.join(name).with_added_extension("pub");
    println!("full path = {}", full_path.display());
    let pk = AsfaloadPublicKeys::from_file(full_path)?;
    let pk_string = pk.to_base64();
    if json {
        let output = ShareKeyOutput {
            public_key: pk_string.clone(),
            message: format!("my public_key = {}", pk_string),
        };
        println!("{}", serde_json::to_string(&output)?);
    }
    println!("{}", pk.to_base64());
    Ok(())
}
