use crate::cli::{Cli, Commands};

pub mod keys;
pub mod signers_file;
use anyhow::Result;

/// Dispatches the command to the appropriate handler
pub fn handle_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::NewKeys {
            name,
            output_dir,
            password,
            password_file,
        } => {
            keys::handle_new_keys_command(
                name,
                output_dir,
                password.clone(),
                password_file.as_deref(),
            )?;
        }
        Commands::NewSignersFile {
            artifact_signer,
            artifact_threshold,
            admin_key,
            admin_threshold,
            master_key,
            master_threshold,
            output_dir,
        } => {
            signers_file::handle_new_signers_file_command(
                artifact_signer,
                *artifact_threshold,
                admin_key,
                *admin_threshold,
                master_key,
                *master_threshold,
                output_dir,
            )?;
        }
    }
    Ok(())
}
