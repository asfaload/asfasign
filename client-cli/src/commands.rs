use crate::{
    cli::{Cli, Commands},
    utils::get_password,
};

pub mod keys;
pub mod sign_file;
pub mod signers_file;
pub mod verify_sig;
use anyhow::Result;

/// Dispatches the command to the appropriate handler
pub fn handle_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::NewKeys {
            name,
            output_dir,
            password,
            password_file,
            accept_weak_password,
        } => {
            let password = get_password(
                password.clone(),
                password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                *accept_weak_password,
            )?;
            keys::handle_new_keys_command(name, output_dir, password)?;
        }
        Commands::SignFile {
            file_to_sign,
            secret_key,
            output_file,
            password,
            password_file,
            accept_weak_password,
        } => {
            let password = get_password(
                password.clone(),
                password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                *accept_weak_password,
            )?;
            sign_file::handle_sign_file_command(
                file_to_sign,
                secret_key,
                password.as_str(),
                output_file,
            )?
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
        Commands::VerifySig {
            signed_file,
            signature,
            public_key,
        } => {
            verify_sig::handle_verify_sig_command(signed_file, signature, public_key)?;
        }
    }
    Ok(())
}
