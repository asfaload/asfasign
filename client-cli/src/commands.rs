use crate::{
    cli::{Cli, Commands, DEFAULT_BACKEND},
    utils::{
        PasswordConfirmation::{RequireConfirmation, WithoutConfirmation},
        get_password,
    },
};

pub mod add_to_aggregate;
pub mod is_agg_complete;
pub mod keys;
pub mod list_pending;
pub mod sign_file;
pub mod sign_pending;
pub mod signers_file;
pub mod verify_sig;
use anyhow::Result;

pub mod download;
pub mod register_release;
pub mod register_repo;

/// Dispatches the command to the appropriate handler
pub fn handle_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::NewKeys {
            name,
            output_dir,
            password_args,
            accept_weak_password,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                RequireConfirmation,
                *accept_weak_password,
            )?;
            keys::handle_new_keys_command(name, output_dir, password, json_args.json)?;
        }
        Commands::SignFile {
            file_to_sign,
            secret_key_args,
            output_file,
            password_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                // As this is the use of a password, and not the setup,
                // we don't ask for a confirmation
                WithoutConfirmation,
                // We accept weak password because this the use of a
                // password, makes no sense to prevent use of weak password here
                true,
            )?;
            sign_file::handle_sign_file_command(
                file_to_sign,
                &secret_key_args.secret_key,
                password.as_str(),
                output_file,
            )?
        }
        Commands::NewSignersFile {
            artifact_signer,
            artifact_signer_file,
            artifact_threshold,
            admin_key,
            admin_key_file,
            admin_threshold,
            master_key,
            master_key_file,
            master_threshold,
            output_file,
            json_args,
        } => {
            signers_file::handle_new_signers_file_command(
                artifact_signer,
                artifact_signer_file,
                *artifact_threshold,
                admin_key,
                admin_key_file,
                admin_threshold.as_ref().copied(),
                master_key,
                master_key_file,
                master_threshold.as_ref().copied(),
                output_file,
                json_args.json,
            )?;
        }
        Commands::VerifySig {
            signed_file,
            signature,
            public_key,
            json_args,
        } => {
            verify_sig::handle_verify_sig_command(
                signed_file,
                signature,
                public_key,
                json_args.json,
            )?;
        }
        Commands::AddToAggregate {
            signed_file,
            secret_key_args,
            password_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            add_to_aggregate::handle_add_to_aggregate_command(
                signed_file,
                &secret_key_args.secret_key,
                password.as_str(),
            )?;
        }
        Commands::IsAggComplete {
            signed_file,
            signatures_file,
            signers_file,
            json_args,
        } => {
            is_agg_complete::handle_is_agg_complete_command(
                signed_file,
                signatures_file,
                signers_file,
                json_args.json,
            )?;
        }
        Commands::ListPending {
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(list_pending::handle_list_pending_command(
                &url,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::SignPending {
            file_path,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(sign_pending::handle_sign_pending_command(
                file_path,
                &url,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::RegisterRelease {
            release_url,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(register_release::handle_register_release_command(
                &url,
                release_url,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?
        }
        Commands::RegisterRepo {
            signers_file_url,
            backend_url_args,
            json_args,
        } => {
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(register_repo::handle_register_repo_command(
                &url,
                signers_file_url,
                json_args.json,
            ))?;
        }
        Commands::Download {
            file_url,
            output,
            backend_url_args,
        } => {
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(download::handle_download_command(
                file_url,
                output.as_ref(),
                &url,
            ))?;
        }
    }
    Ok(())
}
