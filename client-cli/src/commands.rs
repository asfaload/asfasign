use crate::{
    cli::{Cli, Commands, DEFAULT_BACKEND},
    utils::{
        PasswordConfirmation::{RequireConfirmation, WithoutConfirmation},
        get_password,
    },
};

pub mod keys;
pub mod list_pending;
pub mod share_key;
pub mod sign_pending;
pub mod signature_status;
pub mod signers_file;
use anyhow::Result;

pub mod download;
pub mod ping;
pub mod register_assets;
pub mod register_repo;
pub mod revoke;
pub mod update_signers;

/// Shared state produced by loading keys and creating a client,
/// used by both `register-repo` and `update-signers`.
pub(crate) struct PreparedSignersSubmission {
    pub client: admin_lib::v1::Client,
    pub public_key: features_lib::AsfaloadPublicKeys,
    pub secret_key: features_lib::AsfaloadSecretKeys,
}

/// Load secret key, derive public key, and create an API client.
/// The caller then decides which API endpoint to call with the result.
pub(crate) async fn prepare_signers_submission(
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
) -> crate::error::Result<PreparedSignersSubmission> {
    use features_lib::{AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait, AsfaloadSecretKeys};

    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key)?;
    let client = admin_lib::v1::Client::new(backend_url);

    Ok(PreparedSignersSubmission {
        client,
        public_key,
        secret_key,
    })
}

pub(crate) mod keys_helpers {

    use anstyle::Style;
    const BOLD: Style = Style::new().bold();
    const UNDERLINE: Style = Style::new().underline();
    use std::fmt::Write;
    pub fn share_pub_key_message(public_key: &str, with_ansi: bool) -> anyhow::Result<String> {
        // Define conditional bolds un case we want non-ansi output, like in json
        let bold = if with_ansi { BOLD } else { Style::new() };
        let underline = if with_ansi { UNDERLINE } else { Style::new() };

        let mut buf = String::new();
        writeln!(
            buf,
            "{bold}The public key is safe to share{bold:#} -- that's how others verify your signatures."
        )?;
        writeln!(buf,)?;
        writeln!(
            buf,
            "{underline}You can share your public key, for example with an admin, with this message:{underline:#}"
        )?;
        writeln!(buf,)?;
        writeln!(
            buf,
            "    I have a key-pair to use with Asfaload. You can use my public"
        )?;
        writeln!(buf, "    key in signers files. Here it is:")?;
        writeln!(buf, "    {public_key}")?;
        Ok(buf)
    }
}

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
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                RequireConfirmation,
                *accept_weak_password,
            )?;
            keys::handle_new_keys_command(name, output_dir, password, json_args.json)?;
        }
        Commands::ShareKey {
            public_key,
            raw,
            json_args,
        } => {
            share_key::handle_share_key_command(public_key, *raw, json_args.json)?;
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
            revocation_key,
            revocation_key_file,
            revocation_threshold,
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
                revocation_key,
                revocation_key_file,
                revocation_threshold.as_ref().copied(),
                output_file,
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
                password_args.password_command.clone(),
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
                password_args.password_command.clone(),
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
        Commands::SignatureStatus {
            file_path,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
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
            runtime.block_on(signature_status::handle_signature_status_command(
                file_path,
                &url,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::RegisterRepo {
            signers_file_url,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
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
            runtime.block_on(register_repo::handle_register_repo_command(
                &url,
                signers_file_url,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::RegisterAssets {
            github_release_url,
            csum_file,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
                &cli.command.password_env_var(),
                &cli.command.password_file_env_var(),
                "Enter password: ",
                WithoutConfirmation,
                true,
            )?;
            let backend = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());

            let mode = register_assets::determine_registration_mode(github_release_url, csum_file)?;

            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(register_assets::handle_register_assets_command(
                &backend,
                mode,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::UpdateSigners {
            signers_file_url,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
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
            runtime.block_on(update_signers::handle_update_signers_command(
                &url,
                signers_file_url,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::Revoke {
            file_path,
            secret_key_args,
            password_args,
            backend_url_args,
            json_args,
        } => {
            let password = get_password(
                password_args.password.clone(),
                password_args.password_file.as_deref(),
                password_args.password_command.clone(),
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
            runtime.block_on(revoke::handle_revoke_command(
                &url,
                file_path,
                &secret_key_args.secret_key,
                password.as_str(),
                json_args.json,
            ))?;
        }
        Commands::Ping {
            secret_key,
            password_args,
            backend_url_args,
            json_args,
        } => {
            // The password is only needed when a secret key is used
            let password = match secret_key {
                Some(_) => Some(get_password(
                    password_args.password.clone(),
                    password_args.password_file.as_deref(),
                    password_args.password_command.clone(),
                    &cli.command.password_env_var(),
                    &cli.command.password_file_env_var(),
                    "Enter password: ",
                    WithoutConfirmation,
                    true,
                )?),
                None => None,
            };
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(ping::handle_ping_command(
                &url,
                secret_key.as_ref(),
                password.as_deref(),
                json_args.json,
            ))?;
        }
        Commands::Download {
            file_url,
            output,
            backend_url_args,
            forge_type_args,
        } => {
            let url = backend_url_args
                .backend_url
                .clone()
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
            let forge_type_str = forge_type_args.forge_type.as_ref().map(|ft| ft.as_str());
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(download::handle_download_command(
                file_url,
                output.as_ref(),
                &url,
                forge_type_str,
            ))?;
        }
    }
    Ok(())
}
