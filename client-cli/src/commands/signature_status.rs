use crate::error::Result;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;

/// Handle the signature-status command.
///
/// Queries the backend for the signature collection status of a file.
/// The caller must be an authorized signer for the file.
pub async fn handle_signature_status_command(
    file_path: &str,
    backend_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.get_signature_status(file_path, &secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.is_complete {
        println!("{}: complete", response.file_path);
    } else {
        println!("{}: pending", response.file_path);
    }

    Ok(())
}
