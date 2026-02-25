use crate::error::Result;
use admin_lib::v1::RegistrationMode;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;

pub async fn handle_register_assets_command(
    backend_url: &str,
    mode: RegistrationMode,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.register_assets(&mode, &secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Assets registered successfully! Remember you still need to sign it yourself!");
        if let Some(index_path) = response.index_file_path {
            println!("Index file path: {}", index_path);
        }
    } else {
        println!("Asset registration failed: {}", response.message);
    }

    Ok(())
}
