use crate::error::Result;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;

pub async fn handle_register_directory_command(
    backend_url: &str,
    urls: &[String],
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    if urls.is_empty() {
        return Err(crate::error::ClientCliError::InvalidInput(
            "At least one --url must be provided".to_string(),
        ));
    }

    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    let client = admin_lib::v1::Client::new(backend_url);
    let response = client.register_directory(urls, &secret_key).await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Directory registered successfully! Remember you still need to sign it yourself!");
        if let Some(index_path) = response.index_file_path {
            println!("Index file path: {}", index_path);
        }
    } else {
        println!("Directory registration failed: {}", response.message);
    }

    Ok(())
}
