use crate::error::Result;
use features_lib::AsfaloadSecretKeyTrait;
use features_lib::AsfaloadSecretKeys;

pub async fn handle_register_release_command(
    backend_url: &str,
    release_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
) -> Result<()> {
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;

    let response = crate::rest_client::register_release(
        backend_url,
        release_url,
        secret_key,
    )
    .await?;

    if response.success {
        println!("Release registered successfully!");
        if let Some(index_path) = response.index_file_path {
            println!("Index file path: {}", index_path);
        }
    } else {
        println!("Release registration failed: {}", response.message);
    }

    Ok(())
}
