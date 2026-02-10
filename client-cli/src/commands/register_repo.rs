use crate::error::Result;
use features_lib::{
    AsfaloadPublicKeyTrait, AsfaloadPublicKeys, AsfaloadSecretKeyTrait, AsfaloadSecretKeys,
    sha512_for_content,
};

pub async fn handle_register_repo_command(
    backend_url: &str,
    signers_file_url: &str,
    secret_key_path: &std::path::PathBuf,
    password: &str,
    json: bool,
) -> Result<()> {
    // Load secret key and derive public key
    let secret_key = AsfaloadSecretKeys::from_file(secret_key_path, password)?;
    let public_key = AsfaloadPublicKeys::from_secret_key(&secret_key)?;

    let client = admin_lib::v1::Client::new(backend_url);

    // Generate signature of signers file that we submit
    let content = client.fetch_external_url(signers_file_url).await?;
    let hash = sha512_for_content(content)?;
    let signature = secret_key.sign(&hash)?;

    // Submit to backend
    let response = client
        .register_repo(signers_file_url, &signature, &public_key, &secret_key)
        .await?;

    if json {
        println!("{}", serde_json::to_string(&response)?);
    } else if response.success {
        println!("Repository registered successfully!");
        println!("Project ID: {}", response.project_id);
        println!(
            "Required signers ({}): {}",
            response.required_signers.len(),
            response.required_signers.join(", ")
        );
        println!("Next step: signers must submit signatures to activate the project.");
    } else {
        println!("Repository registration failed: {}", response.message);
    }

    Ok(())
}
