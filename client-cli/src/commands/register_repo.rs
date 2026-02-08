use crate::error::Result;

pub async fn handle_register_repo_command(
    backend_url: &str,
    signers_file_url: &str,
    json: bool,
) -> Result<()> {
    let response = crate::rest_client::register_repo(backend_url, signers_file_url).await?;

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
