use std::path::PathBuf;

use anyhow::Result;

/// Handle the download command
pub async fn handle_download_command(
    file_url: &str,
    output: Option<&PathBuf>,
    backend_url: &str,
) -> Result<()> {
    client_lib::download_file_with_verification(file_url, output, backend_url)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
}
