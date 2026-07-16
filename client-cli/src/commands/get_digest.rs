use std::path::PathBuf;

use common::{sha512_for_file, sha512_for_url};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct GetDigestOutput {
    digest: String,
}

pub async fn handle_get_digest_command(file: &str, json: bool) -> anyhow::Result<()> {
    let parsing_result = url::Url::parse(file);
    let digest = match parsing_result {
        Ok(parsed_url) => sha512_for_url(parsed_url).await,
        Err(_e) => {
            // If url couldn't parse we suppose we work on a file path
            let p = PathBuf::from(file);
            if p.exists() {
                sha512_for_file(p)
            } else {
                Err(std::io::Error::other(format!("File not found at {}", file)))
            }
        }
    }?;
    if json {
        let output = GetDigestOutput {
            digest: digest.to_string(),
        };
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("{}", digest);
    }
    Ok(())
}
