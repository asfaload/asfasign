use anyhow::Result;
use clap::Parser;
use client_cli::{cli::Cli, commands::handle_command, output::JsonError};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = cli.command.json_output();

    if let Err(e) = handle_command(&cli) {
        if json {
            let json_err = JsonError {
                error: e.to_string(),
            };
            eprintln!(
                "{}",
                serde_json::to_string(&json_err).unwrap_or_else(|_| {
                    // This fallback ensures we always output valid JSON, even if serializing
                    // the original error fails. It avoids injecting a raw error string
                    // that might contain characters that would break the JSON structure.
                    r#"{"error":"An unexpected error occurred and it could not be serialized."}"#
                        .to_string()
                })
            );
        } else {
            eprintln!("{}", e);
        }
        std::process::exit(1);
    }

    Ok(())
}
