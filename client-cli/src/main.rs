use anyhow::Result;
use clap::Parser;
use client_cli::{cli::Cli, commands::handle_command};

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = handle_command(&cli) {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    Ok(())
}
