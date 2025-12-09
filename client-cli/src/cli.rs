use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "client-cli")]
#[command(about = "A CLI client for cryptographic operations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Operations related to cryptographic keys
    NewKeys {
        /// Name of the key
        #[arg(long)]
        name: String,

        /// Directory to store the key
        #[arg(long)]
        output_dir: PathBuf,

        /// Password for the key (conflicts with password_file)
        #[arg(long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Path to a file containing the password (conflicts with password)
        #[arg(long, conflicts_with = "password")]
        password_file: Option<PathBuf>,
    },
    /// Operations related to signers file
    NewSignersFile {
        /// Artifact signer public key (can be repeated)
        #[arg(long)]
        artifact_signer: Vec<String>,

        /// Threshold for artifact signers
        #[arg(long)]
        artifact_threshold: u32,

        /// Admin public key (can be repeated)
        #[arg(long)]
        admin_key: Vec<String>,

        /// Threshold for admin keys
        #[arg(long)]
        admin_threshold: u32,

        /// Master public key (can be repeated)
        #[arg(long)]
        master_key: Vec<String>,

        /// Threshold for master keys
        #[arg(long)]
        master_threshold: u32,

        /// Directory to store the signers file
        #[arg(long)]
        output_dir: PathBuf,
    },
}
