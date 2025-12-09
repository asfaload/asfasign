use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "client-cli")]
#[command(about = "A CLI client for Asfaload operations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new key pair in the directory of your choice
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
        ///
        /// Accept week passwords, bypassing password strength validations (INSECURE!)
        #[arg(long)]
        accept_weak_password: bool,
    },

    /// Sign a file with your private key
    SignFile {
        /// Path to the file to be signed
        #[arg(long)]
        file_to_sign: String,

        /// Path to the secret key file
        #[arg(long)]
        secret_key: String,

        /// Path where the signature file has to be written
        #[arg(long)]
        output_file: String,

        /// Password for the key (conflicts with password_file)
        #[arg(long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Path to a file containing the password (conflicts with password)
        #[arg(long, conflicts_with = "password")]
        password_file: Option<PathBuf>,

        /// Accept week passwords, bypassing password strength validations (INSECURE!)
        #[arg(long)]
        accept_weak_password: bool,
    },

    /// Operations related to signers files
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

const ENV_VAR_PREFIX: &str = "ASFALOAD";
enum EnvVarKind {
    Password,
    PasswordFile,
}
impl std::fmt::Display for EnvVarKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            EnvVarKind::Password => "password",
            EnvVarKind::PasswordFile => "password_file",
        };
        write!(f, "{}", s)
    }
}

impl Commands {
    // Fucntions to build environment variables for commands in a standard way
    fn env_var_base(&self) -> &str {
        match self {
            Self::SignFile { .. } => "SIGN_FILE",
            Self::NewSignersFile { .. } => "NEW_SIGNERS_FILE",
            Self::NewKeys { .. } => "NEW_KEYS",
        }
    }

    fn build_env_var(cmd: &Commands, kind: EnvVarKind) -> String {
        format!(
            "{ENV_VAR_PREFIX}_{}_{}",
            cmd.env_var_base(),
            kind.to_string().to_uppercase()
        )
    }
    pub fn password_env_var(&self) -> String {
        Self::build_env_var(self, EnvVarKind::Password)
    }

    pub fn password_file_env_var(&self) -> String {
        Self::build_env_var(self, EnvVarKind::PasswordFile)
    }
}
