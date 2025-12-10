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
        #[arg(long, short)]
        name: String,

        /// Directory to store the key
        #[arg(long, short)]
        output_dir: PathBuf,

        /// Password for the key (conflicts with password_file)
        #[arg(long, short, conflicts_with = "password_file")]
        password: Option<String>,

        /// Path to a file containing the password (conflicts with password)
        #[arg(long, short = 'P', conflicts_with = "password")]
        password_file: Option<PathBuf>,
        ///
        /// Accept week passwords, bypassing password strength validations (INSECURE!)
        #[arg(long)]
        accept_weak_password: bool,
    },

    /// Sign a file with your private key
    SignFile {
        /// Path to the file to be signed
        #[arg(long, short)]
        file_to_sign: PathBuf,

        /// Path to the secret key file
        #[arg(long, short = 'K')]
        secret_key: PathBuf,

        /// Path where the signature file has to be written
        #[arg(long, short)]
        output_file: PathBuf,

        /// Password for the key (conflicts with password_file)
        #[arg(long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Path to a file containing the password (conflicts with password)
        #[arg(long, short = 'P', conflicts_with = "password")]
        password_file: Option<PathBuf>,
    },

    /// Operations related to signers files
    NewSignersFile {
        /// Artifact signer public key as base64 string (can be repeated)
        #[arg(long, short)]
        artifact_signer: Vec<String>,

        /// Artifact signer public key file (can be repeated, combines with --artifact-signer)
        #[arg(long)]
        artifact_signer_file: Vec<PathBuf>,

        /// Threshold for artifact signers
        #[arg(long, short = 'A')]
        artifact_threshold: u32,

        /// Admin public key string as base64 string (can be repeated)
        #[arg(long, short = 'd')]
        admin_key: Vec<String>,

        /// Admin public key file (can be repeated, combines with --admin-key)
        #[arg(long)]
        admin_key_file: Vec<PathBuf>,

        /// Threshold for admin keys (required if admin keys are provided)
        #[arg(long, short = 'D')]
        admin_threshold: Option<u32>,

        /// Master public key string as base64 string (can be repeated)
        #[arg(long, short)]
        master_key: Vec<String>,

        /// Master public key file (can be repeated, combines with --master-key)
        #[arg(long)]
        master_key_file: Vec<PathBuf>,

        /// Threshold for master keys (required if master keys are provided)
        #[arg(long, short = 'M')]
        master_threshold: Option<u32>,

        /// Path to the signers file to be created
        #[arg(long, short)]
        output_file: PathBuf,
    },
    /// Verify a signature for a file
    VerifySig {
        /// Path to the signed file
        #[arg(long, short = 'f')]
        signed_file: PathBuf,

        /// Path to the signature file
        #[arg(long, short = 'x')]
        signature: PathBuf,

        /// Path to the public key file
        #[arg(long, short = 'k')]
        public_key: PathBuf,
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
            Self::VerifySig { .. } => "VERIFY_SIG",
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
