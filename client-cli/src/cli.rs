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
        file_to_sign: String,

        /// Path to the secret key file
        #[arg(long, short = 'K')]
        secret_key: String,

        /// Path where the signature file has to be written
        #[arg(long, short)]
        output_file: String,

        /// Password for the key (conflicts with password_file)
        #[arg(long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Path to a file containing the password (conflicts with password)
        #[arg(long, short = 'P', conflicts_with = "password")]
        password_file: Option<PathBuf>,
    },

    /// Operations related to signers files
    NewSignersFile {
        /// Artifact signer public key (can be repeated)
        #[arg(long, short)]
        artifact_signer: Vec<String>,

        /// Threshold for artifact signers
        #[arg(long, short = 'A')]
        artifact_threshold: u32,

        /// Admin public key (can be repeated)
        #[arg(long, short = 'd')]
        admin_key: Vec<String>,

        /// Threshold for admin keys
        #[arg(long, short = 'D')]
        admin_threshold: u32,

        /// Master public key (can be repeated)
        #[arg(long, short)]
        master_key: Vec<String>,

        /// Threshold for master keys
        #[arg(long, short = 'M')]
        master_threshold: u32,

        /// Directory to store the signers file
        #[arg(long, short)]
        output_dir: PathBuf,
    },
    /// Verify a signature for a file
    VerifySig {
        /// Path to the signed file
        #[arg(long, short = 'f')]
        signed_file: String,

        /// Path to the signature file
        #[arg(long, short = 'x')]
        signature: String,

        /// Path to the public key file
        #[arg(long, short = 'k')]
        public_key: String,
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
