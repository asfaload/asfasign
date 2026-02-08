use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Default backend API URL
pub const DEFAULT_BACKEND: &str = "http://127.0.0.1:3000";

#[derive(clap::Args, Debug)]
pub struct PasswordArgs {
    /// Password for the key (conflicts with password_file)
    #[arg(long, short, conflicts_with = "password_file")]
    pub password: Option<String>,

    /// Path to a file containing the password (conflicts with password)
    #[arg(long, short = 'P', conflicts_with = "password")]
    pub password_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct SecretKeyArgs {
    /// Path to your secret key file
    #[arg(short = 'K', long)]
    pub secret_key: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct BackendUrlArgs {
    /// Backend API URL (optional, defaults to DEFAULT_BACKEND)
    #[arg(short = 'u', long)]
    pub backend_url: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct JsonArgs {
    /// Output results as JSON
    #[arg(long)]
    pub json: bool,
}

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

        #[command(flatten)]
        password_args: PasswordArgs,
        ///
        /// Accept week passwords, bypassing password strength validations (INSECURE!)
        #[arg(long)]
        accept_weak_password: bool,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Sign a file with your private key
    SignFile {
        /// Path to the file to be signed
        #[arg(long, short)]
        file_to_sign: PathBuf,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        /// Path where the signature file has to be written
        #[arg(long, short)]
        output_file: PathBuf,

        #[command(flatten)]
        password_args: PasswordArgs,
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

        #[command(flatten)]
        json_args: JsonArgs,
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

        #[command(flatten)]
        json_args: JsonArgs,
    },
    /// Add a signature to the aggregate signature for a file.
    /// If you add your signature to an existing aggregate signature,
    /// its file name must be identitical to the signed file, but with
    /// added suffix .signatures.json.pending.
    AddToAggregate {
        /// Path to the signed file
        #[arg(long, short = 'f')]
        signed_file: PathBuf,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,
    },
    /// Check if the aggregate signature for a file is complete
    IsAggComplete {
        /// Path to the signed file
        #[arg(long, short = 'f')]
        signed_file: PathBuf,

        /// Path to the signatures file
        #[arg(long, short = 'x')]
        signatures_file: PathBuf,

        /// Path to the signers file
        #[arg(long, short = 's')]
        signers_file: PathBuf,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// List files requiring your signature from the backend
    ListPending {
        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Sign a pending file (fetch, sign, submit)
    SignPending {
        /// Path to the pending file (relative path in mirror)
        file_path: String,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Register a GitHub release with the backend
    RegisterRelease {
        /// URL of the GitHub release to register
        release_url: String,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Register a repository with the backend
    RegisterRepo {
        /// URL to the signers file (e.g., https://raw.githubusercontent.com/owner/repo/branch/asfaload.signers/index.json)
        signers_file_url: String,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Download a file with signature verification
    Download {
        /// URL of the file to download (e.g., https://github.com/user/repo/releases/download/v1.0.0/file.tar.gz)
        file_url: String,

        /// Output file path (optional, defaults to filename from URL)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,
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
            Self::AddToAggregate { .. } => "ADD_TO_AGGREGATE",
            Self::IsAggComplete { .. } => "IS_AGG_COMPLETE",
            Self::ListPending { .. } => "LIST_PENDING",
            Self::SignPending { .. } => "SIGN_PENDING",
            Self::RegisterRelease { .. } => "REGISTER_RELEASE",
            Self::RegisterRepo { .. } => "REGISTER_REPO",
            Self::Download { .. } => "DOWNLOAD",
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

    pub fn json_output(&self) -> bool {
        match self {
            Self::NewKeys { json_args, .. }
            | Self::NewSignersFile { json_args, .. }
            | Self::VerifySig { json_args, .. }
            | Self::IsAggComplete { json_args, .. }
            | Self::ListPending { json_args, .. }
            | Self::SignPending { json_args, .. }
            | Self::RegisterRelease { json_args, .. }
            | Self::RegisterRepo { json_args, .. } => json_args.json,
            Self::SignFile { .. } | Self::AddToAggregate { .. } | Self::Download { .. } => false,
        }
    }
}
