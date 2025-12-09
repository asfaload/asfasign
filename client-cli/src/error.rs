use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientCliError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Password confirmation does not match")]
    PasswordConfirmationError,

    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signers file error: {0}")]
    SignersFile(String),
}

pub type Result<T> = std::result::Result<T, ClientCliError>;
