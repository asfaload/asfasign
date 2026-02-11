use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForgeUrlError {
    #[error("Invalid Forge URL format: {0}")]
    InvalidFormat(String),
    #[error("Missing branch in URL")]
    MissingBranch,
    #[error("Missing file path in URL")]
    MissingFilePath,
}
