use std::path::Path;
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

pub trait ForgeTrait
where
    Self: Sized,
{
    fn new(url: &str) -> Result<Self, ForgeUrlError>;

    // Identity
    fn project_id(&self) -> String;

    // Accessors
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn branch(&self) -> &str;
    fn file_path(&self) -> &Path;
    fn raw_url(&self) -> &str;
}
