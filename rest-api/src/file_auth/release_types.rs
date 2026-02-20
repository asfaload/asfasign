use crate::{file_auth::releasers::ReleaseInfos, path_validation::NormalisedPaths};
use rest_api_types::errors::ApiError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("Invalid release URL format: {0}")]
    ReleaseUrlError(#[from] ReleaseUrlError),
    #[error("Client error: {0}")]
    ClientError(String),
}

#[derive(Debug, Error)]
pub enum ReleaseUrlError {
    #[error("Invalid release URL format: {0}")]
    InvalidFormat(String),
    #[error("Missing tag in release URL")]
    MissingTag,
    #[error("Unsupported release platform: {0}. Supported platforms: GitHub, GitLab")]
    UnsupportedPlatform(String),
    #[error("Missing {0} in URL")]
    MissingComponent(String),
}

pub trait ReleaseInfo: std::fmt::Debug + Send + Sync {
    fn host(&self) -> &str;
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn tag(&self) -> &str;
    fn release_path(&self) -> &NormalisedPaths;
}

#[allow(async_fn_in_trait)]
pub trait ReleaseAdder: std::fmt::Debug {
    async fn new(
        release_url: &url::Url,
        git_repo_path: PathBuf,
        config: &crate::config::AppConfig,
    ) -> Result<Self, ReleaseError>
    where
        Self: Sized;

    fn signers_file_path(&self) -> PathBuf;

    async fn index_path(&self) -> Result<NormalisedPaths, ApiError>;
    async fn index_content(&self) -> Result<String, ApiError>;

    // Error if index already exists
    async fn create_index(&self) -> Result<NormalisedPaths, ApiError> {
        let index_path = self.index_path().await?.absolute_path();
        if tokio::fs::try_exists(index_path).await? {
            Err(ApiError::ReleaseAlreadyRegistered(
                "Release already registered".to_string(),
            ))
        } else {
            self.write_index().await
        }
    }

    // This unconditionally writes the index.
    // Ideally this should not be accessible to callers, but it appeared to be much more fuss than
    // I thought, so leaving as is for now.
    async fn write_index(&self) -> Result<NormalisedPaths, ApiError>;

    fn release_info(&self) -> ReleaseInfos;
}
