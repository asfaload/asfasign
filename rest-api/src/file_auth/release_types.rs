use crate::{file_auth::releasers::ReleaseInfos, path_validation::NormalisedPaths};
use rest_api_types::errors::ApiError;
use std::path::PathBuf;
use thiserror::Error;

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
    async fn new(release_url: &url::Url, git_repo_path: PathBuf) -> Result<Self, ReleaseUrlError>
    where
        Self: Sized;

    fn signers_file_path(&self) -> PathBuf;

    async fn index_content(&self) -> Result<String, ApiError>;

    async fn write_index(&self) -> Result<NormalisedPaths, ApiError>;

    fn release_info(&self) -> ReleaseInfos;
}
