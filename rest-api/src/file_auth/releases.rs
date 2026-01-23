use std::path::PathBuf;

use crate::path_validation::NormalisedPaths;
use rest_api_types::errors::ApiError;

#[allow(async_fn_in_trait)]
pub trait ReleaseAdder: std::fmt::Debug {
    fn signers_file_path(&self) -> PathBuf;
    async fn index_content(&self) -> Result<String, ApiError>;
    async fn write_index(&self) -> Result<NormalisedPaths, ApiError>;
}
