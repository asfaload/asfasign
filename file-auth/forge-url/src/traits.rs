use std::path::Path;

use crate::ForgeUrlError;

pub trait ForgeTrait
where
    Self: Sized,
{
    fn new(url: &url::Url) -> Result<Self, ForgeUrlError>;

    // Identity
    fn project_id(&self) -> String;

    // Accessors
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn branch(&self) -> &str;
    fn file_path(&self) -> &Path;
    fn raw_url(&self) -> &url::Url;
}
