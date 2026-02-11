mod error;
mod forge_info;
pub mod github;
pub mod gitlab;
mod traits;

pub use error::ForgeUrlError;
pub use forge_info::ForgeInfo;
pub use traits::ForgeTrait;
