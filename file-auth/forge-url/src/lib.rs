mod error;
pub mod fileserver;
mod forge_info;
pub mod github;
pub mod gitlab;
mod origin;
mod traits;

pub use error::ForgeUrlError;
pub use forge_info::ForgeInfo;
pub use origin::path_prefix_from_url;
pub use traits::ForgeTrait;
