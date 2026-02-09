mod auth;
mod client;
mod error;

pub mod v1 {
    pub use crate::client::v1::Client;
}
pub use error::{AdminLibError, AdminLibResult};
