use rest_api_types::models::{ClientPendingFile, PendingFile};

use crate::error::ClientCliError;

pub fn select_pending_file(_files: Vec<PendingFile>) -> Result<ClientPendingFile, ClientCliError> {
    unimplemented!()
}
