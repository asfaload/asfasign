// FIXME: we could improve this by reusing defined const in future consts,
// but it seems too much of a burden at this time.
// We might want to look at https://crates.io/crates/constcat
pub const PENDING_SUFFIX: &str = "pending";

pub const SIGNATURES_SUFFIX: &str = "signatures.json";
pub const PENDING_SIGNATURES_SUFFIX: &str = "signatures.json.pending";
pub const REVOCATION_SUFFIX: &str = "revocation.json";
pub const PENDING_REVOCATION_SUFFIX: &str = "revocation.json.pending";
pub const REVOKED_SUFFIX: &str = "revoked";
pub const SIGNERS_SUFFIX: &str = "signers.json";
pub const SIGNERS_DIR: &str = "asfaload.signers";
pub const PENDING_SIGNERS_DIR: &str = "asfaload.signers.pending";
pub const SIGNERS_FILE: &str = "index.json";
pub const METADATA_FILE: &str = "metadata.json";
pub const PENDING_SIGNERS_FILE: &str = "index.json.pending";
pub const SIGNERS_HISTORY_SUFFIX: &str = "history.json";
pub const SIGNERS_HISTORY_FILE: &str = "asfaload.signers.history.json";
pub const INDEX_FILE: &str = "asfaload.index.json";
