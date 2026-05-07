use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NewKeysOutput {
    pub public_key_path: String,
    pub public_key: String,
    pub secret_key_path: String,
}

#[derive(Debug, Serialize)]
pub struct NewSignersFileOutput {
    pub output_file: String,
    pub artifact_signers_count: usize,
    pub artifact_threshold: u32,
    pub admin_keys_count: usize,
    pub admin_threshold: Option<u32>,
    pub master_keys_count: usize,
    pub master_threshold: Option<u32>,
    pub revocation_keys_count: usize,
    pub revocation_threshold: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct JsonError {
    pub error: String,
}
