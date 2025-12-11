use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AddFileRequest {
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct AddFileResponse {
    pub success: bool,
    pub message: String,
    pub file_path: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}