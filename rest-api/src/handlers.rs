use crate::actors::git_actor::CommitFile;
use crate::error::ApiError;
use crate::models::{AddFileRequest, AddFileResponse};
use crate::state::AppState;
use axum::{Json, extract::State};
use log::info;
use tokio::io::AsyncWriteExt;

pub async fn add_file_handler(
    State(state): State<AppState>,
    Json(request): Json<AddFileRequest>,
) -> Result<Json<AddFileResponse>, ApiError> {
    info!("Received add_file request for path: {}", request.file_path);

    // Validate the file path
    if request.file_path.is_empty() {
        return Err(ApiError::InvalidFilePath(
            "File path cannot be empty".to_string(),
        ));
    }

    // Validate and sanitize the file path
    let file_path = std::path::PathBuf::from(&request.file_path);
    if file_path.is_absolute()
        || file_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ApiError::InvalidFilePath(
            "Path traversal attempt detected".to_string(),
        ));
    }
    let full_path = state.git_repo_path.join(file_path);

    // Create parent directories if they don't exist
    if let Some(parent) = full_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            ApiError::DirectoryCreationFailed(format!("Failed to create directories: {}", e))
        })?;
    }

    // Write the file content
    let mut file = tokio::fs::File::create(&full_path)
        .await
        .map_err(|e| ApiError::FileWriteFailed(format!("Failed to create file: {}", e)))?;

    file.write_all(request.content.as_bytes())
        .await
        .map_err(|e| ApiError::FileWriteFailed(format!("Failed to write file content: {}", e)))?;
    // Send commit message to git actor with the requested format
    let commit_message = format!("added file at /{}", request.file_path);
    let commit_msg = CommitFile {
        file_path: full_path.clone(),
        commit_message: commit_message.clone(),
    };

    state
        .git_actor
        .tell(commit_msg)
        .await
        .map_err(|e| ApiError::ActorMessageFailed(e.to_string()))?;

    Ok(Json(AddFileResponse {
        success: true,
        message: "File added successfully".to_string(),
        file_path: request.file_path,
    }))
}
