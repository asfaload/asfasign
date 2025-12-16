use crate::actors::git_actor::CommitFile;
use crate::state::AppState;

use crate::models::{AddFileRequest, AddFileResponse, ErrorResponse};
use axum::{Json, extract::State};
use log::info;
use std::fs;
use std::io::Write;

pub async fn add_file_handler(
    State(state): State<AppState>,
    Json(request): Json<AddFileRequest>,
) -> Result<Json<AddFileResponse>, Json<ErrorResponse>> {
    info!("Received add_file request for path: {}", request.file_path);

    // Validate the file path
    if request.file_path.is_empty() {
        return Err(Json(ErrorResponse {
            error: "File path cannot be empty".to_string(),
        }));
    }

    // Create the full path by joining with git repo path
    let full_path = state.git_repo_path.join(&request.file_path);

    // Create parent directories if they don't exist
    if let Some(parent) = full_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| {
            Json(ErrorResponse {
                error: format!("Failed to create directories: {}", e),
            })
        })?;
    }

    // Write the file content
    let mut file = fs::File::create(&full_path).map_err(|e| {
        Json(ErrorResponse {
            error: format!("Failed to create file: {}", e),
        })
    })?;

    file.write_all(request.content.as_bytes()).map_err(|e| {
        Json(ErrorResponse {
            error: format!("Failed to write file content: {}", e),
        })
    })?;

    // Send commit message to git actor with the requested format
    let commit_message = format!("added file at </{}", request.file_path);
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
