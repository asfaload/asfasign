use std::{path::PathBuf, str::FromStr};

use crate::actors::git_actor::CommitFile;
use crate::path_validation::NormalisedPaths;
use crate::state::AppState;
use axum::{Json, extract::State};
use log::info;
use rest_api_types::{
    errors::ApiError,
    models::{AddFileRequest, AddFileResponse},
};
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
    let normalised_paths = NormalisedPaths::new(
        state.git_repo_path,
        // Using unwrap because it is a Result<_,Infallible>
        PathBuf::from_str(request.file_path.as_ref()).unwrap(),
    )
    .await?;
    let full_path = normalised_paths.absolute_path();

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
    let commit_message = format!(
        "added file at /{}",
        normalised_paths.relative_path().display()
    );
    let commit_msg = CommitFile {
        file_paths: normalised_paths,
        commit_message: commit_message.clone(),
    };

    state
        .git_actor
        .ask(commit_msg)
        .await
        .map_err(|e| ApiError::ActorMessageFailed(e.to_string()))?;

    Ok(Json(AddFileResponse {
        success: true,
        message: "File added successfully".to_string(),
        file_path: request.file_path,
    }))
}
