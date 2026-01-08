use features_lib::{AsfaloadPublicKeyTrait, AsfaloadPublicKeys};
use rest_api_types::{RegisterRepoRequest, RegisterRepoResponse};

use std::{path::PathBuf, str::FromStr};

use crate::actors::git_actor::CommitFile;
use crate::path_validation::NormalisedPaths;
use crate::state::AppState;
use axum::{Json, extract::State, http::HeaderMap};
use rest_api_types::{
    errors::ApiError,
    models::{AddFileRequest, AddFileResponse},
};
use tokio::io::AsyncWriteExt;

fn map_to_user_error(error: impl std::fmt::Display, context: &str) -> ApiError {
    tracing::error!(internal_error = %error, "{}", context);
    ApiError::InvalidRequestBody(
        "Operation failed. Please check your request and try again.".to_string(),
    )
}

pub async fn add_file_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AddFileRequest>,
) -> Result<Json<AddFileResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        "Received add_file request"
    );

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
    // Flushing is absolutely necessary, otherwise the git_actor might try to not yet
    // see the file when it wants to commit it!
    file.flush()
        .await
        .map_err(|e| ApiError::FileWriteFailed(format!("Failed to flush file: {}", e)))?;

    // Send commit message to git actor with the requested format
    let commit_message = format!(
        "added file at /{}",
        normalised_paths.relative_path().display()
    );
    let commit_msg = CommitFile {
        file_paths: normalised_paths,
        commit_message: commit_message.clone(),
        request_id: request_id.to_string(),
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

pub async fn register_repo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterRepoRequest>,
) -> Result<Json<RegisterRepoResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        signers_file_url = %request.signers_file_url,
        "Received register_repo request"
    );

    let auth_request = crate::actors::github_project_authenticator::AuthenticateProjectRequest {
        signers_file_url: request.signers_file_url,
        request_id: request_id.to_string(),
    };

    let signers_proposal = state
        .github_project_authenticator
        .ask(auth_request)
        .await
        .map_err(|e| map_to_user_error(e, "Project authentication failed"))?;

    // Step 2: Initialise signers - create directory structure and files
    let init_request = crate::actors::signers_initialiser::InitialiseSignersRequest {
        project_id: signers_proposal.project_id.clone(),
        signers_config: signers_proposal.signers_config.clone(),
        git_repo_path: state.git_repo_path.clone(),
        request_id: request_id.to_string(),
    };

    let init_result = state
        .signers_initialiser
        .ask(init_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signers initialisation failed"))?;

    // Step 3: Write and commit files via RepoHandler
    let write_commit_request = crate::actors::repo_handler::WriteAndCommitFilesRequest {
        signers_file_path: init_result.signers_file_path.clone(),
        history_file_path: init_result.history_file_path.clone(),
        git_repo_path: state.git_repo_path.clone(),
        request_id: request_id.to_string(),
    };

    let repo_handler_result = state.repo_handler.ask(write_commit_request).await;

    if let Err(e) = repo_handler_result {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Repo handler write and commit failed, initiating cleanup"
        );

        let signers_file_path = init_result.signers_file_path.absolute_path().clone();
        let history_file_path = init_result.history_file_path.absolute_path().clone();
        let pending_dir = signers_file_path
            .parent()
            .ok_or_else(|| {
                tracing::error!(request_id = %request_id, "Failed to get pending directory parent");
                ApiError::InvalidRequestBody("Failed to determine pending directory".to_string())
            })?
            .to_path_buf();

        let cleanup_request = crate::actors::signers_initialiser::CleanupSignersRequest {
            signers_file_path,
            history_file_path,
            pending_dir,
            request_id: request_id.to_string(),
        };

        if let Err(cleanup_err) = state.signers_initialiser.ask(cleanup_request).await {
            tracing::error!(
                request_id = %request_id,
                error = %cleanup_err,
                "Cleanup also failed"
            );
        }

        return Err(map_to_user_error(
            e,
            "Git write and commit operation failed",
        ));
    }

    tracing::info!(
        request_id = %request_id,
        project_id = %signers_proposal.project_id,
        "Repo handler write and commit succeeded"
    );

    tracing::info!(
        request_id = %request_id,
        project_id = %signers_proposal.project_id,
        "Project registration completed successfully"
    );

    Ok(Json(RegisterRepoResponse {
        success: true,
        project_id: signers_proposal.project_id,
        message: "Project registered successfully. Collect signatures to activate.".to_string(),
        required_signers: init_result.required_signers.into_iter().collect(),
        signature_submission_url: "/sign".to_string(),
    }))
}
