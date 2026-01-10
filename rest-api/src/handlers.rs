use rest_api_types::{RegisterRepoRequest, RegisterRepoResponse};

use std::{path::PathBuf, str::FromStr};

use crate::file_auth::github::get_project_normalised_paths;
use crate::path_validation::NormalisedPaths;
use crate::state::AppState;
use crate::{actors::git_actor::CommitFile, file_auth::github::parse_github_url};
use axum::{Json, extract::State, http::HeaderMap};
use common::fs::names::PENDING_SIGNERS_DIR;
use rest_api_types::{
    errors::ApiError,
    models::{AddFileRequest, AddFileResponse},
};
use tokio::io::AsyncWriteExt;

fn map_to_user_error(error: impl std::fmt::Display, context: &str) -> ApiError {
    tracing::error!(internal_error = %error, "{}", context);
    ApiError::InternalServerError(
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

    let repo_info = parse_github_url(&request.signers_file_url).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            url = %request.signers_file_url,
            error = %e,
            "Failed to parse GitHub URL"
        );
        ApiError::InvalidRequestBody(format!("Invalid GitHub URL: {}", e))
    })?;

    let project_id = repo_info.project_id();
    let project_normalised_paths = get_project_normalised_paths(&state.git_repo_path, &project_id)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                project_id = %project_id,
                error = %e,
                "Failed to get normalised paths in handlers"
            );
            e
        })?;

    let project_dir = project_normalised_paths.absolute_path();
    if project_dir.exists() {
        tracing::warn!(
            request_id = %request_id,
            project_id = %project_id,
            "Project directory structure already exists, indicating a pending or completed registration."
        );
        return Err(ApiError::InvalidRequestBody(format!(
            "Project '{}' is already registered or registration is in progress.",
            project_id
        )));
    }
    let auth_request =
        crate::file_auth::github::actors::github_project_validator::ValidateProjectRequest {
            signers_file_url: request.signers_file_url,
            request_id: request_id.to_string(),
        };

    let signers_proposal = state
        .github_project_validator
        .ask(auth_request)
        .await
        .map_err(|e| map_to_user_error(e, "Project authentication failed"))?;

    // Step 2: Initialise signers - create directory structure and files
    let init_request = crate::actors::signers_initialiser::InitialiseSignersRequest {
        project_id: signers_proposal.project_id.clone(),
        project_path: project_normalised_paths,
        signers_config: signers_proposal.signers_config.clone(),
        git_repo_path: state.git_repo_path.clone(),
        request_id: request_id.to_string(),
    };

    let init_result = state
        .signers_initialiser
        .ask(init_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signers initialisation failed"))?;

    // Step 3: Write and commit files via Git actor
    let write_commit_request = crate::actors::git_actor::CommitFile {
        file_paths: init_result.project_path.clone(),
        commit_message: format!(
            "Adding {}",
            init_result.project_path.relative_path().display()
        ),
        request_id: request_id.to_string(),
    };

    let git_actor_result = state.git_actor.ask(write_commit_request).await;

    if let Err(e) = git_actor_result {
        tracing::error!(
            request_id = %request_id,
            error = %e,
            "Git actor commit failed, initiating cleanup"
        );

        let pending_dir = init_result.project_path.join(PENDING_SIGNERS_DIR).await?;

        let cleanup_request = crate::actors::signers_initialiser::CleanupSignersRequest {
            signers_file_path: init_result.signers_file_path.clone(),
            history_file_path: init_result.history_file_path.clone(),
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
