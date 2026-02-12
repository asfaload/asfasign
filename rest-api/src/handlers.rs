use common::fs::names::subject_path_from_pending_signatures;
use constants::SIGNERS_DIR;
use features_lib::{AsfaloadPublicKeyTrait, AsfaloadSignatureTrait};
use rest_api_types::models::{UpdateRepoSignersRequest, UpdateRepoSignersResponse};
use rest_api_types::{
    GetSignatureStatusResponse, ListPendingResponse, RegisterRepoRequest, RegisterRepoResponse,
    RevokeFileRequest, RevokeFileResponse, SubmitSignatureRequest, SubmitSignatureResponse,
};

use std::{path::PathBuf, str::FromStr};

use crate::file_auth::actors::git_actor::CommitFile;
use crate::file_auth::forges::ForgeInfo;
use crate::file_auth::forges::ForgeTrait;
use crate::file_auth::github::get_project_normalised_paths;
use crate::path_validation::NormalisedPaths;
use crate::state::AppState;
use axum::{Json, extract::State, http::HeaderMap};
use constants::PENDING_SIGNERS_DIR;
use rest_api_auth::HEADER_PUBLIC_KEY;
use rest_api_types::{
    errors::ApiError,
    models::{AddFileRequest, AddFileResponse},
};
use tokio::io::AsyncWriteExt;

pub fn map_to_user_error<M>(
    error: kameo::error::SendError<M, ApiError>,
    context: &str,
) -> ApiError {
    match error {
        kameo::error::SendError::HandlerError(api_error) => api_error,
        other => {
            tracing::error!(internal_error = %other, "{}", context);
            ApiError::InternalServerError(
                "Operation failed. Please check your request and try again.".to_string(),
            )
        }
    }
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
        file_paths: vec![normalised_paths],
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

    let parsed_url = url::Url::parse(&request.signers_file_url)
        .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;
    let repo_info = ForgeInfo::new(&parsed_url).map_err(|e| {
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
    if tokio::fs::try_exists(&project_dir).await? {
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
    // Parse public key and signature from the request
    let public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;
    let signature = features_lib::AsfaloadSignatures::from_base64(&request.signature)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid signature format".to_string()))?;

    let auth_request = crate::file_auth::actors::forge_signers_validator::ValidateProjectRequest {
        signers_file_url: parsed_url,
        request_id: request_id.to_string(),
    };

    let signers_proposal = state
        .forge_project_validator
        .ask(auth_request)
        .await
        .map_err(|e| map_to_user_error(e, "Project authentication failed"))?;

    // Construct metadata from forge information
    let forge_kind = match &repo_info {
        ForgeInfo::Github(_) => signers_file_types::Forge::Github,
        ForgeInfo::Gitlab(_) => signers_file_types::Forge::Gitlab,
    };
    let metadata = signers_file_types::SignersConfigMetadata::from_forge(
        signers_file_types::ForgeOrigin::new(
            forge_kind,
            request.signers_file_url.clone(),
            chrono::Utc::now(),
        ),
    );

    // Step 2: Initialise signers - create directory structure and files
    let init_request = crate::file_auth::actors::signers_initialiser::InitialiseSignersRequest {
        project_path: project_normalised_paths,
        signers_info: signers_proposal.signers_info,
        metadata,
        signature,
        pubkey: public_key,
        git_repo_path: state.git_repo_path.clone(),
        request_id: request_id.to_string(),
    };

    let init_result = state
        .signers_initialiser
        .ask(init_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signers initialisation failed"))?;

    // Step 3: Write and commit files via Git actor
    let write_commit_request = crate::file_auth::actors::git_actor::CommitFile {
        file_paths: vec![init_result.project_path.clone()],
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

        match init_result.project_path.join(PENDING_SIGNERS_DIR).await {
            Ok(pending_dir) => {
                let cleanup_request =
                    crate::file_auth::actors::signers_initialiser::CleanupSignersRequest {
                        signers_file_path: init_result.signers_file_path.clone(),
                        history_file_path: Some(init_result.history_file_path.clone()),
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
            }
            Err(join_err) => {
                tracing::error!(
                    request_id = %request_id,
                    error = %join_err,
                    "Failed to construct pending_dir path for cleanup"
                );
            }
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
        signature_submission_url: "/v1/signatures".to_string(),
    }))
}

pub async fn update_signers_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateRepoSignersRequest>,
) -> Result<Json<UpdateRepoSignersResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        signers_file_url = %request.signers_file_url,
        "Received update_signers request"
    );

    let parsed_url = url::Url::parse(&request.signers_file_url)
        .map_err(|e| ApiError::InvalidRequestBody(e.to_string()))?;
    let repo_info = ForgeInfo::new(&parsed_url).map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            url = %request.signers_file_url,
            error = %e,
            "Failed to parse forge URL"
        );
        ApiError::InvalidRequestBody(format!("Invalid forge URL: {}", e))
    })?;

    let project_id = repo_info.project_id();
    let project_normalised_paths = get_project_normalised_paths(&state.git_repo_path, &project_id)
        .await
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                project_id = %project_id,
                error = %e,
                "Failed to get normalised paths"
            );
            e
        })?;

    // For updates, the project directory must already exist
    let project_dir = project_normalised_paths.absolute_path();
    if !tokio::fs::try_exists(&project_dir).await? {
        return Err(ApiError::InvalidRequestBody(format!(
            "Project '{}' is not registered. Register the repo first.",
            project_id
        )));
    }

    // The signers directory must also exist (project fully initialized)
    let signers_dir = project_dir.join(SIGNERS_DIR);
    if !tokio::fs::try_exists(&signers_dir).await? {
        return Err(ApiError::InvalidRequestBody(format!(
            "Project '{}' has no active signers file. Complete initial registration first.",
            project_id
        )));
    }

    // Parse public key and signature from the request
    let public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;
    let signature = features_lib::AsfaloadSignatures::from_base64(&request.signature)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid signature format".to_string()))?;

    // Validate the signers file from the forge
    let auth_request = crate::file_auth::actors::forge_signers_validator::ValidateProjectRequest {
        signers_file_url: parsed_url,
        request_id: request_id.to_string(),
    };

    let signers_proposal = state
        .forge_project_validator
        .ask(auth_request)
        .await
        .map_err(|e| map_to_user_error(e, "Project validation failed"))?;

    // Construct metadata from forge information
    let forge_kind = match &repo_info {
        ForgeInfo::Github(_) => signers_file_types::Forge::Github,
        ForgeInfo::Gitlab(_) => signers_file_types::Forge::Gitlab,
    };
    let metadata = signers_file_types::SignersConfigMetadata::from_forge(
        signers_file_types::ForgeOrigin::new(
            forge_kind,
            request.signers_file_url.clone(),
            chrono::Utc::now(),
        ),
    );

    // Propose signers file update
    let propose_request = crate::file_auth::actors::signers_initialiser::ProposeSignersRequest {
        project_path: project_normalised_paths.clone(),
        signers_info: signers_proposal.signers_info,
        metadata,
        signature,
        pubkey: public_key,
        request_id: request_id.to_string(),
    };

    let propose_result = state
        .signers_initialiser
        .ask(propose_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signers proposal failed"))?;

    // Commit the changes via Git actor
    let write_commit_request = crate::file_auth::actors::git_actor::CommitFile {
        file_paths: vec![propose_result.project_path.clone()],
        commit_message: format!(
            "Proposed signers update for {}",
            propose_result.project_path.relative_path().display()
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

        match propose_result.project_path.join(PENDING_SIGNERS_DIR).await {
            Ok(pending_dir) => {
                let cleanup_request =
                    crate::file_auth::actors::signers_initialiser::CleanupSignersRequest {
                        signers_file_path: propose_result.project_path.clone(),
                        history_file_path: None,
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
            }
            Err(join_err) => {
                tracing::error!(
                    request_id = %request_id,
                    error = %join_err,
                    "Failed to construct pending_dir path for cleanup"
                );
            }
        }

        return Err(map_to_user_error(
            e,
            "Git write and commit operation failed",
        ));
    }

    tracing::info!(
        request_id = %request_id,
        project_id = %signers_proposal.project_id,
        "Signers update proposal completed successfully"
    );

    Ok(Json(UpdateRepoSignersResponse {
        success: true,
        project_id: signers_proposal.project_id,
        message: "Signers update proposed successfully. Collect signatures to activate."
            .to_string(),
        required_signers: propose_result.required_signers,
        signature_submission_url: "/v1/signatures".to_string(),
    }))
}

/// Handle signature submission for a specific file.
///
/// This endpoint accepts individual signatures for any file that has an aggregate signature.
/// The signature is validated and added to the collection. Changes are committed to Git after
/// each signature is collected to prevent data loss.
///
/// # Arguments
/// * `state` - Application state containing actor references
/// * `headers` - HTTP headers (must include x-request-id for tracing)
/// * `request` - Signature submission with file_path, public_key, and signature
///
/// # Returns
/// Returns a response indicating whether signature collection is complete
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or file doesn't exist
/// - Public key or signature format is invalid
/// - Signature verification fails
/// - Git commit fails
pub async fn submit_signature_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SubmitSignatureRequest>,
) -> Result<Json<SubmitSignatureResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        "Received submit_signature request"
    );

    // Validate the file path
    if request.file_path.is_empty() {
        return Err(ApiError::InvalidRequestBody(
            "File path cannot be empty".to_string(),
        ));
    }

    // Normalize and validate the file path
    let file_path = NormalisedPaths::new(
        state.git_repo_path.clone(),
        PathBuf::from_str(request.file_path.as_ref()).unwrap(),
    )
    .await?;

    // Check if the file exists
    if !file_path.absolute_path().exists() {
        return Err(ApiError::InvalidRequestBody(format!(
            "File not found: {}",
            request.file_path
        )));
    }

    // Parse public key and signature from base64 strings
    let public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;

    let signature = features_lib::AsfaloadSignatures::from_base64(&request.signature)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid signature format".to_string()))?;

    // Send signature collection request to the actor
    let collector_request =
        crate::file_auth::actors::signature_collector::CollectSignatureRequest {
            file_path: file_path.clone(),
            public_key,
            signature,
            request_id: request_id.to_string(),
        };

    let collector_result = state
        .signature_collector
        .ask(collector_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signature collection failed"))?;

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        is_complete = collector_result.is_complete,
        "Signature collection result"
    );

    Ok(Json(SubmitSignatureResponse {
        is_complete: collector_result.is_complete,
    }))
}

/// Query the current signature status for a specific file.
///
/// Returns information about the aggregate signature for a file, including
/// whether it's complete and how many signatures have been collected.
///
/// # Arguments
/// * `state` - Application state containing actor references
/// * `headers` - HTTP headers (must include x-request-id for tracing)
/// * `file_path` - Path to the file from the URL path parameter
///
/// # Returns
/// Returns the current status of signature collection including completion
/// status and count of collected signatures
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or file doesn't exist
/// - Failed to load signature status from disk
pub async fn get_signature_status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<Json<GetSignatureStatusResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        "Received get_signature_status request"
    );

    if file_path.is_empty() {
        return Err(ApiError::InvalidRequestBody(
            "File path cannot be empty".to_string(),
        ));
    }

    // Normalize and validate the file path
    let file_path = NormalisedPaths::new(
        state.git_repo_path.clone(),
        PathBuf::from_str(file_path.as_ref()).unwrap(),
    )
    .await?;

    if !file_path.absolute_path().exists() {
        return Err(ApiError::InvalidRequestBody(format!(
            "File not found: {}",
            file_path.relative_path().to_string_lossy()
        )));
    }

    // Send status request to the actor
    let status_request = crate::file_auth::actors::signature_collector::GetSignatureStatusRequest {
        file_path: file_path.clone(),
        request_id: request_id.to_string(),
    };

    let status = state
        .signature_collector
        .ask(status_request)
        .await
        .map_err(|e| map_to_user_error(e, "Signature status query failed"))?;

    Ok(Json(GetSignatureStatusResponse {
        file_path: file_path.relative_path().display().to_string(),
        is_complete: status.is_complete,
    }))
}

/// Handler to list all pending signature files for a specific signer.
///
/// Returns a list of file paths where the authenticated signer is authorized
/// to sign but has not yet submitted their signature.
///
/// # Arguments
/// * `state` - Application state with git repo path and actors
/// * `headers` - HTTP headers (must include authentication headers signed by the signer)
///
/// # Returns
/// Returns JSON response with list of file paths needing the signer's signature
///
/// # Errors
/// Returns `ApiError` if:
/// - Authentication headers are missing or invalid
/// - Failed to scan repository for pending files
/// - Failed to check signer authorization
pub async fn get_pending_signatures_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListPendingResponse>, ApiError> {
    use crate::path_validation::build_normalised_absolute_path;
    use crate::pending_discovery;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        "Received list_pending_signatures request"
    );

    // Extract public key from authentication headers
    let public_key = extract_public_key_from_headers(&headers)?;

    // Create base path NormalisedPaths for scanning from repo root
    let base_path = build_normalised_absolute_path(state.git_repo_path.clone(), PathBuf::from("."))
        .map_err(|e| ApiError::InvalidFilePath(format!("Failed to normalize base path: {}", e)))?;

    // Find pending files for this signer
    let discovery = pending_discovery::create_default_discovery();
    let pending_files = discovery
        .find_pending_for_signer(&base_path, &public_key)
        .map_err(|e| {
            tracing::error!(
                request_id = %request_id,
                error = %e,
                "Failed to find pending signatures"
            );
            ApiError::InternalServerError("Failed to find pending signatures".to_string())
        })?;

    // Extract relative paths and convert from pending signature files to artifact files
    let file_paths: Vec<String> = pending_files
        .iter()
        .map(|np| {
            let pending_sig_path = np.relative_path();
            let artifact_path = subject_path_from_pending_signatures(&pending_sig_path)?;
            Ok(artifact_path.to_string_lossy().to_string())
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    tracing::info!(
        request_id = %request_id,
        count = %file_paths.len(),
        "Returning pending signatures list"
    );

    Ok(Json(ListPendingResponse { file_paths }))
}

/// Helper to extract public key from authentication headers.
fn extract_public_key_from_headers(
    headers: &HeaderMap,
) -> Result<features_lib::AsfaloadPublicKeys, ApiError> {
    let pub_key_header = headers
        .get(HEADER_PUBLIC_KEY)
        .ok_or_else(|| ApiError::MissingAuthenticationHeaders)?
        .to_str()
        .map_err(|_| ApiError::InvalidAuthenticationHeaders)?;

    features_lib::AsfaloadPublicKeys::from_base64(pub_key_header)
        .map_err(|_| ApiError::InvalidAuthenticationHeaders)
}

pub async fn register_release_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<rest_api_types::RegisterReleaseRequest>,
) -> Result<Json<rest_api_types::RegisterReleaseResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        release_url = %request.release_url,
        "Received release registration request"
    );

    let result = state
        .release_actor
        .ask(crate::file_auth::actors::release_actor::ProcessRelease {
            request_id: request_id.to_string(),
            release_url: request.release_url,
        })
        .await
        .map_err(|e| match e {
            kameo::error::SendError::HandlerError(api_error) => api_error,
            other => ApiError::InternalServerError(format!("Actor message failed: {}", other)),
        })?;

    Ok(Json(rest_api_types::RegisterReleaseResponse {
        success: true,
        message: "Release registered successfully".to_string(),
        index_file_path: Some(
            result
                .index_file_path
                .relative_path()
                .to_string_lossy()
                .to_string(),
        ),
    }))
}

/// Handler to fetch a file's raw content from the repository.
///
/// Returns the raw file content as bytes. Used by client CLI to fetch files
/// that need to be signed (e.g., in the sign-pending workflow).
///
/// # Arguments
/// * `state` - Application state with git repo path
/// * `axum::extract::Path(file_path)` - URL path parameter containing the file path
///
/// # Returns
/// The raw file content as bytes with appropriate content-type header
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or contains traversal attempts
/// - File does not exist
/// - File cannot be read
pub async fn get_file_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>), ApiError> {
    use axum::http::header;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        "Received file fetch request"
    );

    // The file_path we get is sanitised, and making it normalised
    // further validates it against path traversals
    let normalised_paths = NormalisedPaths::new(state.git_repo_path, PathBuf::from(&file_path))
        .await
        .map_err(|e| ApiError::InvalidFilePath(format!("Invalid file path: {}", e)))?;

    let absolute_path = normalised_paths.absolute_path();

    // Verify the file exists
    if !absolute_path.exists() {
        tracing::warn!(
            request_id = %request_id,
            file_path = %file_path,
            absolute_path = %absolute_path.display(),
            "File not found"
        );
        return Err(ApiError::FileNotFound(format!(
            "File not found: {}",
            file_path
        )));
    }

    // Verify it's a file (not a directory)
    if !absolute_path.is_file() {
        tracing::warn!(
            request_id = %request_id,
            file_path = %file_path,
            absolute_path = %absolute_path.display(),
            "Path requested is not a file"
        );
        return Err(ApiError::InvalidFilePath(format!(
            "Path is not a file: {}",
            file_path
        )));
    }

    // Read the file content
    let content = tokio::fs::read(&absolute_path).await.map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            file_path = %file_path,
            error = %e,
            "Failed to read file"
        );
        ApiError::InternalServerError(format!("Failed to read file: {}", e))
    })?;

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        size = content.len(),
        "Successfully read file"
    );

    // Build response headers
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&content.len().to_string())
            .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
    );

    Ok((axum::http::StatusCode::OK, headers, content))
}

/// Handler to fetch the signers file for a given file path.
///
/// This endpoint takes a file path and returns the signers configuration
/// that applies to that file. It uses find_global_signers_for to locate
/// the appropriate signers file by traversing parent directories.
///
/// # Arguments
/// * `state` - Application state with git repo path
/// * `axum::extract::Path(file_path)` - URL path parameter containing the file path
///
/// # Returns
/// The signers file content as JSON
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or contains traversal attempts
/// - No signers file found for the given path
/// - Signers file cannot be read
pub async fn get_signers_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<(axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>), ApiError> {
    use axum::http::header;
    use common::fs::names::find_global_signers_for;

    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        "Received get_signers request"
    );

    // Normalize the file path
    let normalised_paths =
        NormalisedPaths::new(state.git_repo_path.clone(), PathBuf::from(&file_path))
            .await
            .map_err(|e| ApiError::InvalidFilePath(format!("Invalid file path: {}", e)))?;

    let absolute_path = normalised_paths.absolute_path();

    // Find the global signers file for this path
    let signers_path = find_global_signers_for(&absolute_path).map_err(|e| {
        tracing::warn!(
            request_id = %request_id,
            file_path = %file_path,
            absolute_path = %absolute_path.display(),
            error = %e,
            "No signers file found for path"
        );
        ApiError::FileNotFound(format!(
            "No signers file found for: {}. Error: {}",
            file_path, e
        ))
    })?;

    // Read the signers file content
    let content = tokio::fs::read(&signers_path).await.map_err(|e| {
        tracing::error!(
            request_id = %request_id,
            signers_path = %signers_path.display(),
            error = %e,
            "Failed to read signers file"
        );
        ApiError::InternalServerError(format!("Failed to read signers file: {}", e))
    })?;

    tracing::info!(
        request_id = %request_id,
        file_path = %file_path,
        signers_path = %signers_path.display(),
        size = content.len(),
        "Successfully retrieved signers file"
    );

    // Build response headers
    let mut response_headers = axum::http::HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&content.len().to_string())
            .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
    );

    Ok((axum::http::StatusCode::OK, response_headers, content))
}

/// Handle a revocation request for a signed file.
///
/// Validates the HTTP request, then delegates to the SignatureCollector
/// actor which serializes revocation alongside signature operations.
///
/// # Arguments
/// * `state` - Application state containing actor references
/// * `headers` - HTTP headers (must include x-request-id for tracing)
/// * `request` - Revocation request with file_path, revocation_json, signature, public_key
///
/// # Returns
/// Returns a response indicating whether revocation succeeded
///
/// # Errors
/// Returns `ApiError` if:
/// - File path is invalid or file doesn't exist
/// - Public key or signature format is invalid
/// - File has no complete aggregate signature
/// - Digest mismatch between revocation JSON and actual file
/// - Revocation authorization fails
pub async fn revoke_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeFileRequest>,
) -> Result<Json<RevokeFileResponse>, ApiError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        "Received revoke request"
    );

    // Validate the file path
    if request.file_path.is_empty() {
        return Err(ApiError::InvalidRequestBody(
            "File path cannot be empty".to_string(),
        ));
    }

    // Normalize and validate the file path
    let file_path = NormalisedPaths::new(
        state.git_repo_path.clone(),
        PathBuf::from_str(request.file_path.as_ref()).unwrap(),
    )
    .await?;

    // Check if the file exists
    if !file_path.absolute_path().exists() {
        return Err(ApiError::FileNotFound(format!(
            "File not found: {}",
            request.file_path
        )));
    }

    // Parse public key and signature from base64 strings
    let public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;

    let signature = features_lib::AsfaloadSignatures::from_base64(&request.signature)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid signature format".to_string()))?;

    // Send revocation request to the SignatureCollector actor
    let result = state
        .signature_collector
        .ask(crate::file_auth::actors::signature_collector::RevokeFileMessage {
            file_path: file_path.clone(),
            revocation_json: request.revocation_json,
            signature,
            public_key,
            request_id: request_id.to_string(),
        })
        .await
        .map_err(|e| map_to_user_error(e, "Revocation failed"))?;

    tracing::info!(
        request_id = %request_id,
        file_path = %request.file_path,
        "Revocation completed successfully"
    );

    Ok(Json(RevokeFileResponse {
        success: result.success,
        message: "File revoked successfully".to_string(),
    }))
}
