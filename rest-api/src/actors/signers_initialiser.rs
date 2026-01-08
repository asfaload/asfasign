use common::fs::names::{
    PENDING_SIGNERS_DIR, PENDING_SIGNERS_FILE, SIGNERS_FILE, SIGNERS_HISTORY_FILE,
};
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::types::AsfaloadPublicKeys;
use signers_file_types::SignersConfig;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct InitialiseSignersRequest {
    pub project_id: String,
    pub signers_config: SignersConfig,
    pub git_repo_path: PathBuf,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct InitialiseSignersResult {
    pub project_id: String,
    pub required_signers: Vec<String>,
    pub signers_file_path: PathBuf,
    pub history_file_path: PathBuf,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct CleanupSignersRequest {
    pub signers_file_path: PathBuf,
    pub history_file_path: PathBuf,
    pub pending_dir: PathBuf,
    pub request_id: String,
}

pub struct SignersInitialiser;

impl Actor for SignersInitialiser {
    type Args = ();
    type Error = String;

    async fn on_start(
        _args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!("SignersInitialiser starting");
        Ok(Self)
    }
}

impl Message<InitialiseSignersRequest> for SignersInitialiser {
    type Reply = Result<InitialiseSignersResult, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: InitialiseSignersRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            project_id = %msg.project_id,
            "SignersInitialiser received initialisation request"
        );

        let validated_project_dir = tokio::task::spawn_blocking({
            let git_repo_path = msg.git_repo_path.clone();
            let project_id = msg.project_id.clone();
            move || validate_project_id(&git_repo_path, &project_id)
        })
        .await
        .map_err(ApiError::from)?
        .map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                project_id = %msg.project_id,
                error = %e,
                "Project ID validation failed"
            );
            e
        })?;

        let project_dir = validated_project_dir;
        let signers_pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let signers_file_path = signers_pending_dir.join(SIGNERS_FILE);
        let history_file_path = project_dir.join(SIGNERS_HISTORY_FILE);

        tokio::fs::create_dir_all(&signers_pending_dir)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    tracing::warn!(
                        request_id = %msg.request_id,
                        project_id = %msg.project_id,
                        "Project directory already exists"
                    );
                    return ApiError::InvalidRequestBody(format!(
                        "Project '{}' is already registered",
                        msg.project_id
                    ));
                }
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %signers_pending_dir.display(),
                    "Failed to create signers directory"
                );
                ApiError::DirectoryCreationFailed(format!(
                    "Failed to create directory {}: {}",
                    signers_pending_dir.display(),
                    e
                ))
            })?;

        let signers_json = serde_json::to_string_pretty(&msg.signers_config).map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                error = %e,
                "Failed to serialize signers config"
            );
            ApiError::FileWriteFailed(format!("Failed to serialize signers config: {}", e))
        })?;

        tokio::fs::write(&signers_file_path, signers_json)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %signers_file_path.display(),
                    "Failed to write signers file"
                );
                ApiError::FileWriteFailed(format!(
                    "Failed to write signers file {}: {}",
                    signers_file_path.display(),
                    e
                ))
            })?;

        let history_json = "[]";
        tokio::fs::write(&history_file_path, history_json)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %history_file_path.display(),
                    "Failed to write history file"
                );
                ApiError::FileWriteFailed(format!(
                    "Failed to write history file {}: {}",
                    history_file_path.display(),
                    e
                ))
            })?;

        let required_signers: Vec<String> = msg
            .signers_config
            .all_signer_keys()
            .into_iter()
            .map(|key: AsfaloadPublicKeys| key.to_base64())
            .collect();

        tracing::info!(
            request_id = %msg.request_id,
            project_id = %msg.project_id,
            required_signers_count = required_signers.len(),
            "Successfully initialised signers"
        );

        Ok(InitialiseSignersResult {
            project_id: msg.project_id,
            required_signers,
            signers_file_path,
            history_file_path,
            request_id: msg.request_id,
        })
    }
}

impl Message<CleanupSignersRequest> for SignersInitialiser {
    type Reply = Result<(), String>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: CleanupSignersRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            signers_file_path = %msg.signers_file_path.display(),
            history_file_path = %msg.history_file_path.display(),
            pending_dir = %msg.pending_dir.display(),
            "Cleaning up signers files"
        );

        if let Err(e) = tokio::fs::remove_file(&msg.signers_file_path).await {
            tracing::warn!(
                request_id = %msg.request_id,
                path = %msg.signers_file_path.display(),
                error = %e,
                "Failed to remove signers file during cleanup"
            );
        }

        if let Err(e) = tokio::fs::remove_file(&msg.history_file_path).await {
            tracing::warn!(
                request_id = %msg.request_id,
                path = %msg.history_file_path.display(),
                error = %e,
                "Failed to remove history file during cleanup"
            );
        }

        if let Err(e) = tokio::fs::remove_dir_all(&msg.pending_dir).await {
            tracing::warn!(
                request_id = %msg.request_id,
                path = %msg.pending_dir.display(),
                error = %e,
                "Failed to remove pending directory during cleanup"
            );
        }

        tracing::info!(
            request_id = %msg.request_id,
            "Cleanup completed"
        );

        Ok(())
    }
}

fn validate_project_id(git_repo_path: &PathBuf, project_id: &str) -> Result<PathBuf, ApiError> {
    if project_id.contains('\0') {
        return Err(ApiError::InvalidRequestBody(
            "Project ID must not contain null bytes".to_string(),
        ));
    }

    if project_id.contains('\\') {
        return Err(ApiError::InvalidRequestBody(
            "Project ID must not contain backslashes".to_string(),
        ));
    }

    let project_path = git_repo_path.join(project_id);
    let canonical_base = fs::canonicalize(git_repo_path).map_err(|e| {
        ApiError::InvalidFilePath(format!("Failed to resolve repository path: {}", e))
    })?;

    let canonical_project = project_path.canonicalize();
    let canonical_project = match canonical_project {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => project_path.clone(),
        Err(e) => {
            return Err(ApiError::InvalidFilePath(format!(
                "Failed to resolve project path: {}",
                e
            )));
        }
    };

    if !canonical_project.starts_with(&canonical_base) {
        return Err(ApiError::InvalidRequestBody(
            "Invalid project ID: path traversal detected".to_string(),
        ));
    }

    Ok(project_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_project_id_with_null_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = validate_project_id(&git_repo_path, "github.com/user/repo\0");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("null bytes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }
    }

    #[test]
    fn test_validate_project_id_with_backslashes() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = validate_project_id(&git_repo_path, "github.com\\user\\repo");
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("backslashes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }
    }

    #[test]
    fn test_validate_project_id_valid() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let result = validate_project_id(&git_repo_path, "github.com/user/repo");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.starts_with(&git_repo_path));
        assert!(path.ends_with("github.com/user/repo"));
    }

    #[test]
    fn test_validate_project_id_with_existing_directory() {
        let temp_dir = TempDir::new().unwrap();
        let git_repo_path = temp_dir.path().to_path_buf();

        let project_id = "github.com/user/repo";
        let project_path = git_repo_path.join(project_id);
        fs::create_dir_all(&project_path).unwrap();

        let result = validate_project_id(&git_repo_path, project_id);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert_eq!(path, project_path);
    }

    #[tokio::test]
    async fn test_signers_initialiser_creates_directory_structure() {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let test_keys = test_helpers::TestKeys::new(1);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        let request = InitialiseSignersRequest {
            project_id: "github.com/test/repo".to_string(),
            signers_config: config,
            git_repo_path: git_path.clone(),
            request_id: "test-123".to_string(),
        };

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        assert!(result.is_ok());
        let init_result = result.unwrap();

        let project_dir = git_path.join("github.com/test/repo");
        let signers_pending_dir = project_dir.join("asfaload.signers.pending");
        assert!(signers_pending_dir.exists());
        assert!(init_result.signers_file_path.exists());
        assert!(init_result.history_file_path.exists());

        let history_content = tokio::fs::read_to_string(&init_result.history_file_path)
            .await
            .unwrap();
        assert_eq!(history_content, "[]");

        let signers_content = tokio::fs::read_to_string(&init_result.signers_file_path)
            .await
            .unwrap();
        let parsed_config: SignersConfig = serde_json::from_str(&signers_content).unwrap();
        assert_eq!(parsed_config.artifact_signers().len(), 1);
    }

    #[tokio::test]
    async fn test_signers_initialiser_extract_public_keys() {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let test_keys = test_helpers::TestKeys::new(2);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![
                    test_keys.pub_key(0).unwrap().clone(),
                    test_keys.pub_key(1).unwrap().clone(),
                ],
                2,
            ),
        )
        .unwrap();

        let request = InitialiseSignersRequest {
            project_id: "github.com/test/repo".to_string(),
            signers_config: config,
            git_repo_path: git_path.clone(),
            request_id: "test-456".to_string(),
        };

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        assert!(result.is_ok());
        let init_result = result.unwrap();

        assert_eq!(init_result.required_signers.len(), 2);
        assert!(
            init_result
                .required_signers
                .contains(&test_keys.pub_key(0).unwrap().to_base64())
        );
        assert!(
            init_result
                .required_signers
                .contains(&test_keys.pub_key(1).unwrap().to_base64())
        );
    }

    #[tokio::test]
    async fn test_signers_initialiser_rejects_path_traversal() {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let malicious_id = "../../../etc/passwd";
        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();

        let config = SignersConfig::with_artifact_signers_only(1, (vec![public_key], 1)).unwrap();

        let request = InitialiseSignersRequest {
            project_id: malicious_id.to_string(),
            signers_config: config,
            git_repo_path: git_path.clone(),
            request_id: "test-traversal-001".to_string(),
        };

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        match result {
            Ok(_) => panic!("Expected error for path traversal"),
            Err(send_error) => match send_error {
                kameo::error::SendError::HandlerError(api_error) => match api_error {
                    ApiError::InvalidRequestBody(msg) => {
                        assert!(
                            msg.contains("Invalid project ID") || msg.contains("path traversal")
                        );
                    }
                    _ => panic!("Expected InvalidRequestBody error for path traversal"),
                },
                _ => panic!("Expected HandlerError for path traversal"),
            },
        }
    }

    #[tokio::test]
    async fn test_signers_initialiser_handles_existing_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let project_dir = git_path.join("github.com/test/existing");
        let signers_pending_dir = project_dir.join("asfaload.signers.pending");
        tokio::fs::create_dir_all(&project_dir).await.unwrap();
        tokio::fs::write(&signers_pending_dir, "").await.unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();

        let config = SignersConfig::with_artifact_signers_only(1, (vec![public_key], 1)).unwrap();

        let request = InitialiseSignersRequest {
            project_id: "github.com/test/existing".to_string(),
            signers_config: config,
            git_repo_path: git_path.clone(),
            request_id: "test-exists-001".to_string(),
        };

        let actor_ref = SignersInitialiser::spawn(());
        let result = actor_ref.ask(request).await;

        match result {
            Ok(_) => panic!("Expected error for existing directory"),
            Err(send_error) => match send_error {
                kameo::error::SendError::HandlerError(api_error) => match api_error {
                    ApiError::InvalidRequestBody(msg) => {
                        assert!(msg.contains("already registered"));
                    }
                    _ => panic!("Expected InvalidRequestBody error for existing directory"),
                },
                _ => panic!("Expected HandlerError for existing directory"),
            },
        }
    }
}
