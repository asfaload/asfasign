use common::fs::names::pending_signatures_path_for;
use constants::{PENDING_SIGNERS_DIR, SIGNERS_FILE, SIGNERS_HISTORY_FILE};
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use signatures::keys::AsfaloadPublicKeyTrait;
use signatures::types::AsfaloadPublicKeys;
use signers_file_types::SignersConfig;
use std::path::PathBuf;

use crate::path_validation::NormalisedPaths;

#[derive(Debug, Clone)]
pub struct InitialiseSignersRequest {
    pub project_path: NormalisedPaths,
    pub signers_config: SignersConfig,
    pub git_repo_path: PathBuf,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct InitialiseSignersResult {
    pub project_path: NormalisedPaths,
    pub required_signers: Vec<String>,
    pub signers_file_path: NormalisedPaths,
    pub history_file_path: NormalisedPaths,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct CleanupSignersRequest {
    pub signers_file_path: NormalisedPaths,
    pub history_file_path: NormalisedPaths,
    pub pending_dir: NormalisedPaths,
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
        let project_id = msg
            .project_path
            .relative_path()
            .to_string_lossy()
            .to_string();
        tracing::info!(
            request_id = %msg.request_id,
            project_id = %project_id,
            "SignersInitialiser received initialisation request"
        );

        let project_normalised_paths = msg.project_path;
        //
        // Even though the handler checks the existence, we need to test it here
        // just in case the handler gets the second request before we create the
        // directory here. The second message the handler sends us will detect
        // here that the project dir was already created.
        let project_dir = project_normalised_paths.absolute_path();
        if tokio::fs::try_exists(&project_dir).await? {
            tracing::warn!(
                request_id = %msg.request_id,
                project_id = %project_id,
                "Project directory structure already exists, indicating a pending or completed registration."
            );
            return Err(ApiError::InvalidRequestBody(format!(
                "Project '{}' is already registered or registration is in progress.",
                project_id
            )));
        }

        tracing::debug!(
                request_id = %msg.request_id,
                project_id = %project_id,
            project_normalised_paths_relative = %project_normalised_paths.relative_path().display(),
            project_normalised_paths_absolute = %project_normalised_paths.absolute_path().display(),
            "Computed normalised paths for project"
        );

        let signers_normalised_paths = project_normalised_paths
            .join(PENDING_SIGNERS_DIR)
            .await?
            .join(SIGNERS_FILE)
            .await?;
        let history_normalised_paths = project_normalised_paths.join(SIGNERS_HISTORY_FILE).await?;

        // Need to assign to avoid
        //    rustc: temporary value dropped while borrowed
        //    consider using a `let` binding to create a longer lived value [E0716]
        let target = signers_normalised_paths.absolute_path();
        let pending_dir_result = target.parent();
        let pending_dir = pending_dir_result.ok_or_else(|| {
            ApiError::InternalServerError(
                "Could not determine parent dir of signers file path".to_string(),
            )
        })?;

        tokio::fs::create_dir_all(&pending_dir).await.map_err(|e| {
            tracing::error!(
                request_id = %msg.request_id,
                error = %e,
                path = %pending_dir.display(),
                "Failed to create signers directory"
            );
            ApiError::DirectoryCreationFailed(format!(
                "Failed to create directory {}: {}",
                pending_dir.display(),
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

        tokio::fs::write(&signers_normalised_paths, signers_json)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %signers_normalised_paths,
                    "Failed to write signers file"
                );
                ApiError::FileWriteFailed(format!(
                    "Failed to write signers file {}: {}",
                    signers_normalised_paths, e
                ))
            })?;

        tracing::debug!(
            request_id = %msg.request_id,
            file_path = %signers_normalised_paths,
            "Wrote signers file to disk"
        );

        // Write an empty signers file so missing signatures works for these newly added signers
        // files
        let pending_signers_sig_path =
            pending_signatures_path_for(signers_normalised_paths.absolute_path());
        match pending_signers_sig_path {
            Ok(ref path) => {
                tokio::fs::write(path, "{}").await.map_err(|e| {
                    tracing::error!(
                        request_id = %msg.request_id,
                        error = %e,
                        path = %path.display(),
                        "Failed to write pending signers signature file"
                    );
                    ApiError::FileWriteFailed(format!(
                        "Failed to write pending signers signature file {}: {}",
                        path.display(),
                        e
                    ))
                })?;

                tracing::debug!(
                    request_id = %msg.request_id,
                    file_path = %path.display(),
                    "Wrote pending signers signature file to disk"
                );
            }
            Err(e) => {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    "Failed to compute pending signers signature path"
                );
            }
        }

        let history_json = "[]";
        tokio::fs::write(&history_normalised_paths, history_json)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    error = %e,
                    path = %history_normalised_paths,
                    "Failed to write history file"
                );
                ApiError::FileWriteFailed(format!(
                    "Failed to write history file {}: {}",
                    history_normalised_paths, e
                ))
            })?;

        tracing::debug!(
            request_id = %msg.request_id,
            file_path = %signers_normalised_paths,
            "Wrote history file to disk"
        );

        let required_signers: Vec<String> = msg
            .signers_config
            .all_signer_keys()
            .into_iter()
            .map(|key: AsfaloadPublicKeys| key.to_base64())
            .collect();

        tracing::info!(
            request_id = %msg.request_id,
            project_id = %project_id,
            required_signers_count = required_signers.len(),
            "Successfully initialised signers"
        );

        Ok(InitialiseSignersResult {
            project_path: project_normalised_paths,
            required_signers,
            signers_file_path: signers_normalised_paths,
            history_file_path: history_normalised_paths,
            request_id: msg.request_id,
        })
    }
}

impl Message<CleanupSignersRequest> for SignersInitialiser {
    type Reply = Result<(), ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: CleanupSignersRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            request_id = %msg.request_id,
            signers_file_path = %msg.signers_file_path,
            history_file_path = %msg.history_file_path,
            pending_dir = %msg.pending_dir,
            "Cleaning up signers files"
        );

        let mut had_error = false;

        if let Err(e) = tokio::fs::remove_file(&msg.history_file_path).await {
            had_error = true;
            tracing::warn!(
                request_id = %msg.request_id,
                path = %msg.history_file_path,
                error = %e,
                "Failed to remove history file during cleanup"
            );
        }

        if let Err(e) = tokio::fs::remove_dir_all(&msg.pending_dir).await {
            had_error = true;
            tracing::warn!(
                request_id = %msg.request_id,
                path = %msg.pending_dir,
                error = %e,
                "Failed to remove pending directory during cleanup"
            );
        }

        tracing::info!(
            request_id = %msg.request_id,
            "Cleanup completed"
        );

        if had_error {
            Err(ApiError::ActorOperationFailed("Cleanup failed".to_string()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::file_auth::github::get_project_normalised_paths;

    use super::*;
    use anyhow::Result;
    use common::fs::names::pending_signatures_path_for;
    use kameo::actor::Spawn;

    #[tokio::test]
    async fn test_signers_initialiser_creates_directory_structure() -> Result<()> {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let test_keys = test_helpers::TestKeys::new(1);

        let config = SignersConfig::with_artifact_signers_only(
            1,
            (vec![test_keys.pub_key(0).unwrap().clone()], 1),
        )
        .unwrap();

        let project_path = get_project_normalised_paths(&git_path, "github.com/test/repo").await?;
        let request = InitialiseSignersRequest {
            project_path,
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
        assert!(init_result.signers_file_path.absolute_path().exists());
        assert!(init_result.history_file_path.absolute_path().exists());

        let pending_signers_sig_path =
            pending_signatures_path_for(&init_result.signers_file_path.absolute_path())?;
        assert!(pending_signers_sig_path.exists());
        let pending_sig_content = tokio::fs::read_to_string(&pending_signers_sig_path)
            .await
            .unwrap();
        assert_eq!(pending_sig_content, "{}");

        let history_content =
            tokio::fs::read_to_string(&init_result.history_file_path.absolute_path())
                .await
                .unwrap();
        assert_eq!(history_content, "[]");

        let signers_content =
            tokio::fs::read_to_string(&init_result.signers_file_path.absolute_path())
                .await
                .unwrap();
        let parsed_config: SignersConfig = serde_json::from_str(&signers_content).unwrap();
        assert_eq!(parsed_config.artifact_signers().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_signers_initialiser_extract_public_keys() -> Result<()> {
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
        let project_path = get_project_normalised_paths(&git_path, "github.com/test/repo").await?;

        let request = InitialiseSignersRequest {
            project_path,
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
        Ok(())
    }

    #[tokio::test]
    async fn test_signers_initialiser_handles_existing_directory() -> Result<()> {
        let temp = tempfile::TempDir::new().unwrap();
        let git_path = temp.path().to_path_buf();

        let project_dir = git_path.join("github.com/test/existing");
        let signers_pending_dir = project_dir.join("asfaload.signers.pending");
        tokio::fs::create_dir_all(&project_dir).await.unwrap();
        tokio::fs::write(&signers_pending_dir, "").await.unwrap();

        let test_keys = test_helpers::TestKeys::new(1);
        let public_key = test_keys.pub_key(0).unwrap().clone();

        let config = SignersConfig::with_artifact_signers_only(1, (vec![public_key], 1)).unwrap();
        let project_path =
            get_project_normalised_paths(&git_path, "github.com/test/existing").await?;

        let request = InitialiseSignersRequest {
            project_path,
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
        Ok(())
    }
}
