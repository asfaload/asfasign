use crate::path_validation::NormalisedPaths;
use common::errors::AggregateSignatureError;
use features_lib::{
    AsfaloadPublicKeys, AsfaloadSignatures, SignatureWithState,
    aggregate_signature_helpers::get_individual_signatures,
};
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;

/// Request to collect a signature for a specific file.
///
/// This request is sent to the SignatureCollector actor to add an individual
/// signature to a file's aggregate signature collection.
#[derive(Debug, Clone)]
pub struct CollectSignatureRequest {
    /// Normalised path to the file being signed
    pub file_path: NormalisedPaths,
    /// Public key of the signer
    pub public_key: AsfaloadPublicKeys,
    /// Signature data
    pub signature: AsfaloadSignatures,
    /// Request ID for tracing and logging
    pub request_id: String,
}

/// Result of a signature collection operation.
///
/// Returns the completion status of the aggregate signature after adding
/// the individual signature.
#[derive(Debug, Clone)]
pub struct CollectSignatureResult {
    /// Whether the aggregate signature is now complete
    pub is_complete: bool,
    /// Request ID from the original request
    pub request_id: String,
}

/// Request to query the current status of a file's signature collection.
#[derive(Debug, Clone)]
pub struct GetSignatureStatusRequest {
    /// Normalised path to the file
    pub file_path: NormalisedPaths,
    /// Request ID for tracing and logging
    pub request_id: String,
}

/// Status of signature collection for a file.
#[derive(Debug, Clone)]
pub struct SignatureStatus {
    /// Whether the aggregate signature is complete
    pub is_complete: bool,
    /// Number of individual signatures collected so far
    pub collected_count: u32,
}

/// Actor responsible for collecting individual signatures for aggregate signatures.
///
/// The SignatureCollector handles the generic collection of signatures for any type
/// of aggregate signature (initial signers files, signers file updates, or artifact files).
/// It delegates to the AggregateSignature API for validation and storage, and automatically
/// transitions signatures from pending to complete state when the threshold is reached.
pub struct SignatureCollector;

const ACTOR_NAME: &str = "SignatureCollector";

impl Actor for SignatureCollector {
    type Args = ();
    type Error = String;

    async fn on_start(
        _args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(actor = ACTOR_NAME, "starting");
        Ok(Self)
    }
}

impl Message<CollectSignatureRequest> for SignatureCollector {
    type Reply = Result<CollectSignatureResult, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: CollectSignatureRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            "received signature collection request"
        );

        if !msg.file_path.absolute_path().exists() {
            return Err(ApiError::InvalidRequestBody(format!(
                "File not found: {}",
                msg.file_path.absolute_path().display()
            )));
        }

        let signature_with_state =
            SignatureWithState::load_for_file(&msg.file_path).map_err(|e| {
                tracing::error!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    error = %e,
                    "failed to load aggregate signature"
                );
                ApiError::InternalServerError("Failed to load aggregate signature".to_string())
            })?;

        let pending_agg = signature_with_state.get_pending().ok_or_else(|| {
            ApiError::InvalidRequestBody("Aggregate signature is already complete".to_string())
        })?;

        let new_state = pending_agg
            .add_individual_signature(&msg.signature, &msg.public_key)
            .map_err(|e| {
                tracing::error!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    error = %e,
                    "failed to add individual signature"
                );
                match e {
                    AggregateSignatureError::Signature(msg) => {
                        if msg.contains("signature verification failed") {
                            ApiError::SignatureVerificationFailed
                        } else {
                            ApiError::InternalServerError(msg)
                        }
                    }
                    AggregateSignatureError::Io(io) => {
                        if io.kind() == std::io::ErrorKind::AlreadyExists {
                            ApiError::InvalidRequestBody("Signature already added".to_string())
                        } else {
                            ApiError::InternalServerError(format!("IO error: {}", io))
                        }
                    }
                    _ => ApiError::InternalServerError(e.to_string()),
                }
            })?;

        // Handle both complete and incomplete states appropriately
        let is_complete = new_state.is_complete();
        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            is_complete = %is_complete,
            "Added individual signature to aggregate signature"
        );

        Ok(CollectSignatureResult {
            is_complete,
            request_id: msg.request_id.clone(),
        })
    }
}

impl Message<GetSignatureStatusRequest> for SignatureCollector {
    type Reply = Result<SignatureStatus, ApiError>;

    #[tracing::instrument(skip(self, msg, _ctx))]
    async fn handle(
        &mut self,
        msg: GetSignatureStatusRequest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::debug!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            "received status request"
        );

        // Load the aggregate signature
        let signature_with_state =
            SignatureWithState::load_for_file(&msg.file_path).map_err(|e| {
                tracing::error!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    error = %e,
                    "failed to load aggregate signature"
                );
                ApiError::InternalServerError("Failed to load aggregate signature".to_string())
            })?;

        let is_complete = signature_with_state.is_complete();

        let collected_count = {
            use common::fs::names::{pending_signatures_path_for, signatures_path_for};

            let sig_file_path = if is_complete {
                signatures_path_for(&msg.file_path)?
            } else {
                pending_signatures_path_for(&msg.file_path)?
            };

            let signatures = get_individual_signatures(&sig_file_path).map_err(|e| {
                tracing::error!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    error = %e,
                    "failed to get individual signatures"
                );
                ApiError::InternalServerError("Failed to read signatures".to_string())
            })?;

            signatures.len() as u32
        };

        Ok(SignatureStatus {
            is_complete,
            collected_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::fs::names::{PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait, sha512_for_file};
    use kameo::actor::Spawn;
    use signers_file_types::SignersConfig;
    use std::{
        path::{Path, PathBuf},
        str::FromStr,
    };
    use tempfile::TempDir;

    // Helper function to create NormalisedPaths for testing
    async fn make_normalised_paths<P: AsRef<Path>>(
        base: &tempfile::TempDir,
        relative: P,
    ) -> NormalisedPaths {
        NormalisedPaths::new(base.path(), relative).await.unwrap()
    }

    #[tokio::test]
    async fn test_collect_signature_for_signers_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let pending_signers_path = pending_dir.join(SIGNERS_FILE);

        // Create directory structure
        std::fs::create_dir_all(&pending_dir)?;

        // Create test keys
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let public_key = key_pair.public_key();

        // Create signers config with 1 signer, threshold 1
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(&pending_signers_path, signers_json)?;

        // Create the signature
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;

        // Create NormalisedPaths
        let file_path =
            make_normalised_paths(&temp_dir, &pending_signers_path.strip_prefix(&temp_dir)?).await;

        // Spawn the actor and send request
        let actor_ref = SignatureCollector::spawn(());
        let request = CollectSignatureRequest {
            file_path,
            public_key,
            signature,
            request_id: "test-123".to_string(),
        };

        let result = actor_ref.ask(request).await;

        // Note: With 1 signer at threshold 1, the signature becomes complete
        assert!(result.is_ok());
        let collect_result = result.unwrap();

        assert!(collect_result.is_complete);

        // The signers file doesn't move - only the signature file transitions
        // from .pending to complete.
        // The signature path is {file_path}.signatures.json for a complete signature
        let complete_sig_path = format!("{}.{}", pending_signers_path.display(), SIGNATURES_SUFFIX);
        let complete_sig_path = std::path::PathBuf::from(complete_sig_path);

        // The signature file should exist
        assert!(complete_sig_path.exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_for_artifact_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;

        // Create signers config
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![key_pair.public_key().clone()], 1))?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(signers_dir.join(SIGNERS_FILE), signers_json)?;

        // Create artifact file
        let artifact_path = "my/nested/dir/with/release.txt";
        std::fs::create_dir_all(
            temp_dir
                .path()
                .join(PathBuf::from_str(artifact_path)?.parent().unwrap()),
        )?;
        let artifact_file = temp_dir.path().join(artifact_path);
        std::fs::write(&artifact_file, "artifact content")?;

        // Create the signature
        let public_key = key_pair.public_key();
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;

        let file_path = make_normalised_paths(&temp_dir, &artifact_path).await;

        // Spawn the actor and send request
        let actor_ref = SignatureCollector::spawn(());
        let request = CollectSignatureRequest {
            file_path,
            public_key,
            signature,
            request_id: "test-456".to_string(),
        };

        let result = actor_ref.ask(request).await;

        assert!(result.is_ok());
        let collect_result = result.unwrap();

        assert!(collect_result.is_complete);

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_second_attempt_after_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let pending_signers_path = pending_dir.join(SIGNERS_FILE);

        std::fs::create_dir_all(&pending_dir)?;

        // Create key pair
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![key_pair.public_key().clone()], 1))?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(&pending_signers_path, signers_json)?;

        // Create a signature
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;
        let public_key = key_pair.public_key();

        let file_path =
            make_normalised_paths(&temp_dir, pending_signers_path.strip_prefix(&temp_dir)?).await;

        let actor_ref = SignatureCollector::spawn(());

        // Add the signature first time - should succeed and complete
        let result1 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key.clone(),
                signature: signature.clone(),
                request_id: "first-sign".to_string(),
            })
            .await;
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_complete);

        // Try to add the same signature again - should fail with "already complete"
        // (because after first signature, the signature file is now complete)
        let result2 = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key,
                signature,
                request_id: "duplicate-sign".to_string(),
            })
            .await;

        assert!(result2.is_err());
        match result2.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("already complete") => {}
            e => panic!(
                "Expected InvalidRequestBody with 'already complete', got {:?}",
                e
            ),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_partial_completion() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join(PENDING_SIGNERS_DIR);
        let pending_signers_path = pending_dir.join(SIGNERS_FILE);

        std::fs::create_dir_all(&pending_dir)?;

        // Create test keys - we'll need 2 for threshold > 1
        let key_pair1 = features_lib::AsfaloadKeyPairs::new("test_password1")?;
        let key_pair2 = features_lib::AsfaloadKeyPairs::new("test_password2")?;

        // Create signers config with 2 signers, threshold 2
        let signers_config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    key_pair1.public_key().clone(),
                    key_pair2.public_key().clone(),
                ],
                2,
            ),
        )?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(&pending_signers_path, signers_json)?;

        // Create first signature
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key1 = key_pair1.secret_key("test_password1")?;
        let signature1 = secret_key1.sign(&digest)?;
        let public_key1 = key_pair1.public_key();

        let file_path =
            make_normalised_paths(&temp_dir, pending_signers_path.strip_prefix(&temp_dir)?).await;

        let actor_ref = SignatureCollector::spawn(());

        // Add first signature - should return is_complete: false
        let result1 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key1,
                signature: signature1,
                request_id: "first-sign".to_string(),
            })
            .await;

        assert!(result1.is_ok());
        let collect_result1 = result1.unwrap();
        assert!(!collect_result1.is_complete); // Should be false - threshold not met yet

        // Add second signature ti complete aggregate signature
        let secret_key2 = key_pair2.secret_key("test_password2")?;
        let signature2 = secret_key2.sign(&digest)?;
        let public_key2 = key_pair2.public_key();
        let result2 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key2,
                signature: signature2,
                request_id: "second-sign".to_string(),
            })
            .await;

        assert!(result2.is_ok());
        let collect_result2 = result2.unwrap();
        assert!(collect_result2.is_complete);

        Ok(())
    }
}
