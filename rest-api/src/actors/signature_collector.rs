use crate::path_validation::NormalisedPaths;
use features_lib::{
    AsfaloadPublicKeys, AsfaloadSignatures, SignatureWithState,
    aggregate_signature_helpers::get_individual_signatures,
};
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;

#[derive(Debug, Clone)]
pub struct CollectSignatureRequest {
    pub file_path: NormalisedPaths,
    pub public_key: AsfaloadPublicKeys,
    pub signature: AsfaloadSignatures,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct CollectSignatureResult {
    pub is_complete: bool,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct GetSignatureStatusRequest {
    pub file_path: NormalisedPaths,
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub struct SignatureStatus {
    pub is_complete: bool,
    pub collected_count: u32,
}

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

        // 1. Check if the file exists
        if !msg.file_path.absolute_path().exists() {
            return Err(ApiError::InvalidRequestBody(format!(
                "File not found: {}",
                msg.file_path.absolute_path().display()
            )));
        }

        // 2. Load the aggregate signature (handles both pending and complete states)
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

        // 3. Get the pending aggregate - only pending signatures can be added to
        let pending_agg = signature_with_state.get_pending().ok_or_else(|| {
            ApiError::InvalidRequestBody("Aggregate signature is already complete".to_string())
        })?;

        // 4. Add the individual signature - this handles:
        //    - Signature validation
        //    - Adding to pending file
        //    - Transparent transition to complete if all signatures collected
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
                    features_lib::errors::AggregateSignatureError::Signature(msg) => {
                        if msg.contains("signature verification failed") {
                            ApiError::SignatureVerificationFailed
                        } else {
                            ApiError::InternalServerError(msg)
                        }
                    }
                    features_lib::errors::AggregateSignatureError::Io(io) => {
                        if io.kind() == std::io::ErrorKind::AlreadyExists {
                            ApiError::InvalidRequestBody("Signature already added".to_string())
                        } else {
                            ApiError::InternalServerError(format!("IO error: {}", io))
                        }
                    }
                    features_lib::errors::AggregateSignatureError::IsIncomplete => {
                        // This is OK - just means still pending
                        ApiError::InternalServerError("Unexpected incompleteness error".to_string())
                    }
                    _ => ApiError::InternalServerError(e.to_string()),
                }
            })?;

        tracing::info!(
            actor = ACTOR_NAME,
            request_id = %msg.request_id,
            file_path = %msg.file_path.absolute_path().display(),
            is_complete = new_state.is_complete(),
            "signature collected successfully"
        );

        Ok(CollectSignatureResult {
            is_complete: new_state.is_complete(),
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

        // Get collected count - Note: AggregateSignature doesn't expose signatures() method directly
        // We'll need to load from disk to get the count
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
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait, sha512_for_file};
    use kameo::actor::Spawn;
    use signers_file_types::SignersConfig;
    use tempfile::TempDir;

    // Helper function to create NormalisedPaths for testing
    async fn make_normalised_paths(base: &tempfile::TempDir, relative: &str) -> NormalisedPaths {
        NormalisedPaths::new(base.path(), relative).await.unwrap()
    }

    #[tokio::test]
    async fn test_collect_signature_for_signers_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join("asfaload.signers.pending");
        let pending_signers_path = pending_dir.join("index.json");

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
        let file_path = make_normalised_paths(
            &temp_dir,
            "github.com/test/repo/asfaload.signers.pending/index.json",
        )
        .await;

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
        let complete_sig_path = format!("{}.signatures.json", pending_signers_path.display());
        let complete_sig_path = std::path::PathBuf::from(complete_sig_path);

        // The signature file should exist
        assert!(complete_sig_path.exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_for_artifact_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let signers_dir = temp_dir.path().join("asfaload.signers");
        std::fs::create_dir_all(&signers_dir)?;

        // Create signers config
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![key_pair.public_key().clone()], 1))?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(signers_dir.join("index.json"), signers_json)?;

        // Create artifact file
        let artifact_file = temp_dir.path().join("release.txt");
        std::fs::write(&artifact_file, "artifact content")?;

        // Create the signature
        let public_key = key_pair.public_key();
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;

        let file_path = make_normalised_paths(&temp_dir, "release.txt").await;

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
    async fn test_collect_signature_duplicate() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join("asfaload.signers.pending");
        let pending_signers_path = pending_dir.join("index.json");

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

        let file_path = make_normalised_paths(
            &temp_dir,
            "github.com/test/repo/asfaload.signers.pending/index.json",
        )
        .await;

        let actor_ref = SignatureCollector::spawn(());

        // Add the signature first time - should succeed
        let result1 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key.clone(),
                signature: signature.clone(),
                request_id: "first-sign".to_string(),
            })
            .await;
        assert!(result1.is_ok());

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
    async fn test_collect_signature_already_complete() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("github.com/test/repo");
        let pending_dir = project_dir.join("asfaload.signers.pending");
        let pending_signers_path = pending_dir.join("index.json");

        std::fs::create_dir_all(&pending_dir)?;

        // Create test keys
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![key_pair.public_key().clone()], 1))?;
        let signers_json = serde_json::to_string_pretty(&signers_config)?;
        std::fs::write(&pending_signers_path, signers_json)?;

        // Complete the signature first
        let digest = sha512_for_file(&pending_signers_path)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;
        let public_key = key_pair.public_key();

        let file_path = make_normalised_paths(
            &temp_dir,
            "github.com/test/repo/asfaload.signers.pending/index.json",
        )
        .await;

        let actor_ref = SignatureCollector::spawn(());
        actor_ref
            .ask(CollectSignatureRequest {
                file_path: file_path.clone(),
                public_key: public_key.clone(),
                signature: signature.clone(),
                request_id: "first-sign".to_string(),
            })
            .await?;

        // Try to add another signature to the now-complete signature
        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key,
                signature,
                request_id: "second-sign".to_string(),
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("already complete") => {}
            e => panic!(
                "Expected InvalidRequestBody with 'already complete', got {:?}",
                e
            ),
        }

        Ok(())
    }
}
