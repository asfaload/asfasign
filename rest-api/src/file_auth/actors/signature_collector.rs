use crate::file_auth::actors::git_actor::{CommitFile, GitActor};
use crate::handlers::map_to_user_error;
use crate::path_validation::NormalisedPaths;
use common::errors::AggregateSignatureError;
use features_lib::{
    AsfaloadPublicKeys, AsfaloadSignatures, SignatureWithState, SignedFileLoader,
    activate_signers_file,
};
use kameo::actor::ActorRef;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use std::path::Path;

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
}

/// Actor responsible for collecting individual signatures for aggregate signatures.
///
/// The SignatureCollector handles the generic collection of signatures for any type
/// of aggregate signature (initial signers files, signers file updates, or artifact files).
/// It delegates to the AggregateSignature API for validation and storage, and automatically
/// transitions signatures from pending to complete state when the threshold is reached.
pub struct SignatureCollector {
    git_actor: ActorRef<GitActor>,
}

const ACTOR_NAME: &str = "SignatureCollector";

impl Actor for SignatureCollector {
    type Args = ActorRef<GitActor>;
    type Error = String;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(actor = ACTOR_NAME, "starting");
        Ok(Self { git_actor: args })
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

        let rel_path = msg.file_path.relative_path();
        let rel_parent = rel_path.parent();
        // We do not support signatures for files in the repo's root.
        // This can be fixed (eg the signers_initialiser would need to be
        // updated to not call parent on the signed file), but is currently not
        // a priority as all files are in subdirectories.
        if rel_parent.is_none() || rel_parent == Some(Path::new("")) {
            return Err(ApiError::InvalidRequestBody(
                "Files at git repository root cannot have signatures. Files must be in a subdirectory.".to_string()
            ));
        }

        let file_path = msg.file_path.absolute_path();

        let authorized_signers =
            features_lib::aggregate_signature_helpers::get_authorized_signers_for_file(&file_path)
                .map_err(|e| {
                    tracing::error!(
                        actor = ACTOR_NAME,
                        request_id = %msg.request_id,
                        error = %e,
                        "failed to get authorized signers"
                    );
                    ApiError::InternalServerError("Failed to get authorized signers".to_string())
                })?;

        if !authorized_signers.contains(&msg.public_key) {
            return Err(ApiError::InvalidRequestBody(
                "Public key is not an authorized signer".to_string(),
            ));
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
        let is_complete = new_state.is_complete();

        // If signature is complete and this is a signers file, activate it
        if is_complete {
            let signed_file = SignedFileLoader::load(&msg.file_path);
            if (signed_file.is_initial_signers() || signed_file.is_signers())
                && let SignatureWithState::Complete(complete_agg_sig) = new_state
            {
                activate_signers_file(&complete_agg_sig).map_err(|e| {
                    tracing::error!(
                        actor = ACTOR_NAME,
                        request_id = %msg.request_id,
                        error = %e,
                        "failed to activate signers file"
                    );
                    ApiError::InternalServerError(format!("Failed to activate signers file: {}", e))
                })?;
                tracing::info!(
                    actor = ACTOR_NAME,
                    request_id = %msg.request_id,
                    file_path = %msg.file_path.absolute_path().display(),
                    "Successfully activated signers file"
                );
            }
        }

        let commit_message = if is_complete {
            format!(
                "completed signature collection for {}",
                msg.file_path.relative_path().display()
            )
        } else {
            format!(
                "added partial signature for {}",
                msg.file_path.relative_path().display(),
            )
        };

        let commit_msg = CommitFile {
            file_paths: vec![msg.file_path.parent()],
            commit_message,
            request_id: msg.request_id.to_string(),
        };

        self.git_actor
            .ask(commit_msg)
            .await
            .map_err(|e| map_to_user_error(e, "Failed to commit signature changes"))?;
        // Handle both complete and incomplete states appropriately
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

        Ok(SignatureStatus { is_complete })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constants::{PENDING_SIGNERS_DIR, SIGNATURES_SUFFIX, SIGNERS_DIR, SIGNERS_FILE};
    use features_lib::{AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait, sha512_for_file};
    use git2::{Repository, Signature};
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

    // Helper to initialise a git repo for these tests
    fn initialise_git_repo<P: AsRef<Path>>(repo_path: P) -> anyhow::Result<Repository> {
        let repo = Repository::init(repo_path)?;
        {
            let signature = Signature::now("Test User", "test@example.com")?;
            let tree_oid = repo.index()?.write_tree()?;
            let tree = repo.find_tree(tree_oid)?;
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "Initial commit",
                &tree,
                &[],
            )?;
        }
        Ok(repo)
    }

    #[tokio::test]
    async fn test_collect_signature_for_signers_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        initialise_git_repo(temp_dir.path())?;

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

        // Spawn git actor and signature collector
        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());

        let actor_ref = SignatureCollector::spawn(git_actor);
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

        // After activation, the signers file should be in the active directory
        let active_dir = project_dir.join(SIGNERS_DIR);
        let active_signers_path = active_dir.join(SIGNERS_FILE);

        // The signers file should have been moved to the active directory
        assert!(active_signers_path.exists());

        // The signature path is {file_path}.signatures.json for a complete signature
        let complete_sig_path = format!("{}.{}", active_signers_path.display(), SIGNATURES_SUFFIX);
        let complete_sig_path = std::path::PathBuf::from(complete_sig_path);

        // The signature file should exist in the active directory
        assert!(complete_sig_path.exists());

        // The pending directory should no longer exist
        assert!(!pending_dir.exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_for_artifact_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        initialise_git_repo(temp_dir.path())?;

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

        // Spawn git actor and signature collector
        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());

        let actor_ref = SignatureCollector::spawn(git_actor);
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
        initialise_git_repo(temp_dir.path())?;

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

        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());
        let actor_ref = SignatureCollector::spawn(git_actor);

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

        // After activation, the file path changes from pending to active directory
        let active_signers_path = project_dir.join(SIGNERS_DIR).join(SIGNERS_FILE);
        let active_file_path =
            make_normalised_paths(&temp_dir, active_signers_path.strip_prefix(&temp_dir)?).await;

        // Try to add the same signature again - should fail with "already complete"
        // (because after first signature, the signature file is now complete and activated)
        let result2 = actor_ref
            .ask(CollectSignatureRequest {
                file_path: active_file_path,
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
        initialise_git_repo(temp_dir.path())?;

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

        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());
        let actor_ref = SignatureCollector::spawn(git_actor);

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

        // Add second signature to complete aggregate signature
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

    #[tokio::test]
    async fn test_collect_signature_rejects_root_level_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        initialise_git_repo(temp_dir.path())?;

        // Create signers config
        let key_pair = features_lib::AsfaloadKeyPairs::new("test_password")?;
        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![key_pair.public_key().clone()], 1))?;

        let signers_json = serde_json::to_string_pretty(&signers_config)?;

        // Create signers directory and file
        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;
        std::fs::write(signers_dir.join(SIGNERS_FILE), signers_json)?;

        // Create artifact file at repo root
        let artifact_file = temp_dir.path().join("release.txt");
        std::fs::write(&artifact_file, "artifact content")?;

        // Create the signature
        let public_key = key_pair.public_key();
        let digest = sha512_for_file(&artifact_file)?;
        let secret_key = key_pair.secret_key("test_password")?;
        let signature = secret_key.sign(&digest)?;

        let file_path = make_normalised_paths(&temp_dir, Path::new("release.txt")).await;

        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key,
                signature,
                request_id: "test-root-file".to_string(),
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("Files at git repository root cannot have signatures") => {}
            e => panic!(
                "Expected InvalidRequestBody with root rejection, got {:?}",
                e
            ),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_first_unauthorized_signature() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        initialise_git_repo(temp_dir.path())?;

        let key_pair1 = features_lib::AsfaloadKeyPairs::new("pwd1")?;
        let key_pair2 = features_lib::AsfaloadKeyPairs::new("pwd2")?;
        let key_pair_unauth = features_lib::AsfaloadKeyPairs::new("unauth")?;

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

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;
        std::fs::write(signers_dir.join(SIGNERS_FILE), signers_config.to_json()?)?;

        let artifact_path = "nested/artifact.txt";
        std::fs::create_dir_all(temp_dir.path().join("nested"))?;
        let artifact_full_path = temp_dir.path().join(artifact_path);
        std::fs::write(&artifact_full_path, "content")?;

        let file_path = make_normalised_paths(&temp_dir, artifact_path).await;
        let digest = sha512_for_file(&artifact_full_path)?;
        let signature = key_pair_unauth.secret_key("unauth")?.sign(&digest)?;

        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(artifact_full_path.clone());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: key_pair_unauth.public_key(),
                signature,
                request_id: "test-unauth-1".to_string(),
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("not an authorized signer") => {}
            e => panic!("Expected unauthorized signer error, got {:?}", e),
        }

        let pending_sig_path = common::fs::names::pending_signatures_path_for(&artifact_full_path)?;
        assert!(
            !pending_sig_path.exists(),
            "Pending signatures should not be created when signature is unauthorized"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_unauthorized_for_signers_update() -> anyhow::Result<()>
    {
        let temp_dir = TempDir::new()?;
        initialise_git_repo(temp_dir.path())?;

        // Create old signers config with admin (key 0) and master (key 1)
        let key_pair0 = features_lib::AsfaloadKeyPairs::new("pwd0")?;
        let key_pair1 = features_lib::AsfaloadKeyPairs::new("pwd1")?;
        let key_pair_unauth = features_lib::AsfaloadKeyPairs::new("unauth")?;
        let key_pair2 = features_lib::AsfaloadKeyPairs::new("pwd2")?;

        // First, establish the current signers configuration
        // We create a config with admin and master signers (existing signers for the signers file)
        let old_config = SignersConfig::with_keys(
            1,
            (vec![], 1),
            Some((vec![key_pair0.public_key().clone()], 1)),
            Some((vec![key_pair1.public_key().clone()], 1)),
        )?;

        let signers_dir = temp_dir.path().join(SIGNERS_DIR);
        std::fs::create_dir_all(&signers_dir)?;
        std::fs::write(
            signers_dir.join(SIGNERS_FILE),
            serde_json::to_string_pretty(&old_config)?,
        )?;

        // Create new signers config (in pending) that adds key_pair2 as artifact signer
        let new_config = SignersConfig::with_keys(
            2,
            (vec![key_pair2.public_key().clone()], 1),
            Some((vec![key_pair0.public_key().clone()], 1)),
            Some((vec![key_pair1.public_key().clone()], 1)),
        )?;
        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;
        std::fs::write(
            pending_dir.join(SIGNERS_FILE),
            serde_json::to_string_pretty(&new_config)?,
        )?;

        // Try to sign the pending signers file with unauthorized key
        // The relative path should be "asfaload.signers.pending/index.json"
        let relative_path = format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE);
        let file_path = make_normalised_paths(&temp_dir, &relative_path).await;

        let digest = sha512_for_file(&pending_dir.join(SIGNERS_FILE))?;
        let signature = key_pair_unauth.secret_key("unauth")?.sign(&digest)?;

        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: key_pair_unauth.public_key(),
                signature,
                request_id: "test-unauth-signers".to_string(),
            })
            .await;

        // Should fail - key_pair_unauth is not authorized
        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("not an authorized signer") => {}
            e => panic!("Expected unauthorized signer error, got {:?}", e),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_collect_signature_rejects_unauthorized_for_initial_signers() -> anyhow::Result<()>
    {
        let temp_dir = TempDir::new()?;
        initialise_git_repo(temp_dir.path())?;

        // Create initial signers config
        let key_pair1 = features_lib::AsfaloadKeyPairs::new("pwd1")?;
        let key_pair2 = features_lib::AsfaloadKeyPairs::new("pwd2")?;
        let key_pair_unauth = features_lib::AsfaloadKeyPairs::new("unauth")?;

        let config = SignersConfig::with_artifact_signers_only(
            2,
            (
                vec![
                    key_pair1.public_key().clone(),
                    key_pair2.public_key().clone(),
                ],
                2,
            ),
        )?;

        let pending_dir = temp_dir.path().join(PENDING_SIGNERS_DIR);
        std::fs::create_dir_all(&pending_dir)?;
        std::fs::write(
            pending_dir.join(SIGNERS_FILE),
            serde_json::to_string_pretty(&config)?,
        )?;

        // Try to sign with unauthorized key
        let relative_path = format!("{}/{}", PENDING_SIGNERS_DIR, SIGNERS_FILE);
        let file_path = make_normalised_paths(&temp_dir, &relative_path).await;

        let digest = sha512_for_file(&pending_dir.join(SIGNERS_FILE))?;
        let signature = key_pair_unauth.secret_key("unauth")?.sign(&digest)?;

        let git_actor =
            crate::file_auth::actors::git_actor::GitActor::spawn(temp_dir.path().to_path_buf());
        let actor_ref = SignatureCollector::spawn(git_actor);

        let result = actor_ref
            .ask(CollectSignatureRequest {
                file_path,
                public_key: key_pair_unauth.public_key(),
                signature,
                request_id: "test-unauth-initial".to_string(),
            })
            .await;

        // Should fail
        assert!(result.is_err());
        match result.unwrap_err() {
            kameo::error::SendError::HandlerError(ApiError::InvalidRequestBody(msg))
                if msg.contains("not an authorized signer") => {}
            e => panic!("Expected unauthorized signer error, got {:?}", e),
        }

        Ok(())
    }
}
