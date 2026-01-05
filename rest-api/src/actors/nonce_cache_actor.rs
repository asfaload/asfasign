use chrono::{Duration, Utc};
use kameo::prelude::{Actor, Message};
use log::{error, info};
use rest_api_auth::AUTH_SIGNATURE_VALIDITY_MINUTES;
use rest_api_types::errors::ActorError;
use sled;
use std::path::PathBuf;

pub const NONCE_CACHE_DB: &str = "nonce_cache.db";
// FIXME: risk of overflow?
const TTL_MINUTES: i64 = AUTH_SIGNATURE_VALIDITY_MINUTES + 1;

#[derive(Debug, Clone)]
pub enum NonceCacheMessage {
    CheckAndStoreNonce { nonce: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum NonceCacheResponse {
    Accepted,
    Refused,
}

#[derive(Debug)]
pub struct NonceCacheActor {
    db: sled::Db,
    ttl_minutes: i64,
}

impl NonceCacheActor {
    pub fn new(db_path: PathBuf) -> Result<Self, ActorError> {
        let db = sled::open(&db_path)?;

        info!(
            "NonceCacheActor initialized with database at: {:?}",
            db_path
        );

        Ok(Self {
            db,
            ttl_minutes: TTL_MINUTES,
        })
    }
}

impl NonceCacheActor {
    pub async fn check_and_store_nonce(
        &mut self,
        nonce: String,
    ) -> Result<NonceCacheResponse, ActorError> {
        // Fast path: check if nonce already exists
        if self.db.contains_key(nonce.as_bytes())? {
            error!("Replay attack detected: nonce {} already used", nonce);
            return Ok(NonceCacheResponse::Refused);
        }

        // Store nonce with TTL (expiration timestamp)
        let expires_at = Utc::now() + Duration::minutes(self.ttl_minutes);
        self.db
            .insert(nonce.as_bytes(), expires_at.to_rfc3339().as_bytes())?;

        info!(
            "Stored new nonce {} (expires at: {})",
            nonce,
            expires_at.to_rfc3339()
        );

        Ok(NonceCacheResponse::Accepted)
    }
}

impl Message<NonceCacheMessage> for NonceCacheActor {
    type Reply = Result<NonceCacheResponse, ActorError>;

    async fn handle(
        &mut self,
        msg: NonceCacheMessage,
        _ctx: &mut kameo::message::Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            NonceCacheMessage::CheckAndStoreNonce { nonce } => {
                self.check_and_store_nonce(nonce).await
            }
        }
    }
}

impl Actor for NonceCacheActor {
    type Args = PathBuf;
    type Error = ActorError;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        info!("NonceCacheActor starting with db path: {:?}", args);
        Self::new(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kameo::actor::Spawn;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_nonce_cache_actor_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_nonce.db");

        let actor = NonceCacheActor::new(db_path);

        assert!(
            actor.is_ok(),
            "Actor creation should succeed with valid path"
        );
    }

    #[tokio::test]
    async fn test_nonce_acceptance_first_time() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_nonce.db");

        let mut actor = NonceCacheActor::new(db_path).expect("Failed to create actor");

        let nonce = "test_nonce_12345".to_string();

        let result = actor.check_and_store_nonce(nonce).await;

        assert!(result.is_ok(), "Nonce checking should succeed");
        assert_eq!(
            result.unwrap(),
            NonceCacheResponse::Accepted,
            "First-time nonce should be accepted"
        );
    }

    #[tokio::test]
    async fn test_nonce_rejection_replay_attack() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_nonce.db");

        let mut actor = NonceCacheActor::new(db_path).expect("Failed to create actor");

        let nonce = "test_nonce_replay".to_string();

        // First usage should be accepted
        let result1 = actor.check_and_store_nonce(nonce.clone()).await;
        assert!(result1.is_ok(), "First usage should succeed");
        assert_eq!(
            result1.unwrap(),
            NonceCacheResponse::Accepted,
            "First-time nonce should be accepted"
        );

        // Second usage should be refused
        let result2 = actor.check_and_store_nonce(nonce).await;
        assert!(result2.is_ok(), "Second usage should not error");
        assert_eq!(
            result2.unwrap(),
            NonceCacheResponse::Refused,
            "Duplicate nonce should be refused"
        );
    }

    #[tokio::test]
    async fn test_nonce_cache_database_error() {
        let invalid_path = PathBuf::from("/invalid/path/that/does/not/exist/test.db");

        let actor_result = NonceCacheActor::new(invalid_path);

        assert!(
            actor_result.is_err(),
            "Actor creation should fail with invalid path"
        );

        match actor_result.unwrap_err() {
            ActorError::SledError(_) => {} // Expected
            #[allow(unreachable_patterns)]
            other => panic!("Expected SledError, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_concurrent_nonce_handling() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_name = format!("nonce_concurrent_{}.db", Uuid::new_v4());
        let db_path = temp_dir.path().join(db_name);

        let actor = NonceCacheActor::new(db_path).expect("Failed to create actor");
        let actor_arc = std::sync::Arc::new(tokio::sync::Mutex::new(actor));

        let nonce = "concurrent_test_nonce".to_string();

        // Test actual concurrent access using tokio::task with shared mutex
        let actor_clone1 = actor_arc.clone();
        let nonce_clone1 = nonce.clone();
        let handle1 = tokio::task::spawn(async move {
            let mut actor = actor_clone1.lock().await;
            actor.check_and_store_nonce(nonce_clone1).await
        });

        let actor_clone2 = actor_arc.clone();
        let nonce_clone2 = nonce.clone();
        let handle2 = tokio::task::spawn(async move {
            let mut actor = actor_clone2.lock().await;
            actor.check_and_store_nonce(nonce_clone2).await
        });

        let (result1, result2) = tokio::join!(handle1, handle2);

        let result1 = result1.expect("First task should complete successfully");
        let result2 = result2.expect("Second task should complete successfully");

        assert!(result1.is_ok(), "First concurrent usage should succeed");
        assert!(result2.is_ok(), "Second concurrent usage should succeed");

        // One should be accepted, the other refused
        let response1 = result1.unwrap();
        let response2 = result2.unwrap();

        assert!(
            (response1 == NonceCacheResponse::Accepted && response2 == NonceCacheResponse::Refused)
                || (response1 == NonceCacheResponse::Refused
                    && response2 == NonceCacheResponse::Accepted),
            "Exactly one concurrent request should be accepted, got: {:?} and {:?}",
            response1,
            response2
        );
    }

    #[tokio::test]
    async fn test_message_handling_integration() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_name = format!("nonce_message_{}.db", Uuid::new_v4());
        let db_path = temp_dir.path().join(db_name);

        // Create and start the actor using spawn method
        let actor_ref: kameo::actor::ActorRef<NonceCacheActor> = NonceCacheActor::spawn(db_path);

        let nonce = "message_test_nonce".to_string();
        let message = NonceCacheMessage::CheckAndStoreNonce {
            nonce: nonce.clone(),
        };

        // Test actual message sending to the actor
        let result = actor_ref
            .ask(message)
            .await
            .expect("Failed to send message");

        // Verify that the message handling works through the Message trait
        assert_eq!(
            result,
            NonceCacheResponse::Accepted,
            "First-time nonce via message should be accepted"
        );

        // Test that duplicate nonce is refused through message interface
        let duplicate_message = NonceCacheMessage::CheckAndStoreNonce { nonce };
        let duplicate_result = actor_ref
            .ask(duplicate_message)
            .await
            .expect("Failed to send duplicate message");

        assert_eq!(
            duplicate_result,
            NonceCacheResponse::Refused,
            "Duplicate nonce via message should be refused"
        );
    }
}
