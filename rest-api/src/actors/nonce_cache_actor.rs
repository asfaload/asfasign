use chrono::{Duration, Utc};
use kameo::prelude::{Actor, Message};
use rest_api_auth::AUTH_SIGNATURE_VALIDITY_MINUTES;
use rest_api_types::errors::ActorError;
use sled;

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
    pub fn new(db: sled::Db) -> Result<Self, ActorError> {
        tracing::info!("NonceCacheActor initialized");

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
            tracing::error!(nonce = %nonce, "Replay attack detected: nonce already used");
            return Ok(NonceCacheResponse::Refused);
        }

        // Store nonce with TTL (expiration timestamp)
        let expires_at = Utc::now() + Duration::minutes(self.ttl_minutes);
        self.db
            .insert(nonce.as_bytes(), expires_at.to_rfc3339().as_bytes())?;

        tracing::info!(
            nonce = %nonce,
            expires_at = %expires_at.to_rfc3339(),
            "Stored new nonce"
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
    type Args = sled::Db;
    type Error = ActorError;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!("NonceCacheActor starting");
        Self::new(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use kameo::actor::Spawn;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_nonce_cache_actor_creation() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_nonce.db");
        let db = sled::open(db_path).unwrap();

        let actor = NonceCacheActor::new(db);

        assert!(
            actor.is_ok(),
            "Actor creation should succeed with valid path"
        );
    }

    #[tokio::test]
    async fn test_nonce_acceptance_first_time() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_nonce.db");
        let db = sled::open(db_path).unwrap();

        let mut actor = NonceCacheActor::new(db).expect("Failed to create actor");

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
        let db = sled::open(db_path).unwrap();

        let mut actor = NonceCacheActor::new(db).expect("Failed to create actor");

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
    async fn test_concurrent_message_handling() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir
            .path()
            .join(format!("nonce_concurrent_msg_{}.db", Uuid::new_v4()));
        let db = sled::open(db_path).unwrap();

        let actor_ref = NonceCacheActor::spawn(db);
        actor_ref.wait_for_startup().await;

        let nonce = "concurrent_message_nonce".to_string();
        let mut handles = vec![];

        // Spawn 10 tasks that all try to use the same nonce concurrently
        for _ in 0..10 {
            let actor_ref_clone = actor_ref.clone();
            let nonce_clone = nonce.clone();
            handles.push(tokio::spawn(async move {
                actor_ref_clone
                    .ask(NonceCacheMessage::CheckAndStoreNonce { nonce: nonce_clone })
                    .await
            }));
        }

        let results = futures::future::join_all(handles).await;

        let accepted_count = results
            .into_iter()
            .filter_map(Result::ok) // Filter out JoinErrors
            .filter_map(Result::ok) // Filter out AskErrors
            .filter(|res| *res == NonceCacheResponse::Accepted)
            .count();

        assert_eq!(
            accepted_count, 1,
            "Exactly one of the concurrent requests should be accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_message_handling_integration() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_name = format!("nonce_message_{}.db", Uuid::new_v4());
        let db_path = temp_dir.path().join(db_name);
        let db = sled::open(db_path).unwrap();

        // Create and start the actor using spawn method
        let actor_ref: kameo::actor::ActorRef<NonceCacheActor> = NonceCacheActor::spawn(db);

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
