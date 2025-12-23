use chrono::{Duration, Utc};
use kameo::prelude::{Actor, Message};
use log::{error, info};
use rest_api_auth::AUTH_SIGNATURE_VALIDITY_MINUTES;
use rest_api_types::errors::ApiError;
use sled;
use std::path::PathBuf;

pub const NONCE_CACHE_DB: &str = "nonce_cache.db";
// FIXME: risk of overflow?
const TTL_MINUTES: i64 = AUTH_SIGNATURE_VALIDITY_MINUTES + 1;

#[derive(Debug, Clone)]
pub enum NonceCacheMessage {
    CheckAndStoreNonce { nonce: String },
}

#[derive(Debug, Clone)]
pub enum NonceCacheResponse {
    Accepted,
    Refused,
}

pub struct NonceCacheActor {
    db: sled::Db,
    ttl_minutes: i64,
}

impl NonceCacheActor {
    pub fn new(db_path: PathBuf) -> Result<Self, ApiError> {
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

impl Message<NonceCacheMessage> for NonceCacheActor {
    type Reply = Result<NonceCacheResponse, ApiError>;

    async fn handle(
        &mut self,
        msg: NonceCacheMessage,
        _ctx: &mut kameo::message::Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            NonceCacheMessage::CheckAndStoreNonce { nonce } => {
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
    }
}

impl Actor for NonceCacheActor {
    type Args = PathBuf;
    type Error = ApiError;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        info!("NonceCacheActor starting with db path: {:?}", args);
        Self::new(args)
    }
}
