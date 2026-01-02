use chrono::Duration;
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

// Pure logic module
mod logic {
    use super::*;
    use chrono::{DateTime, Utc};

    #[derive(Debug)]
    pub struct NonceValidationPlan {
        pub nonce: String,
        pub timestamp: DateTime<Utc>,
    }

    pub fn plan_nonce_check(
        nonce: String,
        _max_age_seconds: i64,
    ) -> Result<NonceValidationPlan, ApiError> {
        // Pure validation logic
        if nonce.trim().is_empty() {
            return Err(ApiError::InvalidNonce("Nonce cannot be empty".to_string()));
        }

        if nonce.len() > 256 {
            return Err(ApiError::InvalidNonce("Nonce too long".to_string()));
        }

        Ok(NonceValidationPlan {
            nonce,
            timestamp: Utc::now(),
        })
    }
}

// Effect handler module
mod effects {
    use super::logic::NonceValidationPlan;
    use super::*;

    pub async fn execute_nonce_check(
        plan: NonceValidationPlan,
        db: &sled::Db,
        ttl_minutes: i64,
    ) -> Result<NonceCacheResponse, ApiError> {
        // Check if nonce exists
        if db.get(&plan.nonce)?.is_some() {
            error!("Replay attack detected: nonce {} already used", &plan.nonce);
            return Ok(NonceCacheResponse::Refused); // Already exists
        }

        // Store nonce with expiration
        let expires_at = plan.timestamp + Duration::minutes(ttl_minutes);
        db.insert(&plan.nonce, expires_at.to_rfc3339().as_bytes())?;
        info!("Stored new nonce {}", &plan.nonce);

        Ok(NonceCacheResponse::Accepted)
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
                match logic::plan_nonce_check(nonce.clone(), self.ttl_minutes * 60) {
                    Ok(plan) => {
                        effects::execute_nonce_check(plan, &self.db, self.ttl_minutes).await
                    }
                    Err(e) => Err(e),
                }
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
