use chrono::{DateTime, Utc};
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use log::info;
use rest_api_auth::AUTH_SIGNATURE_VALIDITY_MINUTES;
use rest_api_types::errors::ApiError;
use sled;
use std::path::PathBuf;
use tokio::{task, time};

const CLEANUP_INTERVAL_MINUTES: i64 = AUTH_SIGNATURE_VALIDITY_MINUTES
    .checked_mul(2)
    .expect("CLEANUP_INTERVAL_MINUTES value overflows");

mod logic {
    use chrono::{DateTime, Utc};

    #[derive(Debug)]
    pub struct CleanupPlan {
        pub current_time: DateTime<Utc>,
    }

    pub fn plan_cleanup(current_time: DateTime<Utc>) -> CleanupPlan {
        // Pure logic - just returns current time
        // Real filtering will happen in effects where we can access the DB
        CleanupPlan { current_time }
    }
}

mod effects {
    use super::logic::CleanupPlan;
    use super::*;

    pub fn execute_cleanup(plan: CleanupPlan, db: &sled::Db) -> Result<usize, ApiError> {
        let mut removed_count = 0;
        let current_time = plan.current_time;

        // Iterate through all entries and remove expired ones
        for result in db.iter() {
            let (key, value) = result?;

            if let Ok(expires_at_str) = std::str::from_utf8(&value)
                && let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_at_str)
                && expires_at < current_time
            {
                db.remove(&key)?;
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            info!("Cleaned up {} expired nonces", removed_count);
        }

        Ok(removed_count)
    }
}

#[derive(Debug, Clone)]
pub enum NonceCleanupMessage {
    PerformCleanup,
}

#[derive(Debug, Clone)]
pub enum NonceCleanupResponse {
    CleanupCompleted { removed_count: usize },
}

pub struct NonceCleanupActor {
    db: sled::Db,
    cleanup_interval: std::time::Duration,
}

impl NonceCleanupActor {
    pub fn new(db_path: PathBuf) -> Result<Self, ApiError> {
        let db = sled::open(&db_path)?;

        info!(
            "NonceCleanupActor initialized with database at: {:?}",
            db_path
        );

        Ok(Self {
            db,
            cleanup_interval: time::Duration::from_secs(
                (CLEANUP_INTERVAL_MINUTES as u64)
                    .checked_mul(60)
                    .expect("CLEANUP_INTERVAL_MINUTES values overflows when converted to seconds"),
            ),
        })
    }
}

impl Message<NonceCleanupMessage> for NonceCleanupActor {
    type Reply = Result<NonceCleanupResponse, ApiError>;

    async fn handle(
        &mut self,
        msg: NonceCleanupMessage,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            NonceCleanupMessage::PerformCleanup => {
                let plan = logic::plan_cleanup(Utc::now());
                let db_clone = self.db.clone();

                // spawn blocking operation to not block the current thread
                let join_handle =
                    task::spawn_blocking(move || effects::execute_cleanup(plan, &db_clone));

                let cleanup_result = join_handle.await;
                let removed_count = match cleanup_result {
                    // Ok(inner_result) - Blocking task finished (successfully or with an inner error)
                    Ok(inner_result) => {
                        // Propagate the inner `Result<usize, ApiError>`
                        inner_result
                    }
                    // Err(join_error) - Blocking thread panicked or was cancelled
                    Err(join_error) => {
                        // The error type of `Self::Reply` is `ApiError`.
                        // We need to convert the `tokio::task::JoinError` into an `ApiError`.
                        let err_msg =
                            format!("Nonce cleanup spawned thread failed: {:?}", join_error);
                        return Err(ApiError::ActorOperationFailed(err_msg));
                    }
                }?;

                let self_ref = ctx.actor_ref().clone();
                let cleanup_interval = self.cleanup_interval;

                // Schedule the next cleanup using the pattern you specified
                tokio::spawn(async move {
                    time::sleep(cleanup_interval).await;
                    let _ = self_ref.tell(NonceCleanupMessage::PerformCleanup).await;
                });

                Ok(NonceCleanupResponse::CleanupCompleted { removed_count })
            }
        }
    }
}

impl Actor for NonceCleanupActor {
    type Args = PathBuf;
    type Error = ApiError;

    async fn on_start(
        args: Self::Args,
        actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        info!("NonceCleanupActor starting with db path: {:?}", args);
        let actor = Self::new(args)?;

        // Start the cleanup cycle immediately
        let _ = actor_ref.tell(NonceCleanupMessage::PerformCleanup).await;

        Ok(actor)
    }
}
