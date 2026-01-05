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

    /// Clean up expired nonces from the database
    /// This is a synchronous function that is blocking, so needs to be called in spawn_blocking
    fn cleanup_expired_nonces(db: &sled::Db) -> Result<usize, ApiError> {
        let now = Utc::now();
        let mut removed_count = 0;

        // Iterate through all entries and remove expired ones
        for result in db.iter() {
            let (key, value) = result?;

            if let Ok(expires_at_str) = std::str::from_utf8(&value)
                && let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_at_str)
                && expires_at < now
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

impl Message<NonceCleanupMessage> for NonceCleanupActor {
    type Reply = Result<NonceCleanupResponse, ApiError>;

    async fn handle(
        &mut self,
        msg: NonceCleanupMessage,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            NonceCleanupMessage::PerformCleanup => {
                let db_clone = self.db.clone();

                // spawn blocking operation to not block the current thread
                let join_handle = task::spawn_blocking(move || {
                    NonceCleanupActor::cleanup_expired_nonces(&db_clone)
                });
                // We get the result of the spanwed code by awaiting its join handle.
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
                        return Err(ApiError::ServerSetupError(std::io::Error::other(err_msg)));
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use chrono::{DateTime, Duration, Utc};
    use std::path::Path;
    use tempfile::TempDir;
    use uuid::Uuid;

    /// Helper function to create a test database with sample nonces
    fn create_test_database_with_nonces(db_path: &Path) -> Result<sled::Db, ApiError> {
        let db = sled::open(db_path)?;
        let now = Utc::now();

        // Add some valid nonces (expire in the future)
        let valid_nonce_1 = Uuid::new_v4().to_string();
        let valid_expires_1 = (now + Duration::minutes(10)).to_rfc3339();
        db.insert(valid_nonce_1.as_bytes(), valid_expires_1.as_bytes())?;

        let valid_nonce_2 = Uuid::new_v4().to_string();
        let valid_expires_2 = (now + Duration::minutes(20)).to_rfc3339();
        db.insert(valid_nonce_2.as_bytes(), valid_expires_2.as_bytes())?;

        // Add some expired nonces (expire in the past)
        let expired_nonce_1 = Uuid::new_v4().to_string();
        let expired_expires_1 = (now - Duration::minutes(5)).to_rfc3339();
        db.insert(expired_nonce_1.as_bytes(), expired_expires_1.as_bytes())?;

        let expired_nonce_2 = Uuid::new_v4().to_string();
        let expired_expires_2 = (now - Duration::minutes(15)).to_rfc3339();
        db.insert(expired_nonce_2.as_bytes(), expired_expires_2.as_bytes())?;

        // Add a malformed timestamp entry
        let malformed_nonce = Uuid::new_v4().to_string();
        db.insert(malformed_nonce.as_bytes(), "invalid-timestamp".as_bytes())?;

        Ok(db)
    }

    #[tokio::test]
    async fn test_nonce_cleanup_actor_creation() -> Result<()> {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().to_path_buf();

        let actor = NonceCleanupActor::new(db_path.clone())?;

        // Verify the database was created
        assert!(db_path.exists(), "Database path should exist");

        // Verify cleanup interval is set correctly
        let expected_interval = Duration::minutes(AUTH_SIGNATURE_VALIDITY_MINUTES * 2);
        let actual_interval_seconds = actor.cleanup_interval.as_secs();
        let expected_interval_seconds = expected_interval.num_seconds() as u64;
        assert_eq!(
            actual_interval_seconds, expected_interval_seconds,
            "Cleanup interval should be twice the signature validity period"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_expired_nonces() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db = create_test_database_with_nonces(temp_dir.path())
            .expect("Failed to create test database");

        // Count initial entries
        let initial_count: usize = db.iter().count();
        assert_eq!(initial_count, 5, "Should have 5 initial entries");

        let result = NonceCleanupActor::cleanup_expired_nonces(&db);

        assert!(result.is_ok(), "Cleanup should succeed");
        let removed_count = result.unwrap();
        assert_eq!(removed_count, 2, "Should remove exactly 2 expired nonces");

        // Verify remaining entries
        let remaining_count: usize = db.iter().count();
        assert_eq!(remaining_count, 3, "Should have 3 remaining entries");

        // Verify that expired nonces are gone and valid ones remain
        let now = Utc::now();
        let mut valid_count = 0;
        let mut malformed_count = 0;

        for result in db.iter() {
            let (_key, value) = result.expect("Should be able to read entry");

            if let Ok(expires_at_str) = std::str::from_utf8(&value) {
                if let Ok(expires_at) = DateTime::parse_from_rfc3339(expires_at_str) {
                    if expires_at > now {
                        valid_count += 1;
                    }
                } else {
                    malformed_count += 1; // Invalid RFC3339 format
                }
            } else {
                malformed_count += 1; // Invalid UTF-8
            }
        }

        assert_eq!(valid_count, 2, "Should have 2 valid nonces remaining");
        assert_eq!(
            malformed_count, 1,
            "Should have 1 malformed timestamp entry remaining"
        );
    }

    #[tokio::test]
    async fn test_cleanup_empty_database() {
        // Arrange
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db = sled::open(temp_dir.path()).expect("Failed to create empty database");

        // Verify database is empty
        let initial_count: usize = db.iter().count();
        assert_eq!(initial_count, 0, "Database should be empty initially");

        // Act
        let result = NonceCleanupActor::cleanup_expired_nonces(&db);

        // Assert
        assert!(
            result.is_ok(),
            "Cleanup should succeed even on empty database"
        );
        let removed_count = result.unwrap();
        assert_eq!(
            removed_count, 0,
            "Should remove 0 entries from empty database"
        );

        // Verify database is still empty
        let final_count: usize = db.iter().count();
        assert_eq!(final_count, 0, "Database should remain empty");
    }

    #[tokio::test]
    async fn test_cleanup_malformed_timestamps() {
        // Arrange
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db = sled::open(temp_dir.path()).expect("Failed to create database");

        // Add entries with malformed timestamps
        let malformed_entries = vec![
            ("not-a-timestamp"),
            ("invalid-rfc3339"),
            (""),
            ("2024-13-45T99:99:99Z"), // Invalid date/time values
        ];

        for malformed_timestamp in malformed_entries {
            let nonce = Uuid::new_v4().to_string();
            db.insert(nonce.as_bytes(), malformed_timestamp.as_bytes())
                .expect("Should be able to insert malformed entry");
        }

        // Add one valid entry for comparison
        let now = Utc::now();
        let valid_nonce = Uuid::new_v4().to_string();
        let valid_expires = (now + Duration::minutes(10)).to_rfc3339();
        db.insert(valid_nonce.as_bytes(), valid_expires.as_bytes())
            .expect("Should be able to insert valid entry");

        let initial_count: usize = db.iter().count();
        assert_eq!(initial_count, 5, "Should have 5 total entries");

        let result = NonceCleanupActor::cleanup_expired_nonces(&db);

        assert!(
            result.is_ok(),
            "Cleanup should succeed despite malformed timestamps"
        );
        let removed_count = result.unwrap();
        assert_eq!(
            removed_count, 0,
            "Should remove 0 entries (none are expired with valid timestamps)"
        );

        // Verify all entries are still present (malformed ones are ignored, not removed)
        let final_count: usize = db.iter().count();
        assert_eq!(
            final_count, 5,
            "All entries should remain (malformed ones are ignored)"
        );
    }
}
