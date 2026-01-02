# Crux Pattern Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Apply Crux's "separate intent from execution" pattern to Kameo actors for faster, simpler testing

**Architecture:** Refactor actors to separate pure business logic (intent) from side effects (execution) while keeping both in the same actor

**Tech Stack:** Rust, Kameo actors, existing git2/sled dependencies, new pure function patterns

## Overview

This plan refactors three actors incrementally:
1. **GitActor** - Separate commit planning from git operations
2. **NonceCacheActor** - Separate nonce validation from database operations  
3. **NonceCleanupActor** - Separate cleanup planning from database operations

Each actor will have:
- **Pure logic functions** - No side effects, fast to test
- **Effect handlers** - All side effects isolated here
- **Message handlers** - Orchestrate logic + effects

New testing structure:
- **`tests/unit/`** - Fast pure function tests (new)
- **`tests/effects/`** - Effect handler tests (new)
- **`tests/integration/`** - Existing tests (unchanged)

---

### Task 1: GitActor Refactoring

**Files:**
- Modify: `rest-api/src/actors/git_actor.rs`
- Create: `rest-api/tests/unit/git_actor_tests.rs`
- Create: `rest-api/tests/effects/git_actor_effects_tests.rs`

**Step 1: Add pure logic module to GitActor**

```rust
// Add to rest-api/src/actors/git_actor.rs
mod logic {
    use super::*;
    
    #[derive(Debug, Clone)]
    pub struct CommitPlan {
        pub repo_path: PathBuf,
        pub relative_path: PathBuf,
        pub commit_message: String,
    }
    
    pub fn plan_commit(msg: CommitFile) -> Result<CommitPlan, ApiError> {
        // Pure validation logic - no I/O
        if msg.commit_message.trim().is_empty() {
            return Err(ApiError::InvalidCommitMessage("Commit message cannot be empty".to_string()));
        }
        
        // Validate file paths
        if msg.file_paths.relative_path().as_os_str().is_empty() {
            return Err(ApiError::InvalidFilePath("File path cannot be empty".to_string()));
        }
        
        Ok(CommitPlan {
            repo_path: msg.file_paths.base_dir().clone(),
            relative_path: msg.file_paths.relative_path().clone(),
            commit_message: msg.commit_message,
        })
    }
}
```

**Step 2: Add effect handler module to GitActor**

```rust
// Add to rest-api/src/actors/git_actor.rs
mod effects {
    use super::*;
    use super::logic::CommitPlan;
    
    pub async fn execute_commit(plan: CommitPlan) -> Result<(), ApiError> {
        // All git operations here - no business logic
        let repo_path = plan.repo_path;
        let relative_path = plan.relative_path;
        let commit_message = plan.commit_message;
        
        tokio::task::spawn_blocking(move || {
            // Move existing git code here
            let repo = Repository::open(&repo_path)?;
            let signature = Signature::now(ACTOR_NAME, GIT_USER_EMAIL)?;
            let mut index = repo.index()?;
            index.add_path(&relative_path)?;
            let tree_oid = index.write_tree()?;
            let tree = repo.find_tree(tree_oid)?;
            let parent_commit = repo.head().and_then(|head| head.peel_to_commit()).ok();
            let parents: Vec<&git2::Commit> = parent_commit.as_ref().into_iter().collect();
            repo.commit(Some("HEAD"), &signature, &signature, &commit_message, &tree, &parents)?;
            Ok(())
        }).await?
    }
}
```

**Step 3: Update GitActor message handler**

```rust
// Replace existing handle implementation
impl Message<CommitFile> for GitActor {
    type Reply = Result<(), ApiError>;

    async fn handle(
        &mut self,
        msg: CommitFile,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // 1. Plan the operation (pure logic)
        let plan = logic::plan_commit(msg)?;
        
        // 2. Execute the plan (side effects)
        effects::execute_commit(plan).await
    }
}
```

**Step 4: Create unit test file**

```rust
// Create rest-api/tests/unit/git_actor_tests.rs
use rest_api::actors::git_actor::*;
use rest_api_types::errors::ApiError;
use tempfile::TempDir;

#[test]
fn test_plan_commit_success() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path();
    let file_path = PathBuf::from("test.txt");
    let normalised_paths = NormalisedPaths::new(repo_path.to_path_buf(), file_path.clone()).unwrap();
    
    let msg = CommitFile {
        file_paths: normalised_paths,
        commit_message: "Add test file".to_string(),
    };
    
    let result = git_actor::logic::plan_commit(msg);
    assert!(result.is_ok());
    
    let plan = result.unwrap();
    assert_eq!(plan.relative_path, file_path);
    assert_eq!(plan.commit_message, "Add test file");
}

#[test]
fn test_plan_commit_empty_message() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = PathBuf::from("test.txt");
    let normalised_paths = NormalisedPaths::new(temp_dir.path().to_path_buf(), file_path).unwrap();
    
    let msg = CommitFile {
        file_paths: normalised_paths,
        commit_message: "   ".to_string(), // Whitespace only
    };
    
    let result = git_actor::logic::plan_commit(msg);
    assert!(result.is_err());
    assert!(matches!(result, Err(ApiError::InvalidCommitMessage(_))));
}
```

**Step 5: Run unit tests**

Run: `cargo test --package rest-api test_plan_commit`
Expected: PASS (fast tests, no git operations)

**Step 6: Create effects test file**

```rust
// Create rest-api/tests/effects/git_actor_effects_tests.rs
use rest_api::actors::git_actor::*;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_execute_commit_success() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path();
    
    // Initialize git repo
    git2::Repository::init(repo_path).unwrap();
    
    // Create a test file
    let test_file = repo_path.join("test.txt");
    let mut file = File::create(&test_file).await.unwrap();
    file.write_all(b"test content").await.unwrap();
    file.flush().await.unwrap();
    
    let plan = git_actor::logic::CommitPlan {
        repo_path: repo_path.to_path_buf(),
        relative_path: PathBuf::from("test.txt"),
        commit_message: "Test commit".to_string(),
    };
    
    let result = git_actor::effects::execute_commit(plan).await;
    assert!(result.is_ok());
}
```

**Step 7: Run effects tests**

Run: `cargo test --package rest-api test_execute_commit`
Expected: PASS (slower tests, actual git operations)

**Step 8: Commit**

```bash
git add rest-api/src/actors/git_actor.rs rest-api/tests/unit/git_actor_tests.rs rest-api/tests/effects/git_actor_effects_tests.rs
git commit -m "refactor: apply Crux pattern to GitActor for better testability"
```

---

### Task 2: NonceCacheActor Refactoring

**Files:**
- Modify: `rest-api/src/actors/nonce_cache_actor.rs`
- Create: `rest-api/tests/unit/nonce_cache_actor_tests.rs`
- Create: `rest-api/tests/effects/nonce_cache_actor_effects_tests.rs`

**Step 1: Add pure logic module**

```rust
// Add to rest-api/src/actors/nonce_cache_actor.rs
mod logic {
    use super::*;
    use chrono::{DateTime, Utc};
    
    #[derive(Debug)]
    pub struct NonceValidationPlan {
        pub nonce: String,
        pub timestamp: DateTime<Utc>,
        pub should_store: bool,
    }
    
    pub fn plan_nonce_check(nonce: String, max_age_seconds: i64) -> Result<NonceValidationPlan, ApiError> {
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
            should_store: true,
        })
    }
}
```

**Step 2: Add effect handler module**

```rust
// Add to rest-api/src/actors/nonce_cache_actor.rs
mod effects {
    use super::*;
    use super::logic::NonceValidationPlan;
    
    pub async fn execute_nonce_check(
        plan: NonceValidationPlan,
        db: &sled::Db,
    ) -> Result<bool, ApiError> {
        // Check if nonce exists
        if let Some(_) = db.get(&plan.nonce)? {
            return Ok(false); // Already exists
        }
        
        // Store nonce with expiration
        let expiration = plan.timestamp.timestamp() + 3600; // 1 hour
        let value = format!("{}:{}", plan.timestamp.timestamp(), expiration);
        db.insert(&plan.nonce, value.as_bytes())?;
        Ok(true)
    }
}
```

**Step 3: Update message handler**

```rust
// Update existing handle implementation
impl Message<NonceCacheMessage> for NonceCacheActor {
    type Reply = NonceCacheResponse;

    async fn handle(
        &mut self,
        msg: NonceCacheMessage,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            NonceCacheMessage::CheckAndStoreNonce { nonce } => {
                match logic::plan_nonce_check(nonce.clone(), 3600) {
                    Ok(plan) => {
                        match effects::execute_nonce_check(plan, &self.db).await {
                            Ok(is_new) => NonceCacheResponse::Success(is_new),
                            Err(e) => NonceCacheResponse::Error(e.to_string()),
                        }
                    }
                    Err(e) => NonceCacheResponse::Error(e.to_string()),
                }
            }
        }
    }
}
```

**Step 4: Create unit tests**

```rust
// Create rest-api/tests/unit/nonce_cache_actor_tests.rs
use rest_api::actors::nonce_cache_actor::*;
use rest_api_types::errors::ApiError;

#[test]
fn test_plan_nonce_check_success() {
    let nonce = "valid_nonce_123".to_string();
    let result = nonce_cache_actor::logic::plan_nonce_check(nonce, 3600);
    
    assert!(result.is_ok());
    let plan = result.unwrap();
    assert_eq!(plan.nonce, "valid_nonce_123");
    assert!(plan.should_store);
}

#[test]
fn test_plan_nonce_check_empty() {
    let nonce = "".to_string();
    let result = nonce_cache_actor::logic::plan_nonce_check(nonce, 3600);
    
    assert!(result.is_err());
    assert!(matches!(result, Err(ApiError::InvalidNonce(_))));
}
```

**Step 5: Run unit tests**

Run: `cargo test --package rest-api test_plan_nonce_check`
Expected: PASS

**Step 6: Commit**

```bash
git add rest-api/src/actors/nonce_cache_actor.rs rest-api/tests/unit/nonce_cache_actor_tests.rs
git commit -m "refactor: apply Crux pattern to NonceCacheActor"
```

---

### Task 3: NonceCleanupActor Refactoring

**Files:**
- Modify: `rest-api/src/actors/nonce_cleanup_actor.rs`
- Create: `rest-api/tests/unit/nonce_cleanup_actor_tests.rs`
- Create: `rest-api/tests/effects/nonce_cleanup_actor_effects_tests.rs`

**Step 1: Add pure logic module**

```rust
// Add to rest-api/src/actors/nonce_cleanup_actor.rs
mod logic {
    use super::*;
    use chrono::{DateTime, Utc};
    
    #[derive(Debug)]
    pub struct CleanupPlan {
        pub expired_keys: Vec<String>,
        pub current_time: DateTime<Utc>,
    }
    
    pub fn plan_cleanup(current_time: DateTime<Utc>) -> CleanupPlan {
        // Pure logic - just returns current time
        // Real filtering will happen in effects where we can access the DB
        CleanupPlan {
            expired_keys: Vec::new(), // Will be populated in effects
            current_time,
        }
    }
}
```

**Step 2: Add effect handler module**

```rust
// Add to rest-api/src/actors/nonce_cleanup_actor.rs
mod effects {
    use super::*;
    use super::logic::CleanupPlan;
    
    pub async fn execute_cleanup(plan: CleanupPlan, db: &sled::Db) -> Result<usize, ApiError> {
        let mut removed_count = 0;
        let current_timestamp = plan.current_time.timestamp();
        
        // Iterate over all keys in database
        for item in db.iter() {
            let (key, value) = item?;
            let value_str = String::from_utf8_lossy(&value);
            
            if let Some((_, expiration)) = value_str.split_once(':') {
                if let Ok(exp_time) = expiration.parse::<i64>() {
                    if current_timestamp > exp_time {
                        db.remove(&key)?;
                        removed_count += 1;
                    }
                }
            }
        }
        
        Ok(removed_count)
    }
}
```

**Step 3: Update message handler**

```rust
// Update existing handle implementation
impl Message<NonceCleanupMessage> for NonceCleanupActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: NonceCleanupMessage,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            NonceCleanupMessage::PerformCleanup => {
                let plan = logic::plan_cleanup(Utc::now());
                if let Err(e) = effects::execute_cleanup(plan, &self.db).await {
                    eprintln!("Cleanup failed: {}", e);
                }
            }
        }
    }
}
```

**Step 4: Create unit tests**

```rust
// Create rest-api/tests/unit/nonce_cleanup_actor_tests.rs
use rest_api::actors::nonce_cleanup_actor::*;
use chrono::Utc;

#[test]
fn test_plan_cleanup() {
    let plan = nonce_cleanup_actor::logic::plan_cleanup(Utc::now());
    
    assert!(plan.expired_keys.is_empty()); // Always empty in pure logic
    assert!(plan.current_time <= Utc::now());
}
```

**Step 5: Run unit tests**

Run: `cargo test --package rest-api test_plan_cleanup`
Expected: PASS

**Step 6: Commit**

```bash
git add rest-api/src/actors/nonce_cleanup_actor.rs rest-api/tests/unit/nonce_cleanup_actor_tests.rs
git commit -m "refactor: apply Crux pattern to NonceCleanupActor"
```

---

### Task 4: Documentation and Final Verification

**Files:**
- Create: `docs/crux-pattern.md`
- Modify: `AGENTS.md`

**Step 1: Create Crux pattern documentation**

```rust
// Create docs/crux-pattern.md
# Crux Pattern in Kameo Actors

This document describes how we applied the Crux pattern's "separate intent from execution" to our Kameo actors for better testability.

## Architecture

Each actor now has three distinct parts:

### 1. Logic Module (Pure Functions)
- **Location**: `actors/xxx_actor.rs::logic`
- **Purpose**: Business logic, validation, planning
- **Characteristics**: No side effects, deterministic, fast to test
- **Tests**: `tests/unit/xxx_actor_tests.rs`

### 2. Effects Module (Side Effects)
- **Location**: `actors/xxx_actor.rs::effects`
- **Purpose**: All I/O operations (git, database, network)
- **Characteristics**: Only side effects, no business logic
- **Tests**: `tests/effects/xxx_actor_effects_tests.rs`

### 3. Message Handler (Orchestration)
- **Location**: `impl Message<...> for XxxActor`
- **Purpose**: Coordinate logic planning + effect execution
- **Characteristics**: Minimal, just glue code

## Testing Strategy

- **Unit Tests**: Test pure logic functions (microseconds)
- **Effect Tests**: Test side effects in isolation (milliseconds)
- **Integration Tests**: Test end-to-end behavior (seconds)

## Performance Improvements

- **Unit tests**: 10-100x faster than integration tests
- **Development cycle**: Faster feedback
- **CI/CD**: Quicker test runs
```

**Step 2: Update AGENTS.md**

```markdown
# Add to AGENTS.md under Testing section:

## Crux Pattern Testing

When adding new actors or modifying existing ones, follow the Crux pattern:

1. **Separate logic from effects** in each actor
2. **Unit tests** in `tests/unit/` for pure logic functions
3. **Effect tests** in `tests/effects/` for side effects
4. **Integration tests** in `tests/integration/` for end-to-end behavior

Example structure:
```rust
mod logic {
    // Pure functions - no side effects
}

mod effects {
    // All side effects - no business logic
}

impl Message<XxxMessage> for XxxActor {
    async fn handle(&mut self, msg: XxxMessage, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let plan = logic::plan_xxx(msg)?;
        effects::execute_xxx(plan).await
    }
}
```
```

**Step 3: Run all new tests**

Run: `cargo test --package rest-api --test unit --test effects`
Expected: All new tests pass

**Step 4: Run existing integration tests to ensure no regression**

Run: `cargo test --package rest-api --test integration_tests`
Expected: All existing tests still pass

**Step 5: Final commit**

```bash
git add docs/crux-pattern.md AGENTS.md
git commit -m "docs: document Crux pattern implementation"
```

## Expected Outcomes

After implementation:
- **Unit tests**: Run in microseconds, no external dependencies
- **Effect tests**: Run in milliseconds, isolated side effects
- **Integration tests**: Still exist but fewer, focused on orchestration
- **Development**: Faster iteration with instant unit test feedback
- **CI/CD**: Quicker test pipelines

The pattern is now established and can be applied to any future actors following the same structure.