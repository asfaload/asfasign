# Phase3b Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address all code review comments on the phase3b branch.

**Architecture:** Seven independent fixes across rest-api, admin-lib, and client-cli. Tasks are ordered by dependency: generic signatures (B) changes the collector struct that other tasks reference; auth (G) touches the handler and route that C/D also modify. The simple removals (A, F) and helper extraction (E) are independent.

**Tech Stack:** Rust, axum, kameo actors

**Worktree:** `/home/dotdev/gits/asfaload/asfasign/.worktrees/phase3b-api-and-client-changes/`

---

### Task 1: Remove dead `_public_key` parsing (Review A)

**Files:**
- Modify: `rest-api/src/handlers.rs:91-93, 268-270`

- [ ] **Step 1: Remove `_public_key` from `register_repo_handler`**

In `rest-api/src/handlers.rs`, delete lines 91-93:

```rust
    // Parse public key (used for request authentication)
    let _public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;
```

- [ ] **Step 2: Remove `_public_key` from `update_signers_handler`**

In the same file, delete lines 268-270 (same pattern):

```rust
    // Parse public key (used for request authentication)
    let _public_key = features_lib::AsfaloadPublicKeys::from_base64(&request.public_key)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid public key format".to_string()))?;
```

- [ ] **Step 3: Run clippy to verify no new warnings**

Run: `cargo clippy --package rest-api 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add rest-api/src/handlers.rs
git commit -m "fix(rest-api): remove unused _public_key parsing in register/update handlers"
```

---

### Task 2: Make signature collection generic (Review B)

**Files:**
- Modify: `rest-api/src/file_auth/actors/signature_collector.rs:15-45, 180-190`
- Modify: `rest-api/src/handlers.rs:443-479`

- [ ] **Step 1: Change `CollectSignatureRequest` struct**

In `rest-api/src/file_auth/actors/signature_collector.rs`, replace the struct fields. Add `use std::collections::HashMap;` to imports and `use std::path::PathBuf;` (PathBuf is not yet imported).

Replace:

```rust
pub struct CollectSignatureRequest {
    /// Normalised path to the file being signed
    pub file_path: NormalisedPaths,
    /// Public key of the signer
    pub public_key: AsfaloadPublicKeys,
    /// Signature data
    pub signature: AsfaloadSignatures,
    /// Metadata signature (required for signers files)
    pub metadata_signature: Option<AsfaloadSignatures>,
    /// Request ID for tracing and logging
    pub request_id: String,
}
```

With:

```rust
pub struct CollectSignatureRequest {
    /// Normalised path to the primary file being signed
    pub file_path: NormalisedPaths,
    /// Public key of the signer
    pub public_key: AsfaloadPublicKeys,
    /// Map of relative file paths to their signatures.
    /// Must contain at least the primary file's signature.
    /// For signers files, also contains the metadata file signature.
    pub signatures: HashMap<PathBuf, AsfaloadSignatures>,
    /// Request ID for tracing and logging
    pub request_id: String,
}
```

- [ ] **Step 2: Update the collector actor's handle method**

In the same file, update the signers file branch (around line 180). Replace:

```rust
        let new_state = if is_signers_file {
            let metadata_sig = msg.metadata_signature.ok_or_else(|| {
                ApiError::InvalidRequestBody(
                    "Metadata signature required for signers files".to_string(),
                )
            })?;
            signers_file::sign_signers_and_metadata_file(
                msg.file_path.absolute_path(),
                &msg.signature,
                &msg.public_key,
                &metadata_sig,
            )
```

With:

```rust
        let new_state = if is_signers_file {
            let primary_path = msg.file_path.relative_path();
            let signature = msg.signatures.get(&primary_path).ok_or_else(|| {
                ApiError::InvalidRequestBody(format!(
                    "No signature provided for primary file: {}",
                    primary_path.display()
                ))
            })?;
            let metadata_rel_path =
                common::fs::names::metadata_path_for(&primary_path).map_err(|e| {
                    ApiError::InternalServerError(format!(
                        "Failed to compute metadata path: {}",
                        e
                    ))
                })?;
            let metadata_sig = msg.signatures.get(&metadata_rel_path).ok_or_else(|| {
                ApiError::InvalidRequestBody(
                    "Metadata signature required for signers files".to_string(),
                )
            })?;
            signers_file::sign_signers_and_metadata_file(
                msg.file_path.absolute_path(),
                signature,
                &msg.public_key,
                metadata_sig,
            )
```

- [ ] **Step 3: Update the non-signers file branch**

In the same handle method, the else branch (non-signers files) currently uses `msg.signature`. Replace:

```rust
            pending_agg
                .add_individual_signature(&msg.signature, &msg.public_key)
```

With:

```rust
            let primary_path = msg.file_path.relative_path();
            let signature = msg.signatures.get(&primary_path).ok_or_else(|| {
                ApiError::InvalidRequestBody(format!(
                    "No signature provided for file: {}",
                    primary_path.display()
                ))
            })?;
            pending_agg
                .add_individual_signature(signature, &msg.public_key)
```

- [ ] **Step 4: Update `submit_signature_handler` to build the generic map**

In `rest-api/src/handlers.rs`, replace the signature extraction block (lines 443-479):

```rust
    // Extract primary signature from the signatures map
    let signature_b64 = request.signatures.get(&request.file_path).ok_or_else(|| {
        ApiError::InvalidRequestBody(format!(
            "No signature provided for primary file: {}",
            request.file_path
        ))
    })?;
    let signature = features_lib::AsfaloadSignatures::from_base64(signature_b64)
        .map_err(|_| ApiError::InvalidRequestBody("Invalid signature format".to_string()))?;

    // Extract metadata signature if present
    let metadata_rel_path = common::fs::names::metadata_path_for(&request.file_path)
        .map(|p| p.to_string_lossy().to_string())
        .ok();
    let metadata_signature = if let Some(ref meta_path) = metadata_rel_path {
        request
            .signatures
            .get(meta_path)
            .map(|sig_b64| {
                features_lib::AsfaloadSignatures::from_base64(sig_b64).map_err(|_| {
                    ApiError::InvalidRequestBody("Invalid metadata signature format".to_string())
                })
            })
            .transpose()?
    } else {
        None
    };

    // Send signature collection request to the actor
    let collector_request =
        crate::file_auth::actors::signature_collector::CollectSignatureRequest {
            file_path: file_path.clone(),
            public_key,
            signature,
            metadata_signature,
            request_id: request_id.to_string(),
        };
```

With:

```rust
    // Parse all signatures from the request map
    let mut parsed_signatures = std::collections::HashMap::new();
    for (path_str, sig_b64) in &request.signatures {
        let sig = features_lib::AsfaloadSignatures::from_base64(sig_b64).map_err(|_| {
            ApiError::InvalidRequestBody(format!(
                "Invalid signature format for path: {}",
                path_str
            ))
        })?;
        parsed_signatures.insert(PathBuf::from(path_str), sig);
    }

    // Verify the primary file has a signature
    let primary_path = PathBuf::from(&request.file_path);
    if !parsed_signatures.contains_key(&primary_path) {
        return Err(ApiError::InvalidRequestBody(format!(
            "No signature provided for primary file: {}",
            request.file_path
        )));
    }

    // Send signature collection request to the actor
    let collector_request =
        crate::file_auth::actors::signature_collector::CollectSignatureRequest {
            file_path: file_path.clone(),
            public_key,
            signatures: parsed_signatures,
            request_id: request_id.to_string(),
        };
```

- [ ] **Step 5: Update test helpers in signature_collector.rs**

Search for any test code that constructs `CollectSignatureRequest` and update field names. The test helper `compute_metadata_signature` and test functions that build `CollectSignatureRequest` need to use the `signatures: HashMap` field instead of `signature` + `metadata_signature`.

For each test constructing `CollectSignatureRequest`, build a `HashMap<PathBuf, AsfaloadSignatures>` containing the primary signature (keyed by relative path) and optionally the metadata signature (keyed by metadata relative path), then pass it as the `signatures` field.

- [ ] **Step 6: Run tests**

Run: `cargo test --package rest-api 2>&1 | tail -20`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add rest-api/src/file_auth/actors/signature_collector.rs rest-api/src/handlers.rs
git commit -m "refactor(rest-api): make signature collection generic with path-to-signature map"
```

---

### Task 3: Use normalised path in files-to-sign response (Review C)

**Files:**
- Modify: `rest-api/src/handlers.rs:806-808`

- [ ] **Step 1: Replace raw `file_path` with normalised path**

In `rest-api/src/handlers.rs`, in `get_files_to_sign_handler`, replace:

```rust
    files.insert(
        file_path.clone(),
        base64::engine::general_purpose::STANDARD.encode(&content),
    );
```

With:

```rust
    let relative_path = normalised_paths.relative_path().to_string_lossy().to_string();
    files.insert(
        relative_path.clone(),
        base64::engine::general_purpose::STANDARD.encode(&content),
    );
```

Also update the metadata relative path computation below (line 823-829). Replace:

```rust
            let metadata_relative =
                common::fs::names::metadata_path_for(&file_path).map_err(|e| {
                    ApiError::InternalServerError(format!(
                        "Failed to compute metadata relative path: {}",
                        e
                    ))
                })?;
```

With:

```rust
            let metadata_relative =
                common::fs::names::metadata_path_for(&relative_path).map_err(|e| {
                    ApiError::InternalServerError(format!(
                        "Failed to compute metadata relative path: {}",
                        e
                    ))
                })?;
```

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --package rest-api 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add rest-api/src/handlers.rs
git commit -m "fix(rest-api): use normalised path instead of raw user input in files-to-sign response"
```

---

### Task 4: Error on missing metadata for signers files (Review D)

**Files:**
- Modify: `rest-api/src/handlers.rs:819-834`

- [ ] **Step 1: Add error branch for missing metadata**

In `get_files_to_sign_handler`, replace:

```rust
        if metadata_path.exists() {
            let metadata_content = tokio::fs::read(&metadata_path).await.map_err(|e| {
                ApiError::InternalServerError(format!("Failed to read metadata file: {}", e))
            })?;
            let metadata_relative =
                common::fs::names::metadata_path_for(&relative_path).map_err(|e| {
                    ApiError::InternalServerError(format!(
                        "Failed to compute metadata relative path: {}",
                        e
                    ))
                })?;
            files.insert(
                metadata_relative.to_string_lossy().to_string(),
                base64::engine::general_purpose::STANDARD.encode(&metadata_content),
            );
        }
```

With:

```rust
        if metadata_path.exists() {
            let metadata_content = tokio::fs::read(&metadata_path).await.map_err(|e| {
                ApiError::InternalServerError(format!("Failed to read metadata file: {}", e))
            })?;
            let metadata_relative =
                common::fs::names::metadata_path_for(&relative_path).map_err(|e| {
                    ApiError::InternalServerError(format!(
                        "Failed to compute metadata relative path: {}",
                        e
                    ))
                })?;
            files.insert(
                metadata_relative.to_string_lossy().to_string(),
                base64::engine::general_purpose::STANDARD.encode(&metadata_content),
            );
        } else {
            return Err(ApiError::InternalServerError(format!(
                "Metadata file not found for signers file: {}",
                metadata_path.display()
            )));
        }
```

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --package rest-api 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add rest-api/src/handlers.rs
git commit -m "fix(rest-api): return error when metadata file is missing for signers file"
```

---

### Task 5: Extract pending signatures helper (Review E)

**Files:**
- Modify: `rest-api/src/file_auth/actors/signers_initialiser.rs:151-168, 309-326`

- [ ] **Step 1: Add the helper function**

Add this function at module level in `rest-api/src/file_auth/actors/signers_initialiser.rs` (before the `impl Actor for SignersInitialiser` block):

```rust
/// Create empty pending signatures files for a signers file and its metadata file.
/// This makes them discoverable by `list-pending`.
async fn create_empty_pending_signatures(signers_abs_path: &std::path::Path) -> Result<(), ApiError> {
    let empty_sigs = signatures::signatures_file::SignaturesFile::new();
    let empty_sigs_json = serde_json::to_string_pretty(&empty_sigs).map_err(|e| {
        ApiError::FileWriteFailed(format!("Failed to serialize empty signatures: {}", e))
    })?;

    // Create pending signatures for the signers file
    let pending_sig_path = common::fs::names::pending_signatures_path_for(signers_abs_path)
        .map_err(|e| {
            ApiError::FileWriteFailed(format!(
                "Failed to compute pending signatures path: {}",
                e
            ))
        })?;
    tokio::fs::write(&pending_sig_path, &empty_sigs_json)
        .await
        .map_err(|e| {
            ApiError::FileWriteFailed(format!("Failed to write pending signatures file: {}", e))
        })?;

    // Create pending signatures for the metadata file
    let metadata_path = common::fs::names::metadata_path_for(signers_abs_path).map_err(|e| {
        ApiError::FileWriteFailed(format!("Failed to compute metadata path: {}", e))
    })?;
    let metadata_pending_sig_path =
        common::fs::names::pending_signatures_path_for(&metadata_path).map_err(|e| {
            ApiError::FileWriteFailed(format!(
                "Failed to compute metadata pending signatures path: {}",
                e
            ))
        })?;
    tokio::fs::write(&metadata_pending_sig_path, &empty_sigs_json)
        .await
        .map_err(|e| {
            ApiError::FileWriteFailed(format!(
                "Failed to write metadata pending signatures file: {}",
                e
            ))
        })?;

    Ok(())
}
```

- [ ] **Step 2: Replace the init path duplicate**

In the `handle` method for `InitialiseSignersRequest` (around line 151), replace:

```rust
        // Create empty pending signatures files so list-pending can discover them
        let signers_abs = signers_normalised_paths.absolute_path();
        let pending_sig_path = common::fs::names::pending_signatures_path_for(&signers_abs)
            .map_err(|e| {
                ApiError::FileWriteFailed(format!(
                    "Failed to compute pending signatures path: {}",
                    e
                ))
            })?;
        let empty_sigs = signatures::signatures_file::SignaturesFile::new();
        let empty_sigs_json = serde_json::to_string_pretty(&empty_sigs).map_err(|e| {
            ApiError::FileWriteFailed(format!("Failed to serialize empty signatures: {}", e))
        })?;
        tokio::fs::write(&pending_sig_path, &empty_sigs_json)
            .await
            .map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to write pending signatures file: {}", e))
            })?;
```

With:

```rust
        let signers_abs = signers_normalised_paths.absolute_path();
        create_empty_pending_signatures(&signers_abs).await?;
```

- [ ] **Step 3: Replace the propose path duplicate**

In the `handle` method for `ProposeSignersRequest` (around line 309), replace:

```rust
        // Create empty pending signatures file so list-pending can discover it
        let signers_abs = signers_normalised_paths.absolute_path();
        let pending_sig_path = common::fs::names::pending_signatures_path_for(&signers_abs)
            .map_err(|e| {
                ApiError::FileWriteFailed(format!(
                    "Failed to compute pending signatures path: {}",
                    e
                ))
            })?;
        let empty_sigs = signatures::signatures_file::SignaturesFile::new();
        let empty_sigs_json = serde_json::to_string_pretty(&empty_sigs).map_err(|e| {
            ApiError::FileWriteFailed(format!("Failed to serialize empty signatures: {}", e))
        })?;
        tokio::fs::write(&pending_sig_path, &empty_sigs_json)
            .await
            .map_err(|e| {
                ApiError::FileWriteFailed(format!("Failed to write pending signatures file: {}", e))
            })?;
```

With:

```rust
        let signers_abs = signers_normalised_paths.absolute_path();
        create_empty_pending_signatures(&signers_abs).await?;
```

- [ ] **Step 4: Run tests**

Run: `cargo test --package rest-api 2>&1 | tail -20`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add rest-api/src/file_auth/actors/signers_initialiser.rs
git commit -m "refactor(rest-api): extract create_empty_pending_signatures helper

Also creates pending signatures for the metadata file, which was
previously missing and prevented list-pending from discovering it."
```

---

### Task 6: Remove change-referencing comment (Review F)

**Files:**
- Modify: `rest-api/src/file_auth/actors/signers_initialiser.rs:648`

- [ ] **Step 1: Delete the comment**

In `rest-api/src/file_auth/actors/signers_initialiser.rs`, delete line 648:

```rust
        // Init no longer auto-signs, so we need to explicitly sign afterward.
```

Note: line number may have shifted after Task 5. Search for the exact string.

- [ ] **Step 2: Commit**

```bash
git add rest-api/src/file_auth/actors/signers_initialiser.rs
git commit -m "fix(rest-api): remove change-referencing comment in test"
```

---

### Task 7: Authenticate fetch_files_to_sign (Review G)

**Files:**
- Modify: `admin-lib/src/client/v1.rs:113-139`
- Modify: `rest-api/src/handlers.rs:780-837`
- Modify: `rest-api/src/v1/routes.rs:44-47`
- Modify: `client-cli/src/commands/sign_pending.rs:45`

- [ ] **Step 1: Add auth to admin-lib `fetch_files_to_sign`**

In `admin-lib/src/client/v1.rs`, change the method signature and add auth headers. Replace:

```rust
    /// Fetch all files that need signing for a given file path.
    ///
    /// Makes an unauthenticated GET request to `/v1/files-to-sign/{file_path}`.
    /// Returns a map of file paths to their raw content bytes.
    pub async fn fetch_files_to_sign(
        &self,
        file_path: &str,
    ) -> AdminLibResult<HashMap<String, Vec<u8>>> {
        use base64::Engine;

        let url = format!("{}/v1/files-to-sign/{}", self.base_url, file_path);
        let response = self.client.get(&url).send().await?;
```

With:

```rust
    /// Fetch all files that need signing for a given file path.
    ///
    /// Makes an authenticated GET request to `/v1/files-to-sign/{file_path}`.
    /// Returns a map of file paths to their raw content bytes.
    pub async fn fetch_files_to_sign(
        &self,
        file_path: &str,
        secret_key: &AsfaloadSecretKeys,
    ) -> AdminLibResult<HashMap<String, Vec<u8>>> {
        use base64::Engine;

        let url = format!("{}/v1/files-to-sign/{}", self.base_url, file_path);
        let headers = create_auth_headers("", secret_key)?;
        let response = self.client.get(&url).headers(headers).send().await?;
```

- [ ] **Step 2: Update the client-cli caller**

In `client-cli/src/commands/sign_pending.rs`, line 45, replace:

```rust
    let files_to_sign = client.fetch_files_to_sign(file_path).await?;
```

With:

```rust
    let files_to_sign = client.fetch_files_to_sign(file_path, &secret_key).await?;
```

- [ ] **Step 3: Add auth middleware to the route**

In `rest-api/src/v1/routes.rs`, replace:

```rust
    let files_to_sign_router = Router::new().route(
        "/files-to-sign/{*file_path}",
        get(get_files_to_sign_handler),
    );
```

With:

```rust
    let files_to_sign_router = Router::new()
        .route(
            "/files-to-sign/{*file_path}",
            get(get_files_to_sign_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
```

- [ ] **Step 4: Add auth header extraction to the handler**

In `rest-api/src/handlers.rs`, update `get_files_to_sign_handler` to accept headers and extract the public key. Replace the function signature:

```rust
pub async fn get_files_to_sign_handler(
    State(state): State<AppState>,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<Json<FilesToSignResponse>, ApiError> {
```

With:

```rust
pub async fn get_files_to_sign_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(file_path): axum::extract::Path<String>,
) -> Result<Json<FilesToSignResponse>, ApiError> {
```

Then after the `normalised_paths` creation and file existence check, add public key extraction:

```rust
    // Extract and validate the signer's public key from auth headers
    let _public_key = extract_public_key_from_headers(&headers)?;
```

Note: For now we extract and validate the key (ensuring the request is authenticated) but don't filter files by signer — the endpoint returns all files that need signing for the given path. Signer-specific filtering can be added later if needed.

- [ ] **Step 5: Update any integration tests that call fetch_files_to_sign**

Search for `fetch_files_to_sign` in test files and add the `secret_key` parameter. If the client-server integration tests call this endpoint, they need to pass a secret key and include auth headers.

- [ ] **Step 6: Run full test suite**

Run: `cargo test 2>&1 | tail -20`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add admin-lib/src/client/v1.rs client-cli/src/commands/sign_pending.rs rest-api/src/handlers.rs rest-api/src/v1/routes.rs
git commit -m "feat(rest-api): authenticate files-to-sign endpoint"
```
