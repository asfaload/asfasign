# Phase3b Review Fixes

Addresses code review comments on the `phase3b-api-and-client-changes` branch.

## A. Remove dead `_public_key` parsing

**Files:** `rest-api/src/handlers.rs` (lines 91-93, 268-270)

In `register_repo_handler` and `update_signers_handler`, the public key is parsed from the request body into `_public_key` but never used. Authentication happens via the forge validator, not via this key. Delete the parse + comment in both handlers.

## B. Make signature collection generic in rest-api layer

**Files:** `rest-api/src/handlers.rs`, `rest-api/src/file_auth/actors/signature_collector.rs`

**Problem:** The handler manually extracts the primary signature and metadata signature from `request.signatures` (a `HashMap<String, String>`), then passes them as separate fields to the collector actor. This makes the handler aware of metadata file types.

**Solution:**

1. Change `CollectSignatureRequest` to replace `signature` + `metadata_signature: Option<...>` with `signatures: HashMap<PathBuf, AsfaloadSignatures>` — a map of relative paths to parsed signatures.

2. In `submit_signature_handler`, iterate over all entries in `request.signatures`, resolve each key to a `PathBuf`, parse each value as `AsfaloadSignatures`, and pass the whole map to the collector.

3. In the collector actor, extract the primary signature (matching `msg.file_path`) and any additional signatures (e.g. metadata) from the map. The actor already knows the file type and can call `sign_signers_and_metadata_file` with the right arguments.

**Scope boundary:** The `signers_file` crate's `sign_signers_and_metadata_file` function is NOT changed. The collector extracts what it needs from the map before calling it.

## C. Use normalised path in files-to-sign response

**File:** `rest-api/src/handlers.rs` (line 807)

Replace `file_path.clone()` (raw user-provided string) with a value derived from `normalised_paths` as the HashMap key in the response. This avoids using untrusted input in the response.

## D. Error on missing metadata for signers files

**File:** `rest-api/src/handlers.rs` (line 819)

The `get_files_to_sign_handler` silently skips metadata when `metadata_path.exists()` is false. For signers files, metadata is mandatory. Add an `else` branch returning an error.

## E. Extract pending signatures helper

**File:** `rest-api/src/file_auth/actors/signers_initialiser.rs` (lines ~151-180, ~310-340)

Both `handle_init` and `handle_propose` duplicate the pattern:
- Compute pending signatures path for the signers file
- Create empty `SignaturesFile`, serialize, write to disk
- Do the same for the metadata file

Extract an async helper:
```rust
async fn create_empty_pending_signatures(signers_abs_path: &Path) -> Result<(), ApiError>
```

This helper creates empty pending signature files for both the signers file and its metadata file.

## F. Remove change-referencing comment

**File:** `rest-api/src/file_auth/actors/signers_initialiser.rs` (line 648)

Delete `// Init no longer auto-signs, so we need to explicitly sign afterward.` — it references how things used to work, violating the "comments describe current state" rule.

## G. Authenticate fetch_files_to_sign

**Files:** `admin-lib/src/client/v1.rs`, `rest-api/src/handlers.rs`

`fetch_files_to_sign` in admin-lib makes an unauthenticated GET request. The backend should know which signer is requesting so it can validate authorization.

1. In `admin-lib/src/client/v1.rs`: add `secret_key: &AsfaloadSecretKeys` parameter to `fetch_files_to_sign`, generate auth headers, include them in the request.
2. In `rest-api/src/handlers.rs` (`get_files_to_sign_handler`): extract the public key from auth headers and validate the signer is authorized for the requested file.
