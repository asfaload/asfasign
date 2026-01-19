# Producing Better Code

## Critical Rules (Non-Negotiable)

- **Never hardcode file/dir names** → Use `common::fs::names` constants. THIS IS VERY IMPORTANT
- **Never pass raw PathBuf for security-sensitive paths** → Use typed wrappers like `NormalisedPaths`
- **Always verify protocol specifications** → Never guess (e.g., HTTP Retry-After is seconds, not ms)
- **Zero compiler warnings** → Fix all warnings before committing
- **Never leave code commented out** → Delete or uncomment

## Code Quality Standards

### Naming
- Names must accurately reflect actual behavior (not "Authenticator" if only validates)
- Follow project naming conventions exactly
- Use existing constants, don't create duplicates

### Type Safety
- Use typed wrappers for security-critical concepts (file paths, authentication tokens)
- Implement trait implementations (`Display`, `AsRef<Path>`) for ergonomics when frequently used

### Error Handling
- Consistent error types across codebase
- Never swallow errors in cleanup functions - propagate failures
- Proactive error checks (check existence before operation) preferred over reactive error handling
- Dynamic error messages that match actual behavior

### Code Organization
- Remove unused code immediately (imports, functions, fields, types)
- Follow Rust conventions (prefer directory names over `mod.rs`)
- Avoid unnecessary abstraction layers (remove forwarders, unused actors)
- Add helper methods for common operations (e.g., `NormalisedPaths::join`)

## Specific Patterns

### File Path Handling
```rust
// BAD
let path = base.join("asfaload.signers.pending").join("index.json");
tokio::fs::write(&path, content).await;

// GOOD
use common::fs::names::{PENDING_SIGNERS_DIR, SIGNERS_FILE};
let path = base.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
// Or use NormalisedPaths::join() for security
```

### Type Wrappers
```rust
// BAD
fn process(path: PathBuf) { /* ... */ }

// GOOD for security-sensitive paths
fn process(path: NormalisedPaths) { /* ... */ }
impl AsRef<Path> for NormalisedPaths { /* ... */ }
```


## Testing Requirements

### Coverage
- Unit tests for all public functions
- Integration tests for API endpoints
- Error path tests for all failure modes
- Edge cases: empty inputs, maximum values, special characters

### Test Patterns
- Tests must match actual code behavior (expect correct error types)
- Verify timing/sleep behavior for retry logic
- Test network errors, timeouts, partial failures
- Use helper functions for common test setup

### Test Contexts
- Understand difference between `#[cfg(test)]` and integration test contexts
- Annotations that work in unit tests may break integration tests

## Common Mistakes to Avoid

| Mistake | Fix |
|---------|-----|
| Hardcoded strings → Use project constants |
| Duplicated validation → Trust existing validation layer |
| Creating RepoHandler to forward to GitActor → Call GitActor directly |
| Commented out "temporarily" disabled code → Delete or re-enable |
| `Result<(), String>` for actor errors → Use `Result<(), ApiError>` |
| Swallowing cleanup errors → Track and return error if any failed |
| Checking `AlreadyExists` error → Check existence proactively |
| Guessing protocol behavior → Read specs |

## Before Submitting Code

### Verification Checklist

- [ ] No compiler warnings (`cargo clippy` passes)
- [ ] All tests pass (`cargo test` passes)
- [ ] Code is formatted (`cargo fmt`)
- [ ] No commented-out code
- [ ] No unused imports, functions, fields, types
- [ ] File/dir names use `common::fs::names` constants
- [ ] Security-sensitive paths use typed wrappers
- [ ] Error messages are dynamic and accurate
- [ ] Names accurately reflect behavior
- [ ] No unnecessary abstraction layers
- [ ] Test coverage for all code paths
- [ ] Tests expect correct error types

### Protocol Compliance
- [ ] HTTP headers verified against MDN specs
- [ ] Retry logic uses correct time units
- [ ] API contract compliance verified
- [ ] No assumptions about external behavior

### Code Review Preparation
- [ ] Each commit has clear, focused purpose
- [ ] Commits build incrementally
- [ ] No "fix in follow-up" comments
- [ ] Cleanup functions properly propagate errors
