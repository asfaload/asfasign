# Client-Server Integration Tests

This crate contains integration tests for the client-cli and rest-api server.

## Purpose

These tests verify that client-cli commands work correctly with a live REST API server. They test the full workflow of:
- Client-side commands (list-pending, sign-pending)
- Server-side API endpoints (add-file, get-pending-signatures, submit-signature)
- Authentication and authorization
- Git repository integration

## Architecture

The test harness spawns the REST API server programmatically using `tokio::spawn(run_server())` on a dedicated thread with its own tokio runtime. Server and tests share the same temporary git repository, ensuring consistent state.

## Running Tests

```bash
cargo test --package client-server-integration-tests
```

Or via Makefile:

```bash
make client-server-tests
```

## Test Structure

### Test Harness (`src/test_harness.rs`)

The test harness provides:
- **Shared Server**: A single REST API server instance shared across all tests using `tokio::sync::OnceCell`
- **Test Keys**: Pre-generated key pairs for authentication
- **Helper Functions**: Common utilities for adding files and waiting for commits

### Test Files

- `tests/integration_tests.rs`: All integration tests (list-pending, add-file, sign-pending)

## Test Isolation

Tests are isolated using:
- **Shared Server**: One server instance for all tests (started once)
- **Shared Keys**: Same key pair used across all tests
- **Unique File Paths**: Each test uses unique file paths in the shared git repo via `unique_test_paths()`

## Dependencies

- `rest-api`: The server being tested
- `client-cli`: The client commands being tested
- `rest_api_test_helpers`: Test utilities for server setup
- `features_lib`: Cryptographic functions
- `signers_file` and `signers_file_types`: Signers file handling
- `common`: Shared utilities

## CI/CD

These tests run in GitHub Actions via `.github/workflows/client-server-integration.yml` on:
- Push to master branch
- Pull requests
