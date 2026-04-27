# `client signature-status`

- **Usage**: `client signature-status [OPTIONS] <FILE_PATH>`
- **Source**: [`src/commands/signature_status.rs`](../../src/commands/signature_status.rs)
- **Related endpoint**: [`GET /v1/signatures/{file_path}`](../../../rest-api/docs/manual/signature-status.md)

Query the backend for the signature collection status of a file. The caller must be an authorized signer in the file's current signers file; see the linked endpoint for the exact authorization rule.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the file to query, for example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`.

## Options

### `-K --secret-key <PATH>`

Path to the caller's secret key file. Required.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file`. Prompted interactively if neither is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password`.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `http://127.0.0.1:3000`.

### `--json`

Emit the backend response as JSON instead of human-readable text.

## Environment

- `ASFALOAD_SIGNATURE_STATUS_PASSWORD` — alternative to `--password`.
- `ASFALOAD_SIGNATURE_STATUS_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default):

    <file_path>: pending

or

    <file_path>: complete

JSON (with `--json`):

    {"file_path":"<file_path>","is_complete":false}

## Examples

    # check a pending release index
    client signature-status -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # use a non-default backend
    client signature-status -K ~/.asfaload/key -u https://asfaload.example.com \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # machine-readable output
    client signature-status --json -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — query succeeded.
- non-zero — error (authentication failure, not authorized, file not found, network error).
