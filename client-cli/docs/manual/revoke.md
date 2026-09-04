# `asfaload-cli revoke`

- **Usage**: `asfaload-cli revoke [OPTIONS] -K <SECRET_KEY> <FILE_PATH>`
- **Source**: [`src/commands/revoke.rs`](../../src/commands/revoke.rs)

Revoke a previously signed file on the mirror. The command fetches the file from the backend, builds a revocation document (timestamped, with the initiator's public key and the file's SHA-512 digest), signs it, and submits it.

Once revoked, clients that [`download`](download.md) the file will see a revocation warning.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the signed file, for example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`.

## Options

### `-K --secret-key <PATH>`

Path to your secret key file. Required.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-c --password-command <COMMAND>`

Shell command to run; its standard output is read as the password. Useful for password managers (`pass`, `op`, `bw`, etc.). Conflicts with `--password` and `--password-file`. The command string is parsed with shell-style quoting (no shell is spawned, so pipes and redirections don't apply); trailing newlines are stripped from the output.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `https://backend.asfaload.com`.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

These variables provide fallbacks for the matching options. Password sources are tried in the order described in the [manual index](index.md#passwords): flags first (in the order `--password`, `--password-command`, `--password-file`), then environment variables, then an interactive prompt.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_REVOKE_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_REVOKE_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default):

    Success! File revoked: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

JSON (with `--json`):

    {"success":true,"message":""}

## Examples

    # revoke a release index
    asfaload-cli revoke -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — file revoked.
- non-zero — error (authentication failure, file not found, not authorized, network error).
