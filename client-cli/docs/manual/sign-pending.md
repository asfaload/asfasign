# `asfaload-cli sign-pending`

- **Usage**: `asfaload-cli sign-pending [OPTIONS] -K <SECRET_KEY> <FILE_PATH>`
- **Source**: [`src/commands/sign_pending.rs`](../../src/commands/sign_pending.rs)

Sign a pending file. The command fetches all files associated with the given path from the backend, computes a SHA-512 hash of each, signs them with your secret key, and submits the signatures in a single request.

Use [`list-pending`](list-pending.md) to discover which files need signing.

## Arguments

### `<FILE_PATH>`

Mirror-relative path to the file to sign, as returned by `list-pending`. For example `https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json`.

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

These variables provide fallbacks for the matching options; an explicit flag always wins.

- `ASFALOAD_SECRET_KEY` — alternative to `--secret-key`.
- `ASFALOAD_BACKEND_URL` — alternative to `--backend-url`.
- `ASFALOAD_PASSWORD_FILE` — alternative to `--password-file`.
- `ASFALOAD_PASSWORD_COMMAND` — alternative to `--password-command`.
- `ASFALOAD_SIGN_PENDING_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_SIGN_PENDING_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default):

    Success! Signature submitted

When the submission completes the required threshold:

    Success! Signature submitted (complete)

JSON (with `--json`):

    {"is_complete":true}

## Examples

    # sign a pending release index
    asfaload-cli sign-pending -K ~/.asfaload/key \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

    # sign with explicit password (CI usage)
    asfaload-cli sign-pending -K ~/.asfaload/key -p "$PASSWORD" \
        https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json

## Exit codes

- `0` — signature submitted successfully.
- non-zero — error (authentication failure, file not found, network error).
