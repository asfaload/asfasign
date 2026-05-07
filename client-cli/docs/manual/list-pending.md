# `asfaload-cli list-pending`

- **Usage**: `asfaload-cli list-pending [OPTIONS] -K <SECRET_KEY>`
- **Source**: [`src/commands/list_pending.rs`](../../src/commands/list_pending.rs)

List all files on the backend that still need your signature. The command authenticates with your secret key and returns only the files where your public key is among the expected signers.

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

Backend API URL. Defaults to `http://127.0.0.1:3000`.

### `--json`

Emit the backend response as JSON instead of human-readable text.

## Environment

- `ASFALOAD_LIST_PENDING_PASSWORD` — alternative to `--password`.
- `ASFALOAD_LIST_PENDING_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default), when files are pending:

    Files requiring your signature:
      - https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json
      - https/github.com/443/acme/repo/releases/tag/v2.0/asfaload.index.json

When nothing is pending:

    No pending signatures found.

JSON (with `--json`):

    {"file_paths":["https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"]}

## Examples

    # list pending files
    asfaload-cli list-pending -K ~/.asfaload/key

    # non-interactive, piped into sign-pending
    asfaload-cli list-pending --json -K ~/.asfaload/key -p "$PASSWORD" \
        | jq -r '.file_paths[]'

## Exit codes

- `0` — query succeeded (even if no files are pending).
- non-zero — error (authentication failure, network error).
