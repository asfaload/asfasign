# `client update-signers`

- **Usage**: `client update-signers [OPTIONS] -K <SECRET_KEY> <SIGNERS_FILE_URL>`
- **Source**: [`src/commands/update_signers.rs`](../../src/commands/update_signers.rs)

Propose an update to an existing project's signers file. The backend fetches the new file from the forge and starts a signature collection round — signers from the **current** configuration must approve the change before it takes effect.

## Arguments

### `<SIGNERS_FILE_URL>`

Public URL to the **new** signers file on the forge. For example:

    https://raw.githubusercontent.com/owner/repo/main/asfaload.signers/index.json

## Options

### `-K --secret-key <PATH>`

Path to your secret key file. Required.

### `-p --password <PASSWORD>`

Password for the secret key. Conflicts with `--password-file`. Prompted interactively if neither is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password`.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `http://127.0.0.1:3000`.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

- `ASFALOAD_UPDATE_SIGNERS_PASSWORD` — alternative to `--password`.
- `ASFALOAD_UPDATE_SIGNERS_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default):

    Signers update proposed successfully!
    Project ID: abc123
    Required signers (2): alice, bob
    Next step: signers must submit signatures to activate the update.

JSON (with `--json`):

    {"success":true,"project_id":"abc123","required_signers":["alice","bob"],"message":""}

## Examples

    # propose a signers update
    client update-signers -K ~/.asfaload/key \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

## Exit codes

- `0` — update proposed.
- non-zero — error (authentication failure, invalid signers file, network error).
