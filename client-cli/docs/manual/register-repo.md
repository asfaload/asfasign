# `client register-repo`

- **Usage**: `client register-repo [OPTIONS] -K <SECRET_KEY> <SIGNERS_FILE_URL>`
- **Source**: [`src/commands/register_repo.rs`](../../src/commands/register_repo.rs)

Register a new repository with the backend. Points the backend at your signers file so it knows which keys are authorized to sign artifacts for this project.

After registration, all signers listed in the file must submit their signatures to activate the project.

## Arguments

### `<SIGNERS_FILE_URL>`

Public URL to the signers file on the forge. For example:

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

- `ASFALOAD_REGISTER_REPO_PASSWORD` — alternative to `--password`.
- `ASFALOAD_REGISTER_REPO_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default):

    Repository registered successfully!
    Project ID: abc123
    Required signers (2): alice, bob
    Next step: signers must submit signatures to activate the project.

JSON (with `--json`):

    {"success":true,"project_id":"abc123","required_signers":["alice","bob"],"message":""}

## Examples

    # register a GitHub-hosted signers file
    client register-repo -K ~/.asfaload/key \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

    # with explicit backend
    client register-repo -K ~/.asfaload/key \
        -u https://asfaload.example.com \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

## Exit codes

- `0` — repository registered.
- non-zero — error (authentication failure, invalid signers file URL, network error).
