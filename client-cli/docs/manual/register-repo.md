# `asfaload-cli register-repo`

- **Usage**: `asfaload-cli register-repo [OPTIONS] -K <SECRET_KEY> <SIGNERS_FILE_URL>`
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
- `ASFALOAD_REGISTER_REPO_PASSWORD` — alternative to `--password` (still supported, lower precedence).
- `ASFALOAD_REGISTER_REPO_PASSWORD_FILE` — alternative to `--password-file` (still supported, lower precedence).

## Output

Human-readable (default):

    Repository registered successfully!
    Project ID: abc123
    Required signers (2): alice, bob
    Next step: signers must submit signatures to activate the project.

JSON (with `--json`):

    {"success":true,"project_id":"abc123","message":"","required_signers":["alice","bob"],"signature_submission_url":"/v1/signatures"}

## Examples

    # register a GitHub-hosted signers file
    asfaload-cli register-repo -K ~/.asfaload/key \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

    # with explicit backend
    asfaload-cli register-repo -K ~/.asfaload/key \
        -u https://asfaload.example.com \
        https://raw.githubusercontent.com/acme/tool/main/asfaload.signers/index.json

## Exit codes

- `0` — repository registered.
- non-zero — error (authentication failure, invalid signers file URL, network error).
