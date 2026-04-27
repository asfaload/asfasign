# `client register-assets`

- **Usage**: `client register-assets [OPTIONS] -K <SECRET_KEY>`
- **Source**: [`src/commands/register_assets.rs`](../../src/commands/register_assets.rs)

Register assets for signing. Tell the backend about a new set of files — either a GitHub release or one or more checksum files — so that the signature collection process can begin.

After registration you still need to sign the assets yourself with [`sign-pending`](sign-pending.md).

## Options

### `--github-release-url <URL>`

URL of a GitHub release page. The backend fetches the release assets automatically. Mutually exclusive with `--csum-file`.

### `--csum-file <URL>`

URL of a checksums file. Repeatable — pass once per file. All URLs must share a common parent path. Mutually exclusive with `--github-release-url`.

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

- `ASFALOAD_REGISTER_ASSETS_PASSWORD` — alternative to `--password`.
- `ASFALOAD_REGISTER_ASSETS_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default):

    Assets registered successfully! Remember you still need to sign it yourself!
    Index file path: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json

JSON (with `--json`):

    {"success":true,"message":"","index_file_path":"https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json"}

## Examples

    # register a GitHub release
    client register-assets -K ~/.asfaload/key \
        --github-release-url https://github.com/acme/tool/releases/tag/v1.0

    # register checksum files
    client register-assets -K ~/.asfaload/key \
        --csum-file https://example.com/releases/v1.0/SHA256SUMS \
        --csum-file https://example.com/releases/v1.0/SHA512SUMS

## Exit codes

- `0` — assets registered.
- non-zero — error (authentication failure, invalid URL, mutually exclusive flags, network error).
