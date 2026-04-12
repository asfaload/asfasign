# `client new-keys`

- **Usage**: `client new-keys [OPTIONS] -n <NAME> -o <OUTPUT_DIR>`
- **Source**: [`src/commands/keys.rs`](../../src/commands/keys.rs)

Generate a new signing key pair. The command creates both a secret key and a public key in the specified directory.

## Options

### `-n --name <NAME>`

Base name for the key files. Produces `<NAME>` (secret key) and `<NAME>.pub` (public key) in the output directory.

### `-o --output-dir <DIR>`

Directory to write the key files into. Created automatically if it doesn't exist.

### `-a --algorithm <ALGORITHM>`

Signing algorithm to use. Defaults to `minisign`.

| Value | Description |
|-------|-------------|
| `minisign` | Minisign format (default) |
| `ed25519` | Raw Ed25519 |

### `-p --password <PASSWORD>`

Password to protect the secret key. Conflicts with `--password-file`. Prompted interactively if neither is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password`.

### `--accept-weak-password`

Bypass password strength validation. **Insecure** — only use for testing.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

- `ASFALOAD_NEW_KEYS_PASSWORD` — alternative to `--password`.
- `ASFALOAD_NEW_KEYS_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default):

    Generating Minisign keypair with name 'mykey' in directory "/home/user/.asfaload"
    Public key saved at /home/user/.asfaload/mykey.pub and secret key at /home/user/.asfaload/mykey

JSON (with `--json`):

    {"public_key_path":"/home/user/.asfaload/mykey.pub","secret_key_path":"/home/user/.asfaload/mykey"}

## Examples

    # generate a minisign key pair
    client new-keys -n mykey -o ~/.asfaload

    # generate an ed25519 key pair
    client new-keys -n mykey -o ~/.asfaload -a ed25519

    # non-interactive usage in CI
    client new-keys -n ci-key -o ./keys -p "$KEY_PASSWORD"

## Exit codes

- `0` — key pair created successfully.
- non-zero — error (invalid directory, password mismatch, etc.).
