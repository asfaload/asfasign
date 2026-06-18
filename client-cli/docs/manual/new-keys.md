# `asfaload-cli new-keys`

- **Usage**: `asfaload-cli new-keys [OPTIONS] -n <NAME> -d <OUTPUT_DIR>`
- **Source**: [`src/commands/keys.rs`](../../src/commands/keys.rs)

Generate a new signing key pair. The command creates both a secret key and a public key in the specified directory.

## Options

### `-n --name <NAME>`

Base name for the key files. Produces `<NAME>` (secret key) and `<NAME>.pub` (public key) in the output directory.

### `-d --output-dir <DIR>`

Directory to write the key files into. Created automatically if it doesn't exist.

### `-p --password <PASSWORD>`

Password to protect the secret key. Conflicts with `--password-file` and `--password-command`. Prompted interactively if none of these is set.

### `-P --password-file <PATH>`

File containing the password. Conflicts with `--password` and `--password-command`.

### `-c --password-command <COMMAND>`

Shell command to run; its standard output is read as the password. Useful for password managers (`pass`, `op`, `bw`, etc.). Conflicts with `--password` and `--password-file`. The command string is parsed with shell-style quoting (no shell is spawned, so pipes and redirections don't apply); trailing newlines are stripped from the output.

### `--accept-weak-password`

Bypass password strength validation. **Insecure** — only use for testing.

### `--json`

Emit output as JSON instead of human-readable text.

## Environment

- `ASFALOAD_NEW_KEYS_PASSWORD` — alternative to `--password`.
- `ASFALOAD_NEW_KEYS_PASSWORD_FILE` — alternative to `--password-file`.

## Output

Human-readable (default):

    Generating keypair with name 'mykey' in directory "/home/user/.asfaload"
    Public key saved at /home/user/.asfaload/mykey.pub and secret key at /home/user/.asfaload/mykey

JSON (with `--json`):

    {"public_key_path":"/home/user/.asfaload/mykey.pub","secret_key_path":"/home/user/.asfaload/mykey"}

## Examples

    # generate a key pair
    asfaload-cli new-keys -n mykey -d ~/.asfaload

    # non-interactive usage in CI
    asfaload-cli new-keys -n ci-key -d ./keys -p "$KEY_PASSWORD"

## Exit codes

- `0` — key pair created successfully.
- non-zero — error (invalid directory, password mismatch, etc.).
