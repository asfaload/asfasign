# Generate a key pair

Every signer needs their own key pair. This guide walks you through creating one.

## Prerequisites

- The `client` binary is installed and in your `PATH`.

## Steps

### 1. Choose a directory

Pick a directory to store your keys. A common convention is `~/.asfaload/`:

```sh
mkdir -p ~/.asfaload
```

### 2. Generate the key pair

```sh
client new-keys --name mykey --output-dir ~/.asfaload
```

You'll be prompted for a password to protect the secret key. Pick a strong one — this password is required every time you sign.

This creates two files:

| File | Purpose |
|------|---------|
| `~/.asfaload/mykey` | Secret key (keep this safe) |
| `~/.asfaload/mykey.pub` | Public key (share with your team) |

### 3. Verify the output

```sh
ls ~/.asfaload/mykey*
```

You should see both `mykey` and `mykey.pub`.

## Non-interactive usage

For CI or scripting, pass the password directly:

```sh
client new-keys --name ci-key --output-dir ./keys --password "$KEY_PASSWORD"
```

Or read the password from a file with `--password-file` (`-P`):

```sh
client new-keys --name ci-key --output-dir ./keys --password-file /run/secrets/key-password
```

The file should contain the password on a single line. Trailing newlines are stripped.

Both options are also available as environment variables:

```sh
export ASFALOAD_NEW_KEYS_PASSWORD="$KEY_PASSWORD"
client new-keys --name ci-key --output-dir ./keys
```

```sh
export ASFALOAD_NEW_KEYS_PASSWORD_FILE="/run/secrets/key-password"
client new-keys --name ci-key --output-dir ./keys
```

## Next step

Share your `.pub` file with whoever maintains the signers file, it is not secret.  They'll include it when [creating the signers file](create-signers-file.md).

## Reference

- [`client new-keys`](../manual/new-keys.md)
