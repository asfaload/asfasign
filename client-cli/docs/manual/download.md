# `asfaload-cli download`

- **Usage**: `asfaload-cli download [OPTIONS] <FILE_URL>`
- **Source**: [`src/commands/download.rs`](../../src/commands/download.rs)

Download a file and verify its signatures before saving. The command fetches the signers file, index, and signatures from the backend, checks everything is valid, then downloads the actual file and verifies its hash.

If the file has been revoked, a warning is printed to stderr and the download is aborted.

## Arguments

### `<FILE_URL>`

Public URL of the file to download. For example:

    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

## Options

### `-o --output <PATH>`

Output file path. Defaults to the filename extracted from the URL.

### `-u --backend-url <URL>`

Backend API URL. Defaults to `http://127.0.0.1:3000`.

### `--type <FORGE_TYPE>`

Override automatic forge type detection.

| Value | Description |
|-------|-------------|
| `github` | GitHub release |
| `gitlab` | GitLab release |
| `fileserver` | Generic file server |

### `--full-check`

Verify the full signers chain history during download. Without this flag only the current signers file is checked.

## Output

The command prints progress to stdout as each verification step completes:

    Starting download: https://github.com/acme/tool/releases/download/v1.0/tool.tar.gz
    ✓ Downloaded signers file (1234 bytes)
    ✓ Downloaded index file (567 bytes)
    ✓ Downloaded signatures file (890 bytes)
    ✓ Signatures verified successfully (2 valid)
    ✓ Signers chain history verified (3 entries)
    Downloading tool.tar.gz
      Size: 12.50 MB
    Progress: 100.0% (12.50 MB / 12.50 MB)
    ✓ Download complete (12.50 MB)
    ✓ File hash verified (SHA-256)
    ✓ File saved to: ./tool.tar.gz
    ✓ All done! Verified 2 signature(s)

If the file has been revoked:

    This file has been revoked.
      Revoked at: 2025-03-15T10:30:00Z
      Revoked by: asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8

## Examples

    # download and verify a release artifact
    asfaload-cli download \
        https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

    # save to a specific path
    asfaload-cli download -o /tmp/tool.tar.gz \
        https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

    # verify the full signers chain history
    asfaload-cli download --full-check \
        https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz

    # override forge detection
    asfaload-cli download --type gitlab \
        https://gitlab.com/acme/tool/-/releases/v1.0/downloads/tool.tar.gz

## Exit codes

- `0` — download and verification succeeded.
- non-zero — error (verification failure, revoked file, network error).
