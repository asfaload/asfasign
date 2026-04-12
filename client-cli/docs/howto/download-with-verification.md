# Download a file with signature verification

The `download` command fetches a file and verifies its signatures before saving it to disk. If the signatures don't check out, or the file has been revoked, the download is aborted.

## Prerequisites

- The file has been signed on the backend (signatures meet the threshold).
- The backend is running and reachable.

## Steps

### 1. Download a release artifact

Pass the original download URL — the same URL you'd use to download from GitHub or your forge:

```sh
client download \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

The command prints each verification step:

```
Starting download: https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
✓ Downloaded signers file (1234 bytes)
✓ Downloaded index file (567 bytes)
✓ Downloaded signatures file (890 bytes)
✓ Signatures verified successfully (2 valid)
Downloading tool-linux-amd64.tar.gz
  Size: 12.50 MB
Progress: 100.0% (12.50 MB / 12.50 MB)
✓ Download complete (12.50 MB)
✓ File hash verified (SHA-256)
✓ File saved to: ./tool-linux-amd64.tar.gz
✓ All done! Verified 2 signature(s)
```

### 2. Choose where to save

By default, the file is saved in the current directory using the filename from the URL. Use `-o` to specify a different path:

```sh
client download -o /tmp/tool.tar.gz \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

## Full signers chain verification

By default, only the current signers file is verified. For stronger assurance — especially if the signers file has been updated since the release was signed — use `--full-check`:

```sh
client download --full-check \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

This walks the full signers chain history and verifies each entry against the forge, catching tampering in historical signers files. You'll see an additional verification line:

```
✓ Signers chain history verified (3 entries)
```

## Overriding forge detection

The CLI auto-detects the forge type from the URL. If detection fails or you're using a generic file server:

```sh
client download --type fileserver \
    https://files.example.com/tool/v1.0/tool.tar.gz
```

Available types: `github`, `gitlab`, `fileserver`.

## Pointing to a non-default backend

```sh
client download -u https://asfaload.example.com \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

## What happens with revoked files

If the file has been [revoked](revoke-release.md), the download fails:

```
This file has been revoked.
  Revoked at: 2025-03-15T10:30:00Z
  Revoked by: minisign:RWQwtmTQyX/sEi37...
```

## Reference

- [`client download`](../manual/download.md)
