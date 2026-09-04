# Download a file with signature verification

The `download` command fetches a file and verifies its signatures before saving it to disk. If the signatures don't check out, or the file has been revoked, the download is aborted.

## Prerequisites

- The file has been signed on the backend (signatures meet the threshold).
- The backend is running and reachable.

## Steps

### 1. Download a release artifact

Pass the original download URL — the same URL you'd use to download from GitHub or your forge:

```sh
asfaload-cli download \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

The command prints each verification step:

```
Starting download: https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
✓ Downloaded index file (567 bytes)
✓ Downloaded signatures file (890 bytes)
Downloading tool-linux-amd64.tar.gz
Progress: 2.00 MB
✓ Signers chain history verified (3 entries)
✓ Signatures verified successfully (2 valid)
✓ Download complete (12.50 MB)
✓ File hash verified (SHA-256)
✓ File saved to: ./tool-linux-amd64.tar.gz
✓ All done! Verified 2 signature(s)
```

The file download, signers chain validation, and revocation probe run in parallel, so the `Progress:` and `✓ Signers chain history verified` lines may interleave in any order.

![Demo: download with verification](demos/download-with-verification.gif)

### 2. Choose where to save

By default, the file is saved in the current directory using the filename from the URL. Use `-o` to specify a different path:

```sh
asfaload-cli download -o /tmp/tool.tar.gz \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

## Signers chain verification

The full signers chain history is always verified as part of the download — there is no flag to skip it. The chain is walked entry by entry and each entry is verified against the forge, catching tampering in historical signers files (e.g. a signers file updated since the release was signed). A successful check prints:

```
✓ Signers chain history verified (3 entries)
```

If chain validation fails, a `✗ Signers chain verification failed: <reason>` line is printed to stderr and the download is aborted.

## Overriding forge detection

The CLI auto-detects the forge type from the URL. If detection fails or you're using a generic file server:

```sh
asfaload-cli download --type fileserver \
    https://files.example.com/tool/v1.0/tool.tar.gz
```

Available types: `github`, `gitlab`, `fileserver`.

## Pointing to a non-default backend

```sh
asfaload-cli download -u https://asfaload.example.com \
    https://github.com/acme/tool/releases/download/v1.0/tool-linux-amd64.tar.gz
```

## What happens with revoked files

If the file has been [revoked](revoke-release.md), the download fails:

```
This file has been revoked.
  Revoked at: 2025-03-15T10:30:00Z
  Revoked by: asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

## Reference

- [`asfaload-cli download`](../manual/download.md)
