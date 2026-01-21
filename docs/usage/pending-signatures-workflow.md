# Pending Signatures Workflow

This guide explains how signers can discover and submit signatures for files published on the Asfaload mirror.

## Overview

As a signer, you can use the client CLI to:
1. List all files that require your signature
2. Submit your signature in one convenient command

The workflow is secure - all requests are authenticated using your private key.

## Listing Pending Signatures

Use the `list-pending` command to see which files need your signature:

```bash
client list-pending --secret-key ~/.asfaload/my-key.minisign
```

You'll be prompted for your password (if required), then see output like:

```
Enter password: *****
Files requiring your signature:
  - github.com/org/repo/releases/v1.0.0/asfaload.index.json
  - github.com/org/repo/releases/v1.1.0/checksums.txt
```

### Options

- `--secret-key, -K` - Path to your secret key file (required)
- `--backend-url, -u` - Backend API URL (default: http://127.0.0.1:3000)

## Submitting Signatures

To sign a pending file, use the `sign-pending` command:

```bash
client sign-pending github.com/org/repo/releases/v1.0.0/asfaload.index.json --secret-key ~/.asfaload/my-key.minisign
```

The CLI will:
1. Fetch the file content from the backend
2. Compute the hash
3. Sign with your key
4. Submit to the backend

You'll see:

```
Enter password: *****
Success! Signature submitted (complete)
```

or if the file needs more signatures:

```
Enter password: *****
Success! Signature submitted
```

### Options

- `file_path` - Path to the file (as shown by list-pending) (required)
- `--secret-key, -K` - Path to your secret key file (required)
- `--backend-url, -u` - Backend API URL (default: http://127.0.0.1:3000)

## Example Workflow

```bash
# 1. Check what needs signing
$ client list-pending --secret-key ~/.asfaload/my-key.minisign
Enter password: *****
Files requiring your signature:
  - github.com/asfaload/asfald/releases/v0.5.0/asfaload.index.json

# 2. Sign it in one command
$ client sign-pending github.com/asfaload/asfald/releases/v0.5.0/asfaload.index.json --secret-key ~/.asfaload/my-key.minisign
Enter password: *****
Success! Signature submitted

# 3. Verify no more pending files
$ client list-pending --secret-key ~/.asfaload/my-key.minisign
Enter password: *****
No pending signatures found.
```

## Security Notes

- Your private key never leaves your machine
- All requests to the backend are signed
- Password is only used to decrypt your key locally
- Only you can sign with your private key
