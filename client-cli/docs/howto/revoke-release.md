# Revoke a signed release

If a release needs to be recalled — a vulnerability was found, or the wrong artifacts were published — you can revoke it. Revoked files can no longer be downloaded with verification.

## Prerequisites

- The release is fully signed and active on the backend.
- Your key is listed as a **revocation key** in the active signers file. Artifact signers without revocation privileges cannot revoke.
- The signers file has a revocation group with a threshold. See [Create a signers file](create-signers-file.md).

## Steps

### 1. Initiate the revocation

```sh
client revoke \
    --secret-key ~/.asfaload/revoke-key \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

On success:

```
Success! File revoked: https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

If the revocation threshold is 1, the file is revoked immediately. If the threshold is higher, the revocation enters a **pending** state and more revocation signers must co-sign.

### 2. Co-sign the revocation (if threshold > 1)

When the revocation threshold requires multiple signatures, additional revocation signers use `list-pending` and `sign-pending` to add their signatures:

```sh
# Another revocation signer checks for pending work
client list-pending --secret-key ~/.asfaload/revoke-key-2
```

The pending revocation shows up as a path ending in `.revocation.json.pending`:

```
Files requiring your signature:
  - https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json.revocation.json.pending
```

Sign it:

```sh
client sign-pending --secret-key ~/.asfaload/revoke-key-2 \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json.revocation.json.pending
```

Once the threshold is met, the revocation is finalized.

### 3. Verify the revocation

Attempting to download a revoked file fails:

```sh
client download https://github.com/acme/tool/releases/download/v1.0/artifact.bin
```

```
This file has been revoked.
  Revoked at: 2025-03-15T10:30:00Z
  Revoked by: asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8
```

## Important notes

- **Only revocation keys can revoke.** Artifact signers listed in the `artifact_signers` group cannot initiate or co-sign a revocation.
- **Revocation is irreversible.** Once a file is revoked, it stays revoked.
- **Other releases are unaffected.** Revoking v1.0 does not impact v2.0.
- **Re-initiating a pending revocation fails.** If a revocation is already pending, starting another one for the same file is rejected.

## Reference

- [`client revoke`](../manual/revoke.md)
- [`client list-pending`](../manual/list-pending.md)
- [`client sign-pending`](../manual/sign-pending.md)
