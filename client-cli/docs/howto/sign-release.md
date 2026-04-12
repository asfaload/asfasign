# Sign a release

After a release is [registered](register-release.md), artifact signers must provide enough signatures to meet the threshold defined in the signers file. This is the same `list-pending` / `sign-pending` flow used for [activating a signers file](activate-signers-file.md), but applied to a release index.

## Prerequisites

- A release has been [registered](register-release.md).
- Your key is listed as an artifact signer in the active signers file.

## Steps

### 1. List pending files

```sh
client list-pending --secret-key ~/.asfaload/mykey
```

```
Files requiring your signature:
  - https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

### 2. Sign the release index

```sh
client sign-pending --secret-key ~/.asfaload/mykey \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

The command fetches all files associated with the release, hashes each one, signs the hashes, and submits everything in a single request.

If more signatures are needed:

```
Success! Signature submitted
```

When the threshold is met:

```
Success! Signature submitted (complete)
```

### 3. Check progress

At any point, you can check whether the threshold has been reached:

```sh
client signature-status --secret-key ~/.asfaload/mykey \
    https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json
```

```
https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json: pending
```

or

```
https/github.com/443/acme/tool/releases/tag/v1.0/asfaload.index.json: complete
```

## Example: two-of-three threshold

With three artifact signers and a threshold of 2, only two need to sign:

```
alice: client sign-pending --secret-key alice.key ...  → "submitted"
bob:   client sign-pending --secret-key bob.key ...    → "submitted (complete)"
# carol doesn't need to sign — threshold already met
```

## Next step

Once the release is fully signed, users can [download it with verification](download-with-verification.md).

## Reference

- [`client list-pending`](../manual/list-pending.md)
- [`client sign-pending`](../manual/sign-pending.md)
- [`client signature-status`](../manual/signature-status.md)
