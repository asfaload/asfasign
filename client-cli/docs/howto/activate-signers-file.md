# Activate a signers file

After a repository is registered (or a signers file is updated), the signers file sits in a **pending** state. Every signer listed in it must sign before the project becomes active. This guide covers the signing round.

## Prerequisites

- A repository has been [registered](register-repo.md) or a signers file [update proposed](update-signers-file.md).
- Each signer has their own secret key. See [Generate a key pair](generate-keys.md).

## Steps

Each signer performs steps 1–2 independently.

### 1. Check for pending work

```sh
asfaload-cli list-pending --secret-key ~/.asfaload/mykey
```

If the signers file is waiting for your signature, you'll see:

```
Files requiring your signature:
  - https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

If nothing is pending for you, the output says `No pending signatures found.`

### 2. Sign the pending signers file

Copy the path from the output above and pass it to `sign-pending`:

```sh
asfaload-cli sign-pending --secret-key ~/.asfaload/mykey \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

If more signatures are needed:

```
Success! Signature submitted
```

When your signature completes the required count (every signer must sign for an initial signers file):

```
Success! Signature submitted (complete)
```

![Demo: sign the pending signers file](demos/activate-signers-file.gif)

### 3. Verify activation

Once every signer has signed, the signers file moves from pending to active. There is no separate activation step — the last signature triggers it automatically.

## Coordinating signers

Signers don't need to sign in any particular order. The workflow looks like:

```
alice: asfaload-cli list-pending --secret-key alice.key    → sees pending signers
alice: asfaload-cli sign-pending --secret-key alice.key ...  → "submitted"

bob:   asfaload-cli list-pending --secret-key bob.key      → sees pending signers
bob:   asfaload-cli sign-pending --secret-key bob.key ...    → "submitted"

carol: asfaload-cli list-pending --secret-key carol.key    → sees pending signers
carol: asfaload-cli sign-pending --secret-key carol.key ...  → "submitted (complete)"
```

## Scripting the sign step

For CI, supply the password non-interactively:

```sh
asfaload-cli sign-pending \
    --secret-key ~/.asfaload/mykey \
    --password-file "/path/to/password-file" \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

## Troubleshooting

**"Already completed" error when signing** — someone else already provided the final signature. The signers file is active; no action needed.

**list-pending returns empty** — either your key is not listed in the signers file, or the file has already been fully signed.

## Next step

Once the signers file is active, you can [register a release](register-release.md) for signing.

## Reference

- [`asfaload-cli list-pending`](../manual/list-pending.md)
- [`asfaload-cli sign-pending`](../manual/sign-pending.md)
