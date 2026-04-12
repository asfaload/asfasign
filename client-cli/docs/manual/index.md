# client-cli manual

Reference for all `client` commands.

## Keys

- [`new-keys`](new-keys.md) — generate a new signing key pair

## Signers

- [`new-signers-file`](new-signers-file.md) — create a signers file defining authorized keys and thresholds
- [`update-signers`](update-signers.md) — propose an update to an existing signers file

## Registration

- [`register-repo`](register-repo.md) — register a repository with the backend
- [`register-assets`](register-assets.md) — register assets (GitHub release or checksum files) for signing

## Signing

- [`list-pending`](list-pending.md) — list files that still need your signature
- [`sign-pending`](sign-pending.md) — sign a pending file
- [`signature-status`](signature-status.md) — check a file's signature collection status

## Revocation

- [`revoke`](revoke.md) — revoke a previously signed file

## Verification

- [`download`](download.md) — download a file with signature verification
