# rest-api manual

Reference for the Asfaload REST API.

## Registration

- [`POST /v1/register_repo`](register-repo.md) — register a new project with the signing server
- [`POST /v1/update_signers`](update-signers.md) — propose an update to a project's signers file

## Signatures

- [`POST /v1/signatures`](submit-signature.md) — submit signatures for a file
- [`GET /v1/signatures/{file_path}`](signature-status.md) — query signature collection status for a file
- [`GET /v1/pending_signatures`](pending-signatures.md) — list files awaiting the caller's signature

## Files

- [`GET /v1/files/{file_path}`](get-file.md) — fetch raw file content from the repository
- [`GET /v1/files-to-sign/{file_path}`](files-to-sign.md) — fetch file contents needed for signing

## Signers

- [`GET /v1/get_signers/{file_path}`](get-signers.md) — get the signers configuration for a path
- [`GET /v1/get_signers_chain/{artifact_path}`](get-signers-chain.md) — get the signers history chain for a signed artifact

## Revocation

- [`POST /v1/revoke`](revoke.md) — revoke a previously signed file

## Assets

- [`POST /v1/assets`](register-assets.md) — register assets from a GitHub release or checksums files
