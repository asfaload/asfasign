# `GET /v1/pending_signatures`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `get_pending_signatures_handler`

List all files that still need the caller's signature. The server walks the repository, finds files with pending aggregate signatures, and filters to those where the caller is an authorized signer who has not yet signed.

The returned paths point to the artifact files themselves, not to the `.signatures.json.pending` files used internally.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random nonce.
- `X-asfld-sig` — Ed25519 signature over the canonical request string.
- `X-asfld-pk` — caller's public key.

## Response

### `200 OK`

    {
      "file_paths": [
        "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json",
        "https/github.com/443/acme/repo/asfaload.signers.pending/asfaload.signers.json"
      ]
    }

Fields:

- `file_paths` — list of mirror-relative paths to files awaiting the caller's signature. Empty array if nothing is pending.

## Errors

- `401 Unauthorized` — missing or invalid authentication headers.
- `500 Internal Server Error` — failed to scan repository or check signer authorization.

## Examples

### Files pending signature

    curl -sS 'http://127.0.0.1:3000/v1/pending_signatures' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00Z' \
      -H 'X-asfld-nonce: <random-nonce>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>'

    {"file_paths":["https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"]}

### Nothing pending

    {"file_paths":[]}
