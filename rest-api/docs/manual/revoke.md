# `POST /v1/revoke`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `revoke_handler`

Revoke a previously signed file. The caller provides a revocation document (as a JSON string), a signature over its SHA-512 digest, and their public key. The server validates that the file has a complete aggregate signature, verifies the revocation authorization, and records the revocation.

Only files with a complete aggregate signature can be revoked. Files that are still collecting signatures or already revoked are rejected.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — Unix timestamp, seconds.
- `X-asfld-nonce` — random nonce.
- `X-asfld-sig` — Ed25519 signature over the canonical request string.
- `X-asfld-pk` — caller's public key.

## Request body

JSON object:

    {
      "file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json",
      "revocation_json": "{\"reason\":\"compromised\",\"timestamp\":1712860800}",
      "signature": "<base64-signature>",
      "public_key": "<base64-public-key>"
    }

Fields:

- `file_path` — mirror-relative path to the signed file being revoked.
- `revocation_json` — JSON string of the revocation document (`RevocationInfo`).
- `signature` — base64-encoded Ed25519 signature of the SHA-512 digest of `revocation_json`.
- `public_key` — base64-encoded Ed25519 public key of the revoker.

## Response

### `200 OK`

    {
      "success": true,
      "message": "File revoked successfully"
    }

Fields:

- `success` — always `true` on success.
- `message` — human-readable confirmation.

## Errors

- `400 Bad Request` — empty file path, invalid public key or signature format, digest mismatch, file already revoked, or revocation authorization failed.
- `401 Unauthorized` — missing or invalid authentication headers.
- `404 Not Found` — file does not exist.
- `409 Conflict` — file has not been fully signed yet.
- `500 Internal Server Error` — revocation processing or Git commit failed.

## Examples

### Successful revocation

    curl -sS -X POST 'http://127.0.0.1:3000/v1/revoke' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 1712860800' \
      -H 'X-asfld-nonce: <random-nonce>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json",
        "revocation_json": "{\"reason\":\"compromised\",\"timestamp\":1712860800}",
        "signature": "<base64-revocation-signature>",
        "public_key": "<base64-public-key>"
      }'

    {"success":true,"message":"File revoked successfully"}

### File not fully signed

    HTTP/1.1 409 Conflict

    {"error":"File has not been fully signed: https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"}
