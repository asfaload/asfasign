# `POST /v1/signatures`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `submit_signature_handler`

Submit one or more signatures for a file. The server validates each signature against the signer's public key and the file content, adds it to the pending collection, and commits the result to Git. Once all required signatures are collected, the aggregate signature is marked complete.

For signers files, the request must include signatures for both the signers file itself and its metadata file.

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
      "public_key": "<base64-public-key>",
      "signatures": {
        "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json": "<base64-signature>"
      }
    }

Fields:

- `file_path` — mirror-relative path to the primary file being signed.
- `public_key` — base64-encoded Ed25519 public key of the signer.
- `signatures` — map of file paths to their base64-encoded Ed25519 signatures. Must include at least the primary `file_path`. For signers files, include the metadata file path as well.

## Response

### `200 OK`

    {
      "is_complete": false
    }

Fields:

- `is_complete` — `true` when all required signatures have been collected; `false` while signatures are still pending.

## Errors

- `400 Bad Request` — empty file path, file not found, invalid public key or signature format, or no signature provided for the primary file.
- `401 Unauthorized` — missing or invalid authentication headers.
- `409 Conflict` — signature already collected for this key, or signature already added.
- `500 Internal Server Error` — signature collection or Git commit failed.

## Examples

### Successful submission (collection not yet complete)

    curl -sS -X POST 'http://127.0.0.1:3000/v1/signatures' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 1712860800' \
      -H 'X-asfld-nonce: <random-nonce>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json",
        "public_key": "<base64-public-key>",
        "signatures": {
          "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json": "<base64-signature>"
        }
      }'

    {"is_complete":false}

### File not found

    HTTP/1.1 400 Bad Request

    {"error":"File not found: https/github.com/443/acme/repo/releases/tag/v1.0/missing.json"}
