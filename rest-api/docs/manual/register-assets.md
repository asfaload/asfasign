# `POST /v1/assets`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `register_assets_handler`

Register assets for signing. Accepts either a GitHub release URL or a list of checksums file URLs — exactly one must be provided.

In GitHub mode, the server fetches the release metadata, downloads all assets, builds an index file, and commits everything to the repository. In checksums mode, it downloads the referenced checksums files, builds the index, and commits.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — Unix timestamp, seconds.
- `X-asfld-nonce` — random nonce.
- `X-asfld-sig` — Ed25519 signature over the canonical request string.
- `X-asfld-pk` — caller's public key.

## Request body

JSON object with exactly one of the two fields set:

### GitHub release mode

    {
      "github_release_url": "https://github.com/acme/repo/releases/tag/v1.0"
    }

### Checksums mode

    {
      "csum_files": [
        "https://example.com/releases/v1.0/SHA256SUMS",
        "https://example.com/releases/v1.0/SHA512SUMS"
      ]
    }

Fields:

- `github_release_url` — full URL to a GitHub release page. Must point to a known GitHub host. Mutually exclusive with `csum_files`.
- `csum_files` — list of URLs to checksums files. All URLs must share the same origin and parent directory. Mutually exclusive with `github_release_url`.

## Response

### `200 OK`

    {
      "success": true,
      "message": "Release registered successfully",
      "index_file_path": "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"
    }

Fields:

- `success` — always `true` on success.
- `message` — human-readable status. Either "Release registered successfully" (GitHub mode) or "Assets registered successfully" (checksums mode).
- `index_file_path` — mirror-relative path to the generated index file.

## Errors

- `400 Bad Request` — both or neither fields provided, invalid URL format, non-GitHub host for `github_release_url`, or invalid checksums URLs.
- `401 Unauthorized` — missing or invalid authentication headers.
- `409 Conflict` — release already registered.
- `500 Internal Server Error` — release processing, checksums download, or Git commit failed.

## Examples

### Register a GitHub release

    curl -sS -X POST 'http://127.0.0.1:3000/v1/assets' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 1712860800' \
      -H 'X-asfld-nonce: <random-nonce>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "github_release_url": "https://github.com/acme/repo/releases/tag/v1.0"
      }'

    {"success":true,"message":"Release registered successfully","index_file_path":"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json"}

### Register checksums files

    curl -sS -X POST 'http://127.0.0.1:3000/v1/assets' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 1712860800' \
      -H 'X-asfld-nonce: <random-nonce>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "csum_files": ["https://example.com/releases/v1.0/SHA256SUMS"]
      }'

    {"success":true,"message":"Assets registered successfully","index_file_path":"https/example.com/443/releases/v1.0/asfaload.index.json"}

### Mutually exclusive fields

    HTTP/1.1 400 Bad Request

    {"error":"github_release_url and csum_files are mutually exclusive"}
