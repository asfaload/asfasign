# `GET /v1/files-to-sign/{file_path}`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `get_files_to_sign_handler`

Fetch the contents of all files that need to be signed for a given artifact. For regular files, the response contains only the primary file. For signers files, it includes both the signers file and its metadata file. All contents are base64-encoded.

This endpoint is used by the client CLI during the sign-pending workflow to retrieve file contents before computing signatures locally.

## Path parameters

### `file_path`

Mirror-relative path to the file. Slashes are preserved (the route uses a catch-all parameter).

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature over the canonical request string.
- `X-asfld-pk` — caller's public key.

## Response

### `200 OK`

For a regular artifact:

    {
      "files": {
        "https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json": "<base64-content>"
      }
    }

For a signers file (includes metadata):

    {
      "files": {
        "https/github.com/443/acme/repo/asfaload.signers.pending/asfaload.signers.json": "<base64-content>",
        "https/github.com/443/acme/repo/asfaload.signers.pending/asfaload.signers.json.metadata.json": "<base64-content>"
      }
    }

Fields:

- `files` — map of mirror-relative file paths to their base64-encoded contents.

## Errors

- `400 Bad Request` — invalid file path.
- `401 Unauthorized` — missing or invalid authentication headers.
- `404 Not Found` — file does not exist.
- `500 Internal Server Error` — failed to determine file type, read file, or locate metadata file for a signers file.

## Examples

### Fetch files for a release artifact

    curl -sS 'http://127.0.0.1:3000/v1/files-to-sign/https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00+00:00' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>'

    {"files":{"https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json":"<base64-content>"}}

### File not found

    HTTP/1.1 404 Not Found

    {"error":"File not found: https/github.com/443/acme/repo/releases/tag/v1.0/missing.json"}
