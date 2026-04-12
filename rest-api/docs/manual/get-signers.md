# `GET /v1/get_signers/{file_path}`

- **Auth**: none
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `get_signers_handler`

Fetch the signers configuration that applies to a given path. The server walks parent directories from the given path upward until it finds an active signers file, then returns its raw JSON content. This is a public endpoint — no authentication is required.

## Path parameters

### `file_path`

Mirror-relative path to any file or directory in the repository. The server locates the nearest signers file by traversing parent directories. Slashes are preserved (the route uses a catch-all parameter).

## Response

### `200 OK`

Raw signers file JSON with headers:

- `Content-Type: application/json`
- `Content-Length: <size-in-bytes>`

The body is the signers configuration file as stored on disk — a `SignersConfig` JSON object.

## Errors

- `400 Bad Request` — invalid file path.
- `404 Not Found` — no signers file found in any parent directory of the given path.
- `500 Internal Server Error` — failed to read the signers file.

## Examples

### Fetch signers for a release artifact

    curl -sS 'http://127.0.0.1:3000/v1/get_signers/https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json'

Returns the content of the nearest `asfaload.signers/asfaload.signers.json` ancestor.

### No signers file found

    curl -sS -i 'http://127.0.0.1:3000/v1/get_signers/https/github.com/443/unknown/repo/file.txt'

    HTTP/1.1 404 Not Found

    {"error":"No signers file found for: https/github.com/443/unknown/repo/file.txt. Error: No signers file found in parent directories"}
