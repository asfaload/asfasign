# `GET /v1/files/{file_path}`

- **Auth**: none
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `get_file_handler`

Fetch the raw content of a file from the repository. Returns the file as an `application/octet-stream` byte stream. This is a public endpoint — no authentication is required.

The server validates the path against directory traversal attempts before reading.

## Path parameters

### `file_path`

Mirror-relative path to the file. Slashes are preserved (the route uses a catch-all parameter).

## Response

### `200 OK`

Raw file bytes with headers:

- `Content-Type: application/octet-stream`
- `Content-Length: <size-in-bytes>`

## Errors

- `400 Bad Request` — invalid file path or path traversal detected, or path points to a directory.
- `404 Not Found` — file does not exist.
- `500 Internal Server Error` — failed to read the file.

## Examples

### Fetch a file

    curl -sS 'http://127.0.0.1:3000/v1/files/https/github.com/443/acme/repo/releases/tag/v1.0/asfaload.index.json' \
      -o index.json

### File not found

    curl -sS -i 'http://127.0.0.1:3000/v1/files/https/github.com/443/acme/repo/releases/tag/v1.0/missing.json'

    HTTP/1.1 404 Not Found

    {"error":"File not found: https/github.com/443/acme/repo/releases/tag/v1.0/missing.json"}
