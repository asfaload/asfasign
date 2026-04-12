# `POST /v1/register_repo`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `register_repo_handler`

Register a new project with the signing server. The server fetches the signers file from the forge URL, validates it, creates the directory structure, records the first signature, and commits the result to the backing Git repository.

A project can only be registered once. Calling this endpoint again for an already-registered project returns an error.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — Unix timestamp, seconds.
- `X-asfld-nonce` — random nonce.
- `X-asfld-sig` — Ed25519 signature over the canonical request string.
- `X-asfld-pk` — caller's public key.

## Request body

JSON object:

    {
      "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
      "public_key": "<base64-public-key>"
    }

Fields:

- `signers_file_url` — URL pointing to the signers file on the forge (GitHub, GitLab, or file server).
- `public_key` — base64-encoded Ed25519 public key of the submitter. Must match one of the keys in the signers file.

## Response

### `200 OK`

    {
      "success": true,
      "project_id": "https/github.com/443/acme/repo",
      "message": "Project registered successfully. Collect signatures to activate.",
      "required_signers": ["<base64-public-key-1>", "<base64-public-key-2>"],
      "signature_submission_url": "/v1/signatures"
    }

Fields:

- `success` — always `true` on success.
- `project_id` — normalised identifier for the registered project.
- `message` — human-readable status message.
- `required_signers` — list of base64-encoded public keys that still need to sign.
- `signature_submission_url` — path to use for submitting signatures.

## Errors

- `400 Bad Request` — invalid or unparseable forge URL, or invalid public key.
- `401 Unauthorized` — missing or invalid authentication headers.
- `409 Conflict` — project is already registered or registration is in progress.
- `500 Internal Server Error` — forge validation, signers initialisation, or Git commit failed.

## Examples

### Successful registration

    curl -sS -X POST 'http://127.0.0.1:3000/v1/register_repo' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 1712860800' \
      -H 'X-asfld-nonce: <random-nonce>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
        "public_key": "<base64-public-key>"
      }'

    {"success":true,"project_id":"https/github.com/443/acme/repo","message":"Project registered successfully. Collect signatures to activate.","required_signers":["<base64-pk-1>","<base64-pk-2>"],"signature_submission_url":"/v1/signatures"}

### Project already registered

    HTTP/1.1 409 Conflict

    {"error":"Project 'https/github.com/443/acme/repo' is already registered or registration is in progress."}
