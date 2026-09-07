# `POST /v1/update_signers`

- **Auth**: required
- **Source**: [`src/handlers.rs`](../../src/handlers.rs) — `update_signers_handler`

Propose an update to a project's signers file. The server fetches the new signers file from the forge, validates it, writes it as a pending proposal, and commits the result. The project must already be registered and have an active signers file.

Like initial registration, the update requires all new signers to submit their signatures before it takes effect.

## Request headers

Standard Asfaload authentication headers, signed by the caller's secret key:

- `X-asfld-timestamp` — request timestamp, RFC 3339 format.
- `X-asfld-nonce` — random UUID v4, unique per request.
- `X-asfld-sig` — Ed25519 signature over the canonical request string.
- `X-asfld-pk` — caller's public key.

## Request body

JSON object (same shape as `register_repo`):

    {
      "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
      "public_key": "<base64-public-key>"
    }

Fields:

- `signers_file_url` — URL pointing to the updated signers file on the forge.
- `public_key` — base64-encoded Ed25519 public key of the submitter.

## Response

### `200 OK`

    {
      "success": true,
      "project_id": "https/github.com/443/acme/repo",
      "message": "Signers update proposed successfully. Collect signatures to activate.",
      "required_signers": ["<base64-public-key-1>", "<base64-public-key-2>"],
      "signature_submission_url": "/v1/signatures"
    }

Fields:

- `success` — always `true` on success.
- `project_id` — normalised project identifier.
- `message` — human-readable status message.
- `required_signers` — list of base64-encoded public keys that need to sign the update.
- `signature_submission_url` — path to use for submitting signatures.

## Errors

- `400 Bad Request` — project not registered, no active signers file, invalid forge URL, or invalid public key.
- `401 Unauthorized` — missing or invalid authentication headers.
- `500 Internal Server Error` — forge validation, proposal creation, or Git commit failed.

## Examples

### Successful update proposal

    curl -sS -X POST 'http://127.0.0.1:3000/v1/update_signers' \
      -H 'Content-Type: application/json' \
      -H 'X-asfld-timestamp: 2024-04-11T20:00:00Z' \
      -H 'X-asfld-nonce: <random-uuid-v4>' \
      -H 'X-asfld-sig: <base64-signature>' \
      -H 'X-asfld-pk: <base64-public-key>' \
      -d '{
        "signers_file_url": "https://github.com/acme/repo/blob/main/asfaload.signers.json",
        "public_key": "<base64-public-key>"
      }'

    {"success":true,"project_id":"https/github.com/443/acme/repo","message":"Signers update proposed successfully. Collect signatures to activate.","required_signers":["<base64-pk-1>","<base64-pk-2>"],"signature_submission_url":"/v1/signatures"}

### Project not registered

    HTTP/1.1 400 Bad Request

    {"error":"Project 'https/github.com/443/acme/repo' is not registered. Register the repo first."}
