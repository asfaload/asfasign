# `asfaload-cli new-signers-file`

- **Usage**: `asfaload-cli new-signers-file [OPTIONS] -o <OUTPUT_FILE>`
- **Source**: [`src/commands/signers_file.rs`](../../src/commands/signers_file.rs)

Create a new signers file that defines who can sign artifacts, administer, and manage the project. At minimum, one artifact signer and its threshold are required.

## Options

### Artifact signers

Every signers file needs at least one artifact signer.

#### `-a --artifact-signer <BASE64_KEY>`

Public key as a base64 string. Repeatable.

#### `--artifact-signers-file <PATH>`

Path to a `.pub` key file. Repeatable. Combines with `--artifact-signer`.

#### `-A --artifact-threshold <N>`

Number of artifact signers required to complete a signature. Must be between 1 and the total number of artifact signers.

### Admin keys (optional)

#### `-d --admin-key <BASE64_KEY>`

Admin public key as a base64 string. Repeatable.

#### `--admin-keys-file <PATH>`

Path to an admin `.pub` key file. Repeatable.

#### `-D --admin-threshold <N>`

Required when admin keys are provided. Number of admins required to approve changes.

### Master keys (optional)

#### `-m --master-key <BASE64_KEY>`

Master public key as a base64 string. Repeatable.

#### `--master-keys-file <PATH>`

Path to a master `.pub` key file. Repeatable.

#### `-M --master-threshold <N>`

Required when master keys are provided.

### Revocation keys (optional)

#### `-r --revocation-key <BASE64_KEY>`

Revocation public key as a base64 string. Repeatable.

#### `--revocation-keys-file <PATH>`

Path to a revocation `.pub` key file. Repeatable.

#### `-R --revocation-threshold <N>`

Required when revocation keys are provided.

### General

#### `-o --output-file <PATH>`

Path for the new signers file. The file must not already exist — the command refuses to overwrite. Parent directories are created automatically.

#### `--json`

Emit output as JSON instead of human-readable text.

## Output

Human-readable (default):

    Signers file created successfully at: "signers.json"
    Artifact signers: 3 (threshold: 2)
    Admin keys: 1 (threshold: 1)
    Master keys: 0 (threshold: none)
    Revocation keys: 0 (threshold: none)

JSON (with `--json`):

    {"output_file":"signers.json","artifact_signers_count":3,"artifact_threshold":2,"admin_keys_count":1,"admin_threshold":1,"master_keys_count":0,"master_threshold":null,"revocation_keys_count":0,"revocation_threshold":null}

## Examples

    # minimal: two artifact signers, threshold of 2
    asfaload-cli new-signers-file \
        --artifact-signers-file alice.pub \
        --artifact-signers-file bob.pub \
        -A 2 \
        -o signers.json

    # with admin and revocation groups
    asfaload-cli new-signers-file \
        --artifact-signers-file alice.pub \
        --artifact-signers-file bob.pub \
        -A 2 \
        --admin-keys-file admin.pub \
        -D 1 \
        --revocation-keys-file revoke.pub \
        -R 1 \
        -o signers.json

    # mix base64 strings and files
    asfaload-cli new-signers-file \
        -a "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8" \
        --artifact-signers-file bob.pub \
        -A 1 \
        -o signers.json

## Exit codes

- `0` — signers file created.
- non-zero — error (output file exists, invalid threshold, missing keys, etc.).
