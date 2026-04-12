# Update a signers file

Need to add a signer, remove one, or change the threshold? This guide covers proposing and activating a signers file update.

## Prerequisites

- The repository is already registered and the current signers file is active.
- A new signers file has been created (see [Create a signers file](create-signers-file.md)), committed, and pushed to the forge.
- Your secret key file. See [Generate a key pair](generate-keys.md).

## Steps

### 1. Create and push the new signers file

Generate a new signers file with the updated set of keys and thresholds:

```sh
client new-signers-file \
    --artifact-signer-file alice.pub \
    --artifact-signer-file bob.pub \
    --artifact-signer-file carol.pub \
    --artifact-signer-file dave.pub \
    --artifact-threshold 3 \
    --revocation-key-file revoke1.pub \
    --revocation-key-file revoke2.pub \
    --revocation-key-file revoke3.pub \
    --revocation-threshold 2 \
    --output-file signers_v2.json
```

Commit and push it to your repository so the backend can fetch it by URL.
We advise to commit the file either in your main branch, or in a dedicated branch in which you save all signers files updates.

### 2. Propose the update

```sh
client update-signers \
    --secret-key ~/.asfaload/mykey \
    https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

On success:

```
Signers update proposed successfully!
Project ID: abc123
Required signers (4): alice, bob, carol, dave
Next step: signers must submit signatures to activate the update.
```

### 3. All signers must sign

Just like initial activation, **every** signer listed in the **new** signers file must sign before the update takes effect. This includes both existing and newly added signers.

Each signer runs:

```sh
client list-pending --secret-key ~/.asfaload/mykey
client sign-pending --secret-key ~/.asfaload/mykey \
    https/github.com/443/acme/tool/asfaload.signers.pending/index.json
```

See [Activate a signers file](activate-signers-file.md) for the full signing flow.

## What about existing releases?

Releases signed under the **previous** signers file remain valid. The backend keeps a signers chain history, so older releases can still be verified against the signers file that was active when they were signed.

## Reference

- [`client new-signers-file`](../manual/new-signers-file.md)
- [`client update-signers`](../manual/update-signers.md)
