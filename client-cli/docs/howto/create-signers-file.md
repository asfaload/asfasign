# Create a signers file

A signers file defines who can sign artifacts for your project, and how many signatures are needed (the threshold). You create it once, commit it to your repository, then register it with the backend.

## Prerequisites

- Public key files (`.pub`) for every signer. See [Generate a key pair](generate-keys.md).
- A target repository where the signers file will live.

## Steps

### 1. Collect the public keys

Gather `.pub` files from all signers. For this example, three artifact signers with a threshold of 2 (any two out of three must sign):

```
alice.pub
bob.pub
carol.pub
```

### 2. Create the signers file

```sh
client new-signers-file \
    --artifact-signer-file alice.pub \
    --artifact-signer-file bob.pub \
    --artifact-signer-file carol.pub \
    --artifact-threshold 2 \
    --output-file signers.json
```

The command prints a summary:

```
Signers file created successfully at: "signers.json"
Artifact signers: 3 (threshold: 2)
Admin keys: 0 (threshold: none)
Master keys: 0 (threshold: none)
```

### 3. Commit and push

Place the signers file in your repository and push it.
We advise to commit the file in your main branch (eg under a directory `.asfaload.signers`) or in a dedicated branch of the repo.
You can choose any naming convention that suits you, as long as the file stays
available at the URL, so that downloaders can confirm its validity.
You could choose to place it in your main branch:

```
https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

or in a dedicated branch (in this example `signers`):
```
https://github.com/acme/tool/blob/signers/20260413_signers.json
```
If you publish an updated signers file, you must make it available at distinct
URL. In other words, you must add a new file to your repo, and you must not
edit an existing signers file.


The backend needs to fetch it by URL during [repository registration](register-repo.md).

A common location is at the root of your repo:

```sh
cp signers.json my-project/asfaload.signers/index.json
cd my-project
git add asfaload.signers/index.json
git commit -m "Add asfaload signers file"
git push
```

## Adding optional key groups

Beyond artifact signers, you can define admin, master, and revocation key groups. Each group has its own keys and threshold.

### With revocation keys

Revocation keys can revoke signed releases. Useful to have a separate set of keys for emergency access:

```sh
client new-signers-file \
    --artifact-signer-file alice.pub \
    --artifact-signer-file bob.pub \
    --artifact-signer-file carol.pub \
    --artifact-threshold 2 \
    --revocation-key-file revoke1.pub \
    --revocation-key-file revoke2.pub \
    --revocation-key-file revoke3.pub \
    --revocation-threshold 2 \
    --output-file signers.json
```

### With admin keys

Admin keys can propose signers file updates:

```sh
client new-signers-file \
    --artifact-signer-file alice.pub \
    --artifact-signer-file bob.pub \
    --artifact-threshold 2 \
    --admin-key-file admin.pub \
    --admin-threshold 1 \
    --output-file signers.json
```

## Mixing base64 strings and files

You can pass public keys as base64 strings instead of files. This is handy when keys come from a secrets manager:

```sh
client new-signers-file \
    --artifact-signer "asfaload-pub:b5S+CxuqICIUn/DGBdMKeTMZCgQcg78ohiWQ1sC00c8" \
    --artifact-signer-file bob.pub \
    --artifact-threshold 1 \
    --output-file signers.json
```

## Next step

[Register the repository](register-repo.md) with the backend so it knows where to find your signers file.

## Reference

- [`client new-signers-file`](../manual/new-signers-file.md)
