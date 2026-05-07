# Register a repository

Registering a repository tells the backend where your signers file lives. Once registered, the backend can enforce signature requirements for your project.

## Prerequisites

- A signers file committed and pushed to your repository. See [Create a signers file](create-signers-file.md).
- Your secret key file. See [Generate a key pair](generate-keys.md).
- The backend is running and reachable.

## Steps

### 1. Get the signers file URL

You need the public URL that points to your signers file on the forge. For GitHub, you can simply copy the URL from your browser when displaying the file of your repo.
This will give you an URL of this form:

```
https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

### 2. Register the repository

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

On success:

```
Repository registered successfully!
Project ID: abc123
Required signers (3): alice, bob, carol
Next step: signers must submit signatures to activate the project.
```

The backend fetches the signers file, creates a pending signers entry, and waits for **all** listed signers to sign before the project becomes active.

### 3. Point to a non-default backend

If your backend is not Asfaload's:

```sh
asfaload-cli register-repo \
    --secret-key ~/.asfaload/mykey \
    -u https://my-asfaload-deployment.example.com \
    https://github.com/acme/tool/blob/main/asfaload.signers/index.json
```

## What happens next

After registration, the signers file is in a **pending** state. Every signer listed in it must sign before the project is activated. See [Activate a signers file](activate-signers-file.md).

## Reference

- [`asfaload-cli register-repo`](../manual/register-repo.md)
