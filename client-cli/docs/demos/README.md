# CLI how-to demos

VHS recordings of the [`asfaload-cli` how-tos](../howto/).

## Run

From the repo root:

```sh
make demos
```

This builds the required binaries, starts a local rest-api and file-server in the background, plays each `.tape` in order, and writes GIFs to `howto/out/` (gitignored).

Sources are the `.tape` files under `howto/`.
