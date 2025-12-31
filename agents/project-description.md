# PROJECT DESCRIPTION

This is the code of Asfasign, a multi-party file signature solution which aims to be simple to use and self-hostable.
This is a rust project, which has its code covered by unit tests and integration tests.


The directory `core/` contains the crates providing the core features on which we build the project.
Those features are made available by the features_lib crate. Code outside core should only depend on features_lib and
never use other crates directly.

`client-cli` is a command line tool providing the client side operations: keypairs generation, signers files generation, file signature, signature verification, etc...

`rest-api` is the server component. The server side is accountless: it doesn't require a registration step. Users are only identified by their public key.
The data managed by the backend is stored in a git repository. To serialise all git operations, an actor based approach is implemented: the actor in  `git_actor.rs` is the only actor that may apply git operations.
