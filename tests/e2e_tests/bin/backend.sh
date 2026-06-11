#!/bin/bash

set -euxo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/helpers.sh"


# Setup new git repo at each run
GIT_REPO_PATH=$(mktemp -d)
init_backend_repo "$GIT_REPO_PATH"

echo "using git repo path: ${GIT_REPO_PATH}"


# Check if the provided path is a directory
if [ ! -d "$GIT_REPO_PATH" ]; then
  echo "Error: '$GIT_REPO_PATH' is not a directory."
  exit 1
fi

# Check if the provided path is a git repository
if [ ! -d "$GIT_REPO_PATH/.git" ]; then
  echo "Error: '$GIT_REPO_PATH' is not a git repository."
  exit 1
fi

echo "Building the project..."
# Build the project in release mode
cargo build --release

# Check if build was successful
if [ $? -ne 0 ]; then
  echo "Error: Build failed."
  exit 1
fi

echo "Build successful!"

base_dir=$(git rev-parse --show-toplevel)

# Stage a 0600 copy of the committed signing keypair: ssh-keygen -Y sign (run by
# the server's startup signing-key validation) refuses a private key that is
# group/world readable, and the fixture is checked out with the umask's mode.
SIGNING_KEY_DIR=$(mktemp -d)
install -m600 "${base_dir}/core/test_helpers/fixtures/git_signing_key" "$SIGNING_KEY_DIR/"
install -m644 "${base_dir}/core/test_helpers/fixtures/git_signing_key.pub" "$SIGNING_KEY_DIR/"

# Set the environment variables and start the server
export ASFALOAD_GIT_REPO_PATH="$GIT_REPO_PATH"
export ASFALOAD_SERVER_PORT="${ASFALOAD_SERVER_PORT:-3000}"
export ASFALOAD_GIT_SIGNING_PUB_KEY_PATH="$SIGNING_KEY_DIR/git_signing_key.pub"
echo "Starting REST API server on port $ASFALOAD_SERVER_PORT with git repository at: $GIT_REPO_PATH"

set -x
# Start the server using the release binary
"${base_dir}/target/release/rest-api" | tee $GIT_REPO_PATH/server.log
