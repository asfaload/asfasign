#!/bin/bash

set -euxo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/helpers.sh"

# Array of files to delete after running
to_delete_on_filesystem=()
cleanup() {
    for path in "${to_delete_on_filesystem[@]}"; do
        if [[ -e "$path" ]]; then
            rm -rf "$path"
        fi
    done
}
trap cleanup EXIT

# Setup new git repo at each run
GIT_REPO_PATH=$(mktemp -d)
to_delete_on_filesystem+=("$GIT_REPO_PATH")
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
build_rest_api

echo "Build successful!"

base_dir=$(git rev-parse --show-toplevel)


# Set the environment variables and start the server
export ASFALOAD_GIT_REPO_PATH="$GIT_REPO_PATH"
export ASFALOAD_SERVER_PORT="${ASFALOAD_SERVER_PORT:-3000}"
echo "Starting REST API server on port $ASFALOAD_SERVER_PORT with git repository at: $GIT_REPO_PATH"

set -x
# Start the server. The helper build_rest_api builds the debug version.
"${base_dir}/target/debug/rest-api" | tee $GIT_REPO_PATH/server.log
