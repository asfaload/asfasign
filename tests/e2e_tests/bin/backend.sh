#!/bin/bash

set -euxo pipefail

# Setup new git repo at each run
GIT_REPO_PATH=$(mktemp -d)
( cd "$GIT_REPO_PATH"; git init;  )

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

# Set the environment variables and start the server
export ASFASIGN_GIT_REPO_PATH="$GIT_REPO_PATH"
export ASFASIGN_SERVER_PORT="${ASFASIGN_SERVER_PORT:-3000}"
echo "Starting REST API server on port $ASFASIGN_SERVER_PORT with git repository at: $GIT_REPO_PATH"

set -x
base_dir=$(git rev-parse --show-toplevel)
# Start the server using the release binary
"${base_dir}/target/release/rest-api" | tee $GIT_REPO_PATH/server.log
