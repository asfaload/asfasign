#!/bin/bash

set -euxo pipefail

echo "using git repo path: ${1?provide path to git repo}"

# Check if a git directory path was provided
if [ -z "$1" ]; then
  echo "Error: No git directory path provided a first argument."
  echo "Usage: $0 /path/to/git/repository"
  exit 1
fi

GIT_REPO_PATH="${1}"

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

# Set the environment variable and start the server
export ASFASIGN_GIT_REPO_PATH="$GIT_REPO_PATH"
echo "Starting REST API server with git repository at: $GIT_REPO_PATH"

cat <<EOF


********************************************************************************
After the server is started, you can created a file in its git repo with

curl -X POST http://localhost:3000/add-file   -H "Content-Type: application/json"   -d '{
    "file_path": "example.txt",
    "content": "This is a test file edited via the REST API"
  }'
********************************************************************************


EOF

base_dir=$(git rev-parse --show-toplevel)
# Start the server using the release binary
"${base_dir}/target/release/rest-api"
