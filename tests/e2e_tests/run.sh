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

You can test the project registration with

curl -X POST http://localhost:3000/register_repo \
  -H "Content-Type: application/json" \
  -d '{"signers_file_url" : "https://raw.githubusercontent.com/asfaload/asfald/refs/heads/signers_file/asfaload_signers_file.json"}'

curl -X POST http://localhost:3000/register_repo \
  -H "Content-Type: application/json" \
  -d '{"signers_file_url" : "https://gitlab.com/myowndb/myowndb/-/blob/signers_file/asfaload_signers_file.json?ref_type=heads"}'

Get debug logs by setting ASFASIGN_LOG_LEVEL=debug
The git repo is at $GIT_REPO_PATH
Logs are also sent to the file $GIT_REPO_PATH/server.log
********************************************************************************


EOF

base_dir=$(git rev-parse --show-toplevel)
# Start the server using the release binary
"${base_dir}/target/release/rest-api" | tee $GIT_REPO_PATH/server.log
