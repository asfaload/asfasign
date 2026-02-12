#!/bin/bash -eu

#This is a test script that I use manually to test both client and server.
# In private/, I have 3 key pairs named key1, key2 and key3 as well as an env file with this content:
#  signers_file=https://raw.githubusercontent.com/asfaload/asfald/refs/heads/signers_file/asfaload_signers_file.json
#  repo=github.com/afaload/asfaload
#  pending_signers_file=github.com/asfaload/asfald/asfaload.signers.pending/index.json
#  backend=http://localhost:3000
#  release_url=https://github.com/asfaload/asfald/releases/tag/v0.9.0
#  release_index=github.com/asfaload/asfald/releases/tag/v0.9.0/asfaload.index.json
#
# This lets me validate github repo registration, signers file activation, pending sigs listing, release registration,
# index file signing, download of a release artifact.
# You can use it with your own information, but you need to:
# * generate 3 keypairs in private/ named as mentioned above
# * commit a signers file in your repo
# * have a release available for that repo
# * create the env file with correct values under private/
#

. private/env

if ! curl $backend --silent > /dev/null; then
  echo "Rest backend at $backend not available. You need to start the rest-api with rest-api/run.sh"
  exit 1
fi

## client-cli
#To be run from inside client-cli/
cd ../client-cli/

### Register asfald
echo "## Registering repo"
cargo run --quiet -- register-repo --secret-key ../rest-api/private/key1 -u $backend --password secret $signers_file

### list pending signatures
echo "## Listing pending sigs for key1, should be none as submitted"
cargo run --quiet -- list-pending --secret-key ../rest-api/private/key1 -u http://localhost:3000 --password secret
echo "## Listing pending sigs for key2"
cargo run --quiet -- list-pending --secret-key ../rest-api/private/key2 -u http://localhost:3000 --password secret
### sign
echo "## Signing signers file"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key2 --password secret $pending_signers_file
echo "This should complete the signature"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key3 --password secret $pending_signers_file

echo "error if key1 signs again as it transitioned to complete and was renamed"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key1 --password secret $pending_signers_file || true

#After signing, we can add a release.

### Add a release

echo "## Registering release with key3. Note this does not sign it!"
cargo run --quiet -- register-release  --secret-key ../rest-api/private/key3 --password secret $release_url
### list pending signatures
echo "## Listing pending sigs for key3"
cargo run --quiet -- list-pending --secret-key ../rest-api/private/key3 -u http://localhost:3000 --password secret

### Sign index file
echo "## Signing index file"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key1 --password secret $release_index
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key2 --password secret $release_index
echo "threshold was 2, so previous signature completed the process"
echo "key 3 can thus not sign it anymore"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key3 --password secret $release_index || true

## Download a file
echo "Downloading release artifact"
cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
# Updating signers file
################################################################################

echo "Update signers file with key1"
cargo run -- update-signers --secret-key ../rest-api/private/key1 -p secret https://github.com/asfaload/asfald/blob/signers_file/asfaload_signers_file_update_01.json

echo "should be none as key1 submitted"
cargo run --quiet -- list-pending --secret-key ../rest-api/private/key1 -u http://localhost:3000 --password secret
echo "should show pending for key2"
cargo run --quiet -- list-pending --secret-key ../rest-api/private/key2 -u http://localhost:3000 --password secret


echo "signing with key2:"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key2 --password secret $pending_signers_file
echo "this should activate the new signers file"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key4 --password secret $pending_signers_file

echo "Downloading release artifact signed with signers file in history"
cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
# Registering a release with new signers file
################################################################################

echo "## Registering other release with key3"
cargo run --quiet -- register-release  --secret-key ../rest-api/private/key3 --password secret $release_url_2

### list pending signatures
echo "## Listing pending sigs for key1"
cargo run --quiet -- list-pending --secret-key ../rest-api/private/key3 -u http://localhost:3000 --password secret

### Sign index file
echo "## Signing index file with keys 1,2,4. So key 3 does not sign"
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key1 --password secret $release_index_2
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key2 --password secret $release_index_2
cargo run --quiet -- sign-pending  --secret-key ../rest-api/private/key4 --password secret $release_index_2

echo "Downloading artifact"
cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.8.0/asfald-x86_64-unknown-linux-musl.tar.gz

cat <<EOF
####################
      SUCCESS
####################
EOF
