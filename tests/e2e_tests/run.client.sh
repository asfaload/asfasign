#!/bin/bash
set -euo pipefail

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"

# --- Pre-checks ---

. "$SCRIPT_DIR/private/env"

printf '%sChecking backend availability at %s...%s ' "$DIM" "$backend" "$RESET"
if ! curl "$backend" --silent > /dev/null 2>&1; then
    printf '%s✗%s\n' "$RED" "$RESET"
    printf '%sRest backend at %s not available.%s\n' "$RED" "$backend" "$RESET"
    printf 'Start the rest-api with: tests/e2e_tests/run.sh\n'
    exit 1
fi
printf '%s✓%s\n\n' "$GREEN" "$RESET"

base_dir="$(git rev-parse --show-toplevel)"
cd "$base_dir/client-cli/"

################################################################################
section "Initial Setup and Repo Registration"
################################################################################

run_step "Register repo with key1" \
    cargo run --quiet -- register-repo --secret-key "$SCRIPT_DIR/private/key1" -u $backend --password secret $signers_file

################################################################################
section "Signers File Activation"
################################################################################

run_step "List pending for key1 (none expected, key1 submitted)" \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key1" -u http://localhost:3000 --password secret

run_step "List pending for key2" \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key2" -u http://localhost:3000 --password secret

run_step "Sign signers file with key2" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" --password secret $pending_signers_file

run_step "Sign signers file with key3 (completes signature)" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key3" --password secret $pending_signers_file

expect_fail "Sign signers file with key1 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key1" --password secret $pending_signers_file

################################################################################
section "Release Registration and Signing"
################################################################################

run_step "Register release with key3 (does not sign it)" \
    cargo run --quiet -- register-release --secret-key "$SCRIPT_DIR/private/key3" --password secret $release_url

run_step "List pending for key3" \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key3" -u http://localhost:3000 --password secret

run_step "Sign release index with key1" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key1" --password secret $release_index

run_step "Sign release index with key2 (completes, threshold=2)" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" --password secret $release_index

expect_fail "Sign release index with key3 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key3" --password secret $release_index

run_step "Download release artifact (v0.6.0)" \
    cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
section "Updating Signers File"
################################################################################

run_step "Update signers file with key1" \
    cargo run -- update-signers --secret-key "$SCRIPT_DIR/private/key1" -p secret https://github.com/asfaload/asfald/blob/signers_file/asfaload_signers_file_update_01.json

run_step "List pending for key1 (none expected, key1 submitted)" \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key1" -u http://localhost:3000 --password secret

run_step "List pending for key2 (should show pending)" \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key2" -u http://localhost:3000 --password secret

run_step "Sign pending signers with key2" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" --password secret $pending_signers_file

run_step "Sign pending signers with key4 (activates new signers file)" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key4" --password secret $pending_signers_file

run_step "Download artifact (v0.6.0, signed with historical signers)" \
    cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step "Register second release with key3" \
    cargo run --quiet -- register-release --secret-key "$SCRIPT_DIR/private/key3" --password secret $release_url_2

run_step "List pending for key3" \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key3" -u http://localhost:3000 --password secret

run_step "Sign release index with key1" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key1" --password secret $release_index_2

run_step "Sign release index with key2" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" --password secret $release_index_2

run_step "Sign release index with key4 (key3 does not sign)" \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key4" --password secret $release_index_2

run_step "Download artifact (v0.8.0)" \
    cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.8.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
print_summary
