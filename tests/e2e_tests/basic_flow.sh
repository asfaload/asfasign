#!/bin/bash
set -euo pipefail


# run with env var debug=1 to print commands and outputs.
# If you start the backend separately, send the backend env var the the backedn url,
# eg http://localhost:3000
#
#
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

# --- Cleanup trap ---

SERVER_PID=""
E2E_GIT_REPO_PATH=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    if [[ -n "$E2E_GIT_REPO_PATH" ]] && [[ -d "$E2E_GIT_REPO_PATH" ]]; then
        rm -rf "$E2E_GIT_REPO_PATH"
    fi
}
trap cleanup EXIT

# --- Detect or start backend ---

. "$SCRIPT_DIR/private/env"

base_dir="$(git rev-parse --show-toplevel)"

if [[ -n "${backend:-}" ]] && curl "$backend" --silent > /dev/null 2>&1; then
    printf '%sUsing existing backend at %s%s\n\n' "$DIM" "$backend" "$RESET"
else
    # No running backend — start one automatically
    port="${ASFASIGN_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
    export ASFASIGN_SERVER_PORT="$port"
    backend="http://localhost:$port"

    E2E_GIT_REPO_PATH=$(mktemp -d)
    git init "$E2E_GIT_REPO_PATH" --quiet
    export ASFASIGN_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

    cargo build -p rest-api --quiet
    "${base_dir}/target/debug/rest-api" > $E2E_GIT_REPO_PATH/server.log &
    if [[ -n $debug ]]; then
        tail -f  $E2E_GIT_REPO_PATH/server.log &
    fi

    SERVER_PID=$!

    printf '%sWaiting for backend at %s...%s ' "$DIM" "$backend" "$RESET"
    for i in $(seq 1 30); do
        if curl "$backend" --silent > /dev/null 2>&1; then
            printf '%s✓%s\n\n' "$GREEN" "$RESET"
            break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            printf '%s✗%s\n' "$RED" "$RESET"
            printf '%sBackend process died unexpectedly.%s\n' "$RED" "$RESET"
            exit 1
        fi
        sleep 0.5
    done

    # Final check if the loop exhausted without connecting
    if ! curl "$backend" --silent > /dev/null 2>&1; then
        printf '%s✗%s\n' "$RED" "$RESET"
        printf '%sBackend at %s did not become ready in 15s.%s\n' "$RED" "$backend" "$RESET"
        exit 1
    fi
fi

cd "$base_dir/client-cli/"

################################################################################
section "Initial Setup and Repo Registration"
################################################################################

run_step_json "Register repo with key1" \
    '.success == true' \
    cargo run --quiet -- register-repo --secret-key "$SCRIPT_DIR/private/key1" -u $backend --password secret $signers_file

################################################################################
section "Signers File Activation"
################################################################################

run_step_json "List pending for key1 (none expected, key1 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key1" -u "$backend" --password secret

run_step_json "List pending for key2" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key2" -u "$backend" --password secret

run_step_json "Sign signers file with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" -u "$backend" --password secret $pending_signers_file

run_step_json "Sign signers file with key3 (completes signature)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key3" -u "$backend" --password secret $pending_signers_file

expect_fail_json "Sign signers file with key1 (already completed)" \
    '.error | length > 0' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key1" -u "$backend" --password secret $pending_signers_file

################################################################################
section "Release Registration and Signing"
################################################################################

run_step_json "Register release with key3 (does not sign it)" \
    '.success == true' \
    cargo run --quiet -- register-release --secret-key "$SCRIPT_DIR/private/key3" -u "$backend" --password secret $release_url

run_step_json "List pending for key3" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key3" -u "$backend" --password secret

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key1" -u "$backend" --password secret $release_index

run_step_json "Sign release index with key2 (completes, threshold=2)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" -u "$backend" --password secret $release_index

expect_fail_json "Sign release index with key3 (already completed)" \
    '.error | length > 0' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key3" -u "$backend" --password secret $release_index

run_step "Download release artifact (v0.6.0)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
section "Updating Signers File"
################################################################################

run_step_json "Update signers file with key1" \
    '.success == true' \
    cargo run -- update-signers --secret-key "$SCRIPT_DIR/private/key1" -u "$backend" -p secret https://github.com/asfaload/asfald/blob/signers_file/asfaload_signers_file_update_01.json

run_step_json "List pending for key1 (none expected, key1 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key1" -u "$backend" --password secret

run_step_json "List pending for key2 (should show pending)" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key2" -u "$backend" --password secret

run_step_json "Sign pending signers with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" -u "$backend" --password secret $pending_signers_file

run_step_json "Sign pending signers with key4 (activates new signers file)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key4" -u "$backend" --password secret $pending_signers_file

run_step "Download artifact (v0.6.0, signed with historical signers)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step_json "Register second release with key3" \
    '.success == true' \
    cargo run --quiet -- register-release --secret-key "$SCRIPT_DIR/private/key3" -u "$backend" --password secret $release_url_2

run_step_json "List pending for key3" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$SCRIPT_DIR/private/key3" -u "$backend" --password secret

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key1" -u "$backend" --password secret $release_index_2

run_step_json "Sign release index with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key2" -u "$backend" --password secret $release_index_2

run_step_json "Sign release index with key4 (key3 does not sign)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$SCRIPT_DIR/private/key4" -u "$backend" --password secret $release_index_2

run_step "Download artifact (v0.8.0)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" https://github.com/asfaload/asfald/releases/download/v0.8.0/asfald-x86_64-unknown-linux-musl.tar.gz


run_step "Revoke artifact (v0.6.0)" \
    cargo run -- revoke --secret-key "$SCRIPT_DIR/private/key4" -p secret -u "$backend" github.com/asfaload/asfald/releases/tag/v0.6.0/asfaload.index.json

expect_fail "Download artifact (v0.6.0, revoked)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
print_summary
