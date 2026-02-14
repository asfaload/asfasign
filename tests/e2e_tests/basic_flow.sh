#!/bin/bash
set -euo pipefail


# run with env var debug=1 to print commands and outputs.
# If you start the backend separately, send the backend env var the the backedn url,
# eg http://localhost:3000
#
#
#This is a test script that I use manually to test both client and server.
# In private/, I have an env file with this content:
#  signers_file=https://raw.githubusercontent.com/asfaload/asfald/refs/heads/signers_file/asfaload_signers_file.json
#  repo=github.com/afaload/asfaload
#  pending_signers_file=github.com/asfaload/asfald/asfaload.signers.pending/index.json
#  backend=http://localhost:3000
#  release_url=https://github.com/asfaload/asfald/releases/tag/v0.6.0
#  release_index=github.com/asfaload/asfald/releases/tag/v0.6.0/asfaload.index.json
#
# Keys are sourced from core/test_helpers/fixtures/keys/ (committed to repo).
# Variables KEY_0 through KEY_3 are defined in lib/helpers.sh.
# You can use it with your own information, but you need to:
# * ensure your signers file references the fixture public keys (key_0.pub through key_3.pub)
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
    port="${ASFALOAD_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
    export ASFALOAD_SERVER_PORT="$port"
    backend="http://localhost:$port"

    E2E_GIT_REPO_PATH=$(mktemp -d)
    git init "$E2E_GIT_REPO_PATH" --quiet
    export ASFALOAD_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

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
    cargo run --quiet -- register-repo --secret-key "$KEY_0" -u $backend --password $key_password $signers_file

################################################################################
section "Signers File Activation"
################################################################################

run_step_json "List pending for key1 (none expected, key1 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key2" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Sign signers file with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $pending_signers_file

run_step_json "Sign signers file with key3 (completes signature)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $pending_signers_file

expect_fail_json "Sign signers file with key1 (already completed)" \
    '.error | length > 0' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $pending_signers_file

################################################################################
section "Release Registration and Signing"
################################################################################

run_step_json "Register release with key3 (does not sign it)" \
    '.success == true' \
    cargo run --quiet -- register-release --secret-key "$KEY_2" -u "$backend" --password $key_password $release_url

run_step_json "List pending for key3" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_2" -u "$backend" --password $key_password

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $release_index

run_step_json "Sign release index with key2 (completes, threshold=2)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $release_index

expect_fail_json "Sign release index with key3 (already completed)" \
    '.error | length > 0' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $release_index

run_step "Download release artifact (v0.1)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" $artifact_for_release_0_1

################################################################################
section "Updating Signers File"
################################################################################

run_step_json "Update signers file with key1" \
    '.success == true' \
    cargo run -- update-signers --secret-key "$KEY_0" -u "$backend" -p $key_password $signers_file_2

run_step_json "List pending for key1 (none expected, key1 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key2 (should show pending)" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Sign pending signers with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $pending_signers_file

run_step_json "Sign pending signers with key4 (activates new signers file)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $pending_signers_file

run_step "Download artifact (v0.1, signed with historical signers)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" $artifact_for_release_0_1

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step_json "Register second release with key3" \
    '.success == true' \
    cargo run --quiet -- register-release --secret-key "$KEY_2" -u "$backend" --password $key_password $release_url_2

run_step_json "List pending for key3" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_2" -u "$backend" --password $key_password

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $release_index_2

run_step_json "Sign release index with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $release_index_2

run_step_json "Sign release index with key4 (key3 does not sign)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $release_index_2

run_step "Download artifact (v0.2)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" $artifact_for_release_0_2


run_step "Revoke index file for v0.1" \
    cargo run -- revoke --secret-key "$KEY_3" -p $key_password -u "$backend" $release_index

expect_fail "Download artifact (v0.1, revoked)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" $artifact_for_release_0_1

################################################################################
print_summary
