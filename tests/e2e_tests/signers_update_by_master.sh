#!/bin/bash
set -euo pipefail

# run with env var debug=1 to print commands and outputs.
# If you start the backend separately, send the backend env var the the backend url,
# eg http://localhost:3000

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"

# --- URL for the update signers file (non-standard name) ---
SIGNERS_UPDATE_URL="https://github.com/${E2E_REPO}/blob/master/${TEST_NAME}/signers_file_update_with_new_masters.json"

# --- Cleanup trap ---

SERVER_PID=""
E2E_GIT_REPO_PATH=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$E2E_GIT_REPO_PATH" ]] && [[ -d "$E2E_GIT_REPO_PATH" ]]; then
        rm -rf "$E2E_GIT_REPO_PATH"
    fi
}
trap cleanup EXIT

# --- Detect or start backend ---

base_dir="$(git rev-parse --show-toplevel)"

if [[ -n "${backend:-}" ]] && curl "$backend" --silent > /dev/null 2>&1; then
    printf '%sUsing existing backend at %s%s\n\n' "$DIM" "$backend" "$RESET"
else
    # No running backend — start one automatically
    port="${ASFALOAD_SERVER_PORT:-$((3000 + RANDOM % 1000))}"
    export ASFALOAD_SERVER_PORT="$port"
    backend="http://localhost:$port"

    E2E_GIT_REPO_PATH=$(mktemp -d)
    init_backend_repo "$E2E_GIT_REPO_PATH"
    export ASFALOAD_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

    build_rest_api
    "${base_dir}/target/debug/rest-api" > $E2E_GIT_REPO_PATH/server.log &
    SERVER_PID=$!

    if [[ -n $debug ]]; then
        tail -f  $E2E_GIT_REPO_PATH/server.log &
    fi


    printf '%sWaiting for backend at %s with repo %s ...%s ' "$DIM" "$backend" "$ASFALOAD_GIT_REPO_PATH" "$RESET"
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

run_step_json "Register repo with key0" \
    '.success == true' \
    cargo run --quiet -- register-repo --secret-key "$KEY_0" -u $backend --password $key_password $(signers_file 1)

# --- Backend: verify pending signers created ---
assert_pending_signers_exist
assert_pending_signers_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"
assert_pending_signers_contain_master_keys "$KEY_3" "$KEY_4"
assert_last_commit_contains "$PENDING_SIGNERS_DIR/$SIGNERS_FILE"

################################################################################
section "Initial Signers File Activation"
################################################################################

run_step_json "List pending for key0 (none expected, key0 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key1" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Sign signers file with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 2
assert_pending_signers_signatures_contain_keys "$KEY_0" "$KEY_1"

run_step_json "Sign signers file with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 3

run_step_json "Sign signers file with key3 (master key)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 4

run_step_json "Sign signers file with key4 (master key, completes activation)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_4" -u "$backend" --password $key_password $(pending_signers_file)

# --- Backend: verify signers activated ---
assert_signers_active
assert_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"
assert_signers_contain_master_keys "$KEY_3" "$KEY_4"
assert_signers_history_entries 0

################################################################################
section "Signers Update by Master Key"
################################################################################

expect_fail "Update signers with key5 (not authorized, not in current admin/master)" \
    cargo run -- update-signers --secret-key "$KEY_5" -u "$backend" -p $key_password $(signers_file "update_with_new_masters")

run_step_json "Update signers with key3 (master key)" \
    '.success == true' \
    cargo run -- update-signers --secret-key "$KEY_3" -u "$backend" -p $key_password $(signers_file "update_with_new_masters")

# --- Backend: verify pending signers updated ---
assert_pending_signers_exist
assert_pending_signers_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_3"
assert_pending_signers_contain_keys "$KEY_5" "$KEY_6" "$KEY_7"
assert_pending_signers_contain_master_keys "$KEY_8" "$KEY_9"

run_step_json "List pending for key3 (none expected, key3 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_3" -u "$backend" --password $key_password

run_step_json "List pending for key5 (should show pending)" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_5" -u "$backend" --password $key_password

################################################################################
section "Signature Collection for Update Activation"
################################################################################

run_step_json "Sign pending with key5 (new artifact signer)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_5" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 2

run_step_json "Sign pending with key6 (new artifact signer)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_6" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 3

run_step_json "Sign pending with key7 (new artifact signer)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_7" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 4

run_step_json "Sign pending with key8 (new master key)" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_8" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 5

run_step_json "Sign pending with key9 (new master key, completes update)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_9" -u "$backend" --password $key_password $(pending_signers_file)

# --- Backend: verify new signers activated ---
assert_signers_active
assert_signers_contain_keys "$KEY_5" "$KEY_6" "$KEY_7"
assert_signers_contain_master_keys "$KEY_8" "$KEY_9"
assert_signers_history_entries 1

################################################################################
print_summary
