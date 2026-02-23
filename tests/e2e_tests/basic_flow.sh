#!/bin/bash
set -euo pipefail


# run with env var debug=1 to print commands and outputs.
# If you start the backend separately, send the backend env var the the backedn url,
# eg http://localhost:3000

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
    rm -f "${DOWNLOAD_V01:-}" "${DOWNLOAD_V01_HISTORICAL:-}" "${DOWNLOAD_V02:-}" "${DOWNLOAD_V01_bis:-}"
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
    git init "$E2E_GIT_REPO_PATH" --quiet
    export ASFALOAD_GIT_REPO_PATH="$E2E_GIT_REPO_PATH"

    cargo build -p rest-api --quiet
    "${base_dir}/target/debug/rest-api" > $E2E_GIT_REPO_PATH/server.log &
    if [[ -n $debug ]]; then
        tail -f  $E2E_GIT_REPO_PATH/server.log &
    fi

    SERVER_PID=$!

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

run_step_json "Register repo with key1" \
    '.success == true' \
    cargo run --quiet -- register-repo --secret-key "$KEY_0" -u $backend --password $key_password $(signers_file 1)

# --- Backend: verify pending signers created ---
assert_pending_signers_exist
assert_pending_signers_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"
assert_last_commit_contains "$PENDING_SIGNERS_DIR/$SIGNERS_FILE"

################################################################################
section "Signers File Activation"
################################################################################

run_step_json "List pending for key1 (none expected, key1 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key1" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Sign signers file with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $(pending_signers_file)

# --- Backend: verify 2nd signature on pending signers ---
assert_pending_signers_signature_count 2
assert_pending_signers_signatures_contain_keys "$KEY_0" "$KEY_1"

run_step_json "Sign signers file with key3 (completes signature)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $(pending_signers_file)

# --- Backend: verify signers activated ---
assert_signers_active
assert_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2"

expect_fail_json "Sign signers file with key1 (already completed)" \
    '.error | length > 0' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $(pending_signers_file)

################################################################################
section "Release Registration and Signing"
################################################################################

run_step_json "Register release with key3 (does not sign it)" \
    '.success == true' \
    cargo run --quiet -- register-release --secret-key "$KEY_2" -u "$backend" --password $key_password $(release_url 0.1)

# --- Backend: verify release index created ---
assert_release_index_exists "0.1"
assert_release_index_pending "0.1"
assert_last_commit_contains "$INDEX_FILE"

run_step_json "List pending for key3" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_2" -u "$backend" --password $key_password

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $(release_index 0.1)

assert_release_index_signature_count "0.1" 1

expect_fail "Register release with key3 (fails as already registered)" \
    cargo run --quiet -- register-release --secret-key "$KEY_2" -u "$backend" --password $key_password $(release_url 0.1)

# Ensure a second release registration does not override the signatures already collected
assert_release_index_signature_count "0.1" 1

run_step_json "Sign release index with key2 (completes, threshold=2)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $(release_index 0.1)

# --- Backend: verify release index activated ---
assert_release_index_active "0.1"
assert_release_index_signers "0.1" "$KEY_0" "$KEY_1" "$KEY_2"

expect_fail_json "Sign release index with key3 (already completed)" \
    '.error | length > 0' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_2" -u "$backend" --password $key_password $(release_index 0.1)

DOWNLOAD_V01="$(mktemp)"
run_step "Download release artifact (v0.1)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01" -u "$backend" $(artifact_url 0.1)

# --- Backend: verify artifact hash ---
assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01"

################################################################################
section "Updating Signers File"
################################################################################

run_step_json "Update signers file with key1" \
    '.success == true' \
    cargo run -- update-signers --secret-key "$KEY_0" -u "$backend" -p $key_password $(signers_file 2)

# --- Backend: verify pending signers updated ---
assert_pending_signers_exist
assert_pending_signers_signature_count 1
assert_pending_signers_signatures_contain_keys "$KEY_0"
assert_pending_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

run_step_json "List pending for key1 (none expected, key1 submitted)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key2 (should show pending)" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_1" -u "$backend" --password $key_password

run_step_json "Sign pending signers with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $(pending_signers_file)

assert_pending_signers_signature_count 2
assert_pending_signers_signatures_contain_keys "$KEY_0" "$KEY_1"

run_step_json "Sign pending signers with key4 (activates new signers file)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $(pending_signers_file)

# --- Backend: verify new signers activated ---
assert_signers_active
assert_signers_contain_keys "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

DOWNLOAD_V01_HISTORICAL="$(mktemp)"
run_step "Download artifact (v0.1, signed with historical signers)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01_HISTORICAL" -u "$backend" $(artifact_url 0.1)

assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01_HISTORICAL"

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step_json "Register second release with key3" \
    '.success == true' \
    cargo run --quiet -- register-release --secret-key "$KEY_2" -u "$backend" --password $key_password $(release_url 0.2)

# --- Backend: verify second release index created ---
assert_release_index_exists "0.2"
assert_release_index_pending "0.2"

run_step_json "List pending for key3" \
    '.file_paths | length > 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_2" -u "$backend" --password $key_password

run_step_json "Sign release index with key1" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_0" -u "$backend" --password $key_password $(release_index 0.2)

assert_release_index_signature_count "0.2" 1

run_step_json "Sign release index with key2" \
    '.is_complete == false' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_1" -u "$backend" --password $key_password $(release_index 0.2)

assert_release_index_signature_count "0.2" 2

run_step_json "Sign release index with key4 (key3 does not sign)" \
    '.is_complete == true' \
    cargo run --quiet -- sign-pending --secret-key "$KEY_3" -u "$backend" --password $key_password $(release_index 0.2)

# --- Backend: verify v0.2 release index activated ---
assert_release_index_active "0.2"
assert_release_index_signers "0.2" "$KEY_0" "$KEY_1" "$KEY_2" "$KEY_3"

DOWNLOAD_V02="$(mktemp)"
run_step "Download artifact (v0.2)" \
    cargo run --quiet -- download -o "$DOWNLOAD_V02" -u "$backend" $(artifact_url 0.2)

assert_artifact_hash_matches "0.2" "artifact.bin" "$DOWNLOAD_V02"

# --- Revoke release 0.1 ---

expect_fail "revoke index file for v0.1, not authorized" \
    cargo run -- revoke --secret-key "$KEY_3" -p $key_password -u "$backend" $(release_index 0.1)

run_step "initiate revoke index file for v0.1" \
    cargo run -- revoke --secret-key "$KEY_4" -p $key_password -u "$backend" $(release_index 0.1)

expect_fail "revoke index file for v0.1 again (already pending)" \
    cargo run -- revoke --secret-key "$KEY_5" -p $key_password -u "$backend" $(release_index 0.1)

DOWNLOAD_V01_bis="$(mktemp)"
run_step "Download artifact (v0.1), not yet revoked as need 2 signatures" \
    cargo run --quiet -- download -o "$DOWNLOAD_V01_bis" -u "$backend" $(artifact_url 0.1)
assert_artifact_hash_matches "0.1" "artifact.bin" "$DOWNLOAD_V01_bis"

run_step_json "List pending for key1 (none expected, key1 cannot revoke)" \
    '.file_paths | length == 0' \
    cargo run --quiet -- list-pending --secret-key "$KEY_0" -u "$backend" --password $key_password

run_step_json "List pending for key5 (one expected, key1 can revoke)" \
    '.file_paths | length == 1' \
    cargo run --quiet -- list-pending --secret-key "$KEY_5" -u "$backend" --password $key_password

run_step "sign pending revocation for v0.1 (second signer via sign-pending)" \
    cargo run -- sign-pending --secret-key "$KEY_5" -p $key_password -u "$backend" "$(release_index 0.1).$REVOCATION_SUFFIX.$PENDING_SUFFIX"

# --- Backend: verify v0.1 revoked ---
assert_release_index_revoked "0.1"
assert_revocation_signers "0.1" "$KEY_4" "$KEY_5" "$KEY_6"
assert_last_commit_contains "$REVOCATION_SUFFIX"

expect_fail "Download artifact (v0.1, revoked)" \
    cargo run --quiet -- download -o "$(mktemp)" -u "$backend" $(artifact_url 0.1)

################################################################################
print_summary
