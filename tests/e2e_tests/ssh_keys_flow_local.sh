#!/bin/bash
set -euo pipefail

# E2E test for OpenSSH ed25519 key support through the CLI.
#
# Uses real SSH ed25519 keys (generated with ssh-keygen at runtime) as
# artifact signers. This exercises the import-only OpenSsh key format
# end-to-end through the admin + client CLI.

# helpers.sh's urls.sh branch requires KEY_TYPE to be minisign|asfaload.
# This test uses neither shared fixture set — it generates its own keys —
# but we still source helpers.sh for run_step / section / color output,
# so we pin a valid value to satisfy the check.
export KEY_TYPE="${KEY_TYPE:-asfaload}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/helpers.sh"

# --- Cleanup trap ---

SSH_KEYS_DIR=""
WORK_DIR=""

cleanup() {
    if [[ -n "$SSH_KEYS_DIR" ]] && [[ -d "$SSH_KEYS_DIR" ]]; then
        rm -rf "$SSH_KEYS_DIR"
    fi
    if [[ -n "$WORK_DIR" ]] && [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

base_dir="$(git rev-parse --show-toplevel)"

if ! command -v ssh-keygen &> /dev/null; then
    printf '%sssh-keygen is required but not installed.%s\n' "$RED" "$RESET"
    exit 1
fi

################################################################################
section "Generate SSH ed25519 keys"
################################################################################

SSH_KEYS_DIR=$(mktemp -d)
SSH_KEY_1="$SSH_KEYS_DIR/id_ed25519_1"
SSH_KEY_2="$SSH_KEYS_DIR/id_ed25519_2"

run_step "Generate SSH ed25519 key 1 (passphrase-protected)" \
    ssh-keygen -t ed25519 -N "$key_password" -C "ssh-e2e-key-1" -f "$SSH_KEY_1" -q

run_step "Generate SSH ed25519 key 2 (passphrase-protected)" \
    ssh-keygen -t ed25519 -N "$key_password" -C "ssh-e2e-key-2" -f "$SSH_KEY_2" -q

# Sanity check: each key has a matching .pub sibling.
run_step "SSH key 1 has secret and public files" \
    bash -c "[[ -f '$SSH_KEY_1' ]] && [[ -f '$SSH_KEY_1.pub' ]]"
run_step "SSH key 2 has secret and public files" \
    bash -c "[[ -f '$SSH_KEY_2' ]] && [[ -f '$SSH_KEY_2.pub' ]]"

################################################################################
section "Create signers file with 2 SSH artifact signers"
################################################################################

WORK_DIR=$(mktemp -d)
SIGNERS_FILE_OUT="$WORK_DIR/signers_file_ssh.json"

run_step "Create signers file with 2 SSH ed25519 artifact signers (threshold 2)" \
    cargo run --quiet --manifest-path "$base_dir/client-cli/Cargo.toml" -- new-signers-file \
        --artifact-signer-file "$SSH_KEY_1.pub" \
        --artifact-signer-file "$SSH_KEY_2.pub" \
        -A 2 \
        -o "$SIGNERS_FILE_OUT"

run_step "Signers file exists" \
    bash -c "[[ -f '$SIGNERS_FILE_OUT' ]]"

run_step "Signers file is valid JSON" \
    jq empty "$SIGNERS_FILE_OUT"

run_step "Signers file records a single artifact-signer group" \
    bash -c "jq -e '.artifact_signers | length == 1' '$SIGNERS_FILE_OUT' > /dev/null"

run_step "Artifact-signer group has threshold of 2" \
    bash -c "jq -e '.artifact_signers[0].threshold == 2' '$SIGNERS_FILE_OUT' > /dev/null"

run_step "Artifact-signer group contains 2 keys" \
    bash -c "jq -e '.artifact_signers[0].signers | length == 2' '$SIGNERS_FILE_OUT' > /dev/null"

run_step "Artifact-signer keys are stored as ed25519 (asfaload-pub: prefix)" \
    bash -c "jq -e '[.artifact_signers[0].signers[].data.pubkey | startswith(\"asfaload-pub:\")] | all' '$SIGNERS_FILE_OUT' > /dev/null"

################################################################################
print_summary
