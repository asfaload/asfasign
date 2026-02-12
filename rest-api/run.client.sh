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

# --- Terminal color support ---
if [ -t 1 ]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    RESET=$'\033[0m'
else
    BOLD='' DIM='' RED='' GREEN='' YELLOW='' BLUE='' RESET=''
fi

# --- Global state ---
STEP_NUM=0
PASS_COUNT=0
EXPECTED_FAIL_COUNT=0
SCRIPT_START=$(date +%s)
CURRENT_SECTION="setup"

# --- ERR trap for unguarded failures ---
on_error() {
    local line="$1" cmd="$2"
    printf '\n%s%s══ UNEXPECTED ERROR ══════════════════════════════════════════%s\n' \
        "$BOLD" "$RED" "$RESET"
    printf '  %sLine:%s    %d\n' "$RED" "$RESET" "$line"
    printf '  %sCommand:%s %s\n' "$RED" "$RESET" "$cmd"
    printf '  %sSection:%s %s\n' "$RED" "$RESET" "${CURRENT_SECTION}"
    exit 1
}
trap 'on_error $LINENO "$BASH_COMMAND"' ERR

# --- Helper functions ---

section() {
    local title="$1"
    CURRENT_SECTION="$title"
    printf '\n%s%s══════════════════════════════════════════════════════════════%s\n' \
        "$BOLD" "$BLUE" "$RESET"
    printf '%s%s  %s%s\n' "$BOLD" "$BLUE" "$title" "$RESET"
    printf '%s%s══════════════════════════════════════════════════════════════%s\n\n' \
        "$BOLD" "$BLUE" "$RESET"
}

run_step() {
    local desc="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s... ' "$DIM" "$STEP_NUM" "$RESET" "$desc"

    if [[ -n $debug ]]; then
        echo
        echo "$@";
    fi

    local step_start output exit_code=0
    step_start=$(date +%s)

    output=$("$@" 2>&1) || exit_code=$?

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [ "$exit_code" -eq 0 ]; then
        printf '%s✓%s %s(%ds)%s\n' "$GREEN" "$RESET" "$DIM" "$elapsed" "$RESET"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf '%s✗ FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s\n' "$RED" "$RESET" "$*"
        printf '  %sExit code:%s %d\n' "$RED" "$RESET" "$exit_code"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        if [ -n "$output" ]; then
            printf '  %sOutput:%s\n%s\n' "$RED" "$RESET" "$output"
        fi
        exit 1
    fi
}

expect_fail() {
    local desc="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s %s(expect fail)%s... ' \
        "$DIM" "$STEP_NUM" "$RESET" "$desc" "$YELLOW" "$RESET"

    if [[ -n $debug ]]; then
        echo
        echo "$@";
    fi

    local step_start output exit_code=0
    step_start=$(date +%s)

    output=$("$@" 2>&1) || exit_code=$?

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [ "$exit_code" -ne 0 ]; then
        printf '%s⚠ expected failure%s %s(%ds)%s\n' "$YELLOW" "$RESET" "$DIM" "$elapsed" "$RESET"
        EXPECTED_FAIL_COUNT=$((EXPECTED_FAIL_COUNT + 1))
    else
        printf '%s✗ UNEXPECTED SUCCESS%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand was expected to fail but succeeded:%s %s\n' "$RED" "$RESET" "$*"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        if [ -n "$output" ]; then
            printf '  %sOutput:%s\n%s\n' "$RED" "$RESET" "$output"
        fi
        exit 1
    fi
}

print_summary() {
    local script_end total_elapsed
    script_end=$(date +%s)
    total_elapsed=$((script_end - SCRIPT_START))
    local total_steps=$((PASS_COUNT + EXPECTED_FAIL_COUNT))
    local minutes=$((total_elapsed / 60))
    local seconds=$((total_elapsed % 60))

    printf '\n'
    printf '%s%s╔══════════════════════════════════════════════════╗%s\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║            ALL TESTS PASSED                      ║%s\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s%s╠══════════════════════════════════════════════════╣%s\n' "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Steps passed:            %-23d%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "$PASS_COUNT" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Expected failures:       %-23d%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "$EXPECTED_FAIL_COUNT" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Total steps:             %-23d%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "$total_steps" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s║%s  Total time:              %-23s%s%s║%s\n' \
        "$BOLD" "$GREEN" "$RESET" "${minutes}m ${seconds}s" "$BOLD" "$GREEN" "$RESET"
    printf '%s%s╚══════════════════════════════════════════════════╝%s\n' "$BOLD" "$GREEN" "$RESET"
}

# --- Pre-checks ---

. private/env

printf '%sChecking backend availability at %s...%s ' "$DIM" "$backend" "$RESET"
if ! curl "$backend" --silent > /dev/null 2>&1; then
    printf '%s✗%s\n' "$RED" "$RESET"
    printf '%sRest backend at %s not available.%s\n' "$RED" "$backend" "$RESET"
    printf 'Start the rest-api with: rest-api/run.sh\n'
    exit 1
fi
printf '%s✓%s\n\n' "$GREEN" "$RESET"

cd ../client-cli/

################################################################################
section "Initial Setup and Repo Registration"
################################################################################

run_step "Register repo with key1" \
    cargo run --quiet -- register-repo --secret-key ../rest-api/private/key1 -u $backend --password secret $signers_file

################################################################################
section "Signers File Activation"
################################################################################

run_step "List pending for key1 (none expected, key1 submitted)" \
    cargo run --quiet -- list-pending --secret-key ../rest-api/private/key1 -u http://localhost:3000 --password secret

run_step "List pending for key2" \
    cargo run --quiet -- list-pending --secret-key ../rest-api/private/key2 -u http://localhost:3000 --password secret

run_step "Sign signers file with key2" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key2 --password secret $pending_signers_file

run_step "Sign signers file with key3 (completes signature)" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key3 --password secret $pending_signers_file

expect_fail "Sign signers file with key1 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key1 --password secret $pending_signers_file

################################################################################
section "Release Registration and Signing"
################################################################################

run_step "Register release with key3 (does not sign it)" \
    cargo run --quiet -- register-release --secret-key ../rest-api/private/key3 --password secret $release_url

run_step "List pending for key3" \
    cargo run --quiet -- list-pending --secret-key ../rest-api/private/key3 -u http://localhost:3000 --password secret

run_step "Sign release index with key1" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key1 --password secret $release_index

run_step "Sign release index with key2 (completes, threshold=2)" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key2 --password secret $release_index

expect_fail "Sign release index with key3 (already completed)" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key3 --password secret $release_index

run_step "Download release artifact (v0.6.0)" \
    cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
section "Updating Signers File"
################################################################################

run_step "Update signers file with key1" \
    cargo run -- update-signers --secret-key ../rest-api/private/key1 -p secret https://github.com/asfaload/asfald/blob/signers_file/asfaload_signers_file_update_01.json

run_step "List pending for key1 (none expected, key1 submitted)" \
    cargo run --quiet -- list-pending --secret-key ../rest-api/private/key1 -u http://localhost:3000 --password secret

run_step "List pending for key2 (should show pending)" \
    cargo run --quiet -- list-pending --secret-key ../rest-api/private/key2 -u http://localhost:3000 --password secret

run_step "Sign pending signers with key2" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key2 --password secret $pending_signers_file

run_step "Sign pending signers with key4 (activates new signers file)" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key4 --password secret $pending_signers_file

run_step "Download artifact (v0.6.0, signed with historical signers)" \
    cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.6.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
section "Registering Release with New Signers File"
################################################################################

run_step "Register second release with key3" \
    cargo run --quiet -- register-release --secret-key ../rest-api/private/key3 --password secret $release_url_2

run_step "List pending for key3" \
    cargo run --quiet -- list-pending --secret-key ../rest-api/private/key3 -u http://localhost:3000 --password secret

run_step "Sign release index with key1" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key1 --password secret $release_index_2

run_step "Sign release index with key2" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key2 --password secret $release_index_2

run_step "Sign release index with key4 (key3 does not sign)" \
    cargo run --quiet -- sign-pending --secret-key ../rest-api/private/key4 --password secret $release_index_2

run_step "Download artifact (v0.8.0)" \
    cargo run --quiet -- download -o /tmp/downloader_${RANDOM} https://github.com/asfaload/asfald/releases/download/v0.8.0/asfald-x86_64-unknown-linux-musl.tar.gz

################################################################################
print_summary
