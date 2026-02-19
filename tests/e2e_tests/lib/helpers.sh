# --- Fixture key paths ---
_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$_HELPERS_DIR/urls.sh"
. "$_HELPERS_DIR/constants.sh"
. "$_HELPERS_DIR/backend_assertions.sh"
KEYS_DIR="$(cd "$_HELPERS_DIR/../../.." && pwd)/core/test_helpers/fixtures/keys"
KEY_0="$KEYS_DIR/key_0"
KEY_1="$KEYS_DIR/key_1"
KEY_2="$KEYS_DIR/key_2"
KEY_3="$KEYS_DIR/key_3"
KEY_4="$KEYS_DIR/key_4"
KEY_5="$KEYS_DIR/key_5"
KEY_6="$KEYS_DIR/key_6"
KEY_7="$KEYS_DIR/key_7"
KEY_8="$KEYS_DIR/key_8"
KEY_9="$KEYS_DIR/key_9"

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

# --- Dependency check ---
if ! command -v jq &> /dev/null; then
    printf '%sjq is required but not installed.%s\n' "$RED" "$RESET"
    exit 1
fi

# --- Global state ---
STEP_NUM=0
PASS_COUNT=0
EXPECTED_FAIL_COUNT=0
SCRIPT_START=$(date +%s)
CURRENT_SECTION="setup"
debug="${debug:-}"

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

    if [[ -n $debug ]]; then
        echo
        echo "$output"
    fi

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

run_step_json() {
    local desc="$1"; shift
    local jq_filter="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s... ' "$DIM" "$STEP_NUM" "$RESET" "$desc"

    if [[ -n $debug ]]; then
        echo
        echo "$@" --json
    fi

    local step_start output exit_code=0
    step_start=$(date +%s)

    local stderr_file=$(mktemp)
    output=$("$@" --json 2>"$stderr_file") || exit_code=$?
    local stderr_output
    stderr_output=$(<"$stderr_file")
    rm -f "$stderr_file"

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ -n $debug ]]; then
        echo
        echo "stdout: $output"
        [[ -n "$stderr_output" ]] && echo "stderr: $stderr_output"
    fi

    if [ "$exit_code" -ne 0 ]; then
        printf '%s✗ FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sExit code:%s %d\n' "$RED" "$RESET" "$exit_code"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        [[ -n "$output" ]] && printf '  %sStdout:%s\n%s\n' "$RED" "$RESET" "$output"
        [[ -n "$stderr_output" ]] && printf '  %sStderr:%s\n%s\n' "$RED" "$RESET" "$stderr_output"
        exit 1
    fi

    if ! echo "$output" | jq -e "$jq_filter" > /dev/null 2>&1; then
        printf '%s✗ ASSERTION FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sFilter:%s  %s\n' "$RED" "$RESET" "$jq_filter"
        printf '  %sJSON:%s\n%s\n' "$RED" "$RESET" "$output"
        [[ -n "$stderr_output" ]] && printf '  %sStderr:%s\n%s\n' "$RED" "$RESET" "$stderr_output"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        exit 1
    fi

    printf '%s✓%s %s(%ds)%s\n' "$GREEN" "$RESET" "$DIM" "$elapsed" "$RESET"
    PASS_COUNT=$((PASS_COUNT + 1))
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

    if [[ -n $debug ]]; then
        echo
        echo "$output"
    fi

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

expect_fail_json() {
    local desc="$1"; shift
    local jq_filter="$1"; shift
    STEP_NUM=$((STEP_NUM + 1))
    printf '%s[%2d]%s %s %s(expect fail)%s... ' \
        "$DIM" "$STEP_NUM" "$RESET" "$desc" "$YELLOW" "$RESET"

    if [[ -n $debug ]]; then
        echo
        echo "$@" --json
    fi

    local step_start stdout_output exit_code=0
    step_start=$(date +%s)

    local stderr_file=$(mktemp)
    stdout_output=$("$@" --json 2>"$stderr_file") || exit_code=$?
    local stderr_output
    stderr_output=$(<"$stderr_file")
    rm -f "$stderr_file"

    local step_end elapsed
    step_end=$(date +%s)
    elapsed=$((step_end - step_start))

    if [[ -n $debug ]]; then
        echo
        [[ -n "$stdout_output" ]] && echo "stdout: $stdout_output"
        echo "stderr: $stderr_output"
    fi

    if [ "$exit_code" -eq 0 ]; then
        printf '%s✗ UNEXPECTED SUCCESS%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand was expected to fail but succeeded:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        [[ -n "$stdout_output" ]] && printf '  %sStdout:%s\n%s\n' "$RED" "$RESET" "$stdout_output"
        exit 1
    fi

    if ! echo "$stderr_output" | jq -e "$jq_filter" > /dev/null 2>&1; then
        printf '%s✗ ASSERTION FAILED%s %s(%ds)%s\n' "$RED" "$RESET" "$DIM" "$elapsed" "$RESET"
        printf '  %sCommand:%s %s --json\n' "$RED" "$RESET" "$*"
        printf '  %sFilter:%s  %s\n' "$RED" "$RESET" "$jq_filter"
        printf '  %sStderr JSON:%s\n%s\n' "$RED" "$RESET" "$stderr_output"
        printf '  %sSection:%s %s\n' "$RED" "$RESET" "$CURRENT_SECTION"
        exit 1
    fi

    printf '%s⚠ expected failure%s %s(%ds)%s\n' "$YELLOW" "$RESET" "$DIM" "$elapsed" "$RESET"
    EXPECTED_FAIL_COUNT=$((EXPECTED_FAIL_COUNT + 1))
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
