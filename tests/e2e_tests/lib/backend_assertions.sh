# --- Backend git repo assertions ---
# Validates the state of the backend's git repository after client-cli operations.
# Requires: E2E_GIT_REPO_PATH, E2E_REPO (from urls.sh), run_step (from helpers.sh),
#           constants (from constants.sh), KEY_* variables (from helpers.sh)

# Compute the project directory inside the backend git repo.
# Called lazily (not at source time) because E2E_GIT_REPO_PATH isn't set yet.
_project_dir() {
    echo "$E2E_GIT_REPO_PATH/github.com/${E2E_REPO}"
}

# Extract minisign public key string from a key file path.
# Usage: pubkey_of "$KEY_0"  →  "RWS1kZJeKmeNOI0vl8hjI/..."
pubkey_of() {
    sed -n 2p "${1}.pub"
}

# --- Low-level assertion primitives ---

# Assert a file exists at the given path.
assert_file_exists() {
    local path="$1" desc="$2"
    run_step "Backend: $desc exists" test -f "$path"
}

# Assert a directory exists at the given path.
assert_dir_exists() {
    local path="$1" desc="$2"
    run_step "Backend: $desc exists" test -d "$path"
}

# Assert a file does NOT exist at the given path.
assert_file_not_exists() {
    local path="$1" desc="$2"
    run_step "Backend: $desc does not exist" test ! -e "$path"
}

# Assert a jq filter evaluates to true on a JSON file.
assert_json_field() {
    local file="$1" jq_filter="$2" desc="$3"
    run_step "Backend: $desc" jq -e "$jq_filter" "$file"
}

# --- Signers lifecycle assertions ---

assert_pending_signers_exist() {
    local project_dir
    project_dir="$(_project_dir)"
    assert_dir_exists "$project_dir/$PENDING_SIGNERS_DIR" "Pending signers dir"
    assert_file_exists "$project_dir/$PENDING_SIGNERS_DIR/$SIGNERS_FILE" "Pending signers index.json"
}

assert_pending_signers_signature_count() {
    local expected="$1"
    local project_dir sig_file
    project_dir="$(_project_dir)"
    sig_file="$project_dir/$PENDING_SIGNERS_DIR/$SIGNERS_FILE.$PENDING_SIGNATURES_SUFFIX"
    assert_json_field "$sig_file" "keys | length == $expected" \
        "Pending signers has $expected signature(s)"
}

assert_signers_active() {
    local project_dir
    project_dir="$(_project_dir)"
    assert_dir_exists "$project_dir/$SIGNERS_DIR" "Active signers dir"
    assert_file_exists "$project_dir/$SIGNERS_DIR/$SIGNERS_FILE" "Active signers index.json"
    assert_file_exists "$project_dir/$SIGNERS_DIR/$SIGNERS_FILE.$SIGNATURES_SUFFIX" \
        "Active signers signatures"
    assert_file_not_exists "$project_dir/$PENDING_SIGNERS_DIR" "Pending signers dir removed"
}

assert_signers_contain_keys() {
    local project_dir signers_path
    project_dir="$(_project_dir)"
    signers_path="$project_dir/$SIGNERS_DIR/$SIGNERS_FILE"
    for key_file in "$@"; do
        local pk
        pk="$(pubkey_of "$key_file")"
        assert_json_field "$signers_path" \
            "[.artifact_signers[].signers[].data.pubkey] | any(. == \"$pk\")" \
            "Active signers contains $(basename "$key_file")"
    done
}

assert_pending_signers_contain_keys() {
    local project_dir signers_path
    project_dir="$(_project_dir)"
    signers_path="$project_dir/$PENDING_SIGNERS_DIR/$SIGNERS_FILE"
    for key_file in "$@"; do
        local pk
        pk="$(pubkey_of "$key_file")"
        assert_json_field "$signers_path" \
            "[.artifact_signers[].signers[].data.pubkey] | any(. == \"$pk\")" \
            "Pending signers contains $(basename "$key_file")"
    done
}

assert_signers_history_entries() {
    local expected="$1"
    local project_dir history_file
    project_dir="$(_project_dir)"
    history_file="$project_dir/$SIGNERS_HISTORY_FILE"
    assert_json_field "$history_file" ".entries | length == $expected" \
        "Signers history has $expected entry/entries"
}

# --- Release lifecycle assertions ---

_release_dir() {
    local version="$1"
    echo "$(_project_dir)/releases/tag/v${version}"
}

assert_release_index_exists() {
    local version="$1"
    assert_file_exists "$(_release_dir "$version")/$INDEX_FILE" \
        "Release v$version index file"
}

assert_release_index_pending() {
    local version="$1"
    local release_dir
    release_dir="$(_release_dir "$version")"
    assert_file_exists "$release_dir/$INDEX_FILE.$PENDING_SIGNATURES_SUFFIX" \
        "Release v$version pending signatures"
}

assert_release_index_signature_count() {
    local version="$1" expected="$2"
    local sig_file
    sig_file="$(_release_dir "$version")/$INDEX_FILE.$PENDING_SIGNATURES_SUFFIX"
    if [[ ! -f "$sig_file" ]]; then
        sig_file="$(_release_dir "$version")/$INDEX_FILE.$SIGNATURES_SUFFIX"
    fi
    assert_json_field "$sig_file" "keys | length == $expected" \
        "Release v$version has $expected signature(s)"
}

assert_release_index_active() {
    local version="$1"
    local release_dir
    release_dir="$(_release_dir "$version")"
    assert_file_exists "$release_dir/$INDEX_FILE.$SIGNATURES_SUFFIX" \
        "Release v$version complete signatures"
    assert_file_not_exists "$release_dir/$INDEX_FILE.$PENDING_SIGNATURES_SUFFIX" \
        "Release v$version pending signatures removed"
}

assert_release_index_signers() {
    local version="$1"; shift
    local signers_path
    signers_path="$(_release_dir "$version")/$INDEX_FILE.$SIGNERS_SUFFIX"
    assert_file_exists "$signers_path" "Release v$version local signers copy"
    for key_file in "$@"; do
        local pk
        pk="$(pubkey_of "$key_file")"
        assert_json_field "$signers_path" \
            "[.artifact_signers[].signers[].data.pubkey] | any(. == \"$pk\")" \
            "Release v$version signers contains $(basename "$key_file")"
    done
}

# --- Revocation assertions ---

assert_release_index_revoked() {
    local version="$1"
    local release_dir
    release_dir="$(_release_dir "$version")"
    local index="$release_dir/$INDEX_FILE"

    assert_file_exists "$index.$REVOCATION_SUFFIX" \
        "Release v$version revocation file"
    assert_file_exists "$index.$REVOCATION_SUFFIX.$SIGNATURES_SUFFIX" \
        "Release v$version revocation signatures"
    assert_file_exists "$index.$SIGNATURES_SUFFIX.$REVOKED_SUFFIX" \
        "Release v$version original signatures marked revoked"
    assert_file_not_exists "$index.$SIGNATURES_SUFFIX" \
        "Release v$version original signatures removed"
}

assert_revocation_signers() {
    local version="$1"; shift
    local release_dir signers_path
    release_dir="$(_release_dir "$version")"
    signers_path="$release_dir/$INDEX_FILE.$REVOCATION_SUFFIX.$SIGNERS_SUFFIX"
    assert_file_exists "$signers_path" "Release v$version revocation signers"
    for key_file in "$@"; do
        local pk
        pk="$(pubkey_of "$key_file")"
        assert_json_field "$signers_path" \
            "[.artifact_signers[].signers[].data.pubkey] | any(. == \"$pk\")" \
            "Release v$version revocation signers contains $(basename "$key_file")"
    done
}

# --- Artifact assertions ---

assert_artifact_hash_matches() {
    local version="$1" artifact_name="$2" downloaded_file="$3"
    local release_dir index_path
    release_dir="$(_release_dir "$version")"
    index_path="$release_dir/$INDEX_FILE"

    local expected_hash
    expected_hash=$(jq -r \
        --arg name "$artifact_name" \
        '.publishedFiles[] | select(.fileName == $name) | .hash' \
        "$index_path")

    local actual_hash
    actual_hash=$(sha256sum "$downloaded_file" | cut -d' ' -f1)

    run_step "Backend: artifact $artifact_name hash matches download" \
        test "$expected_hash" = "$actual_hash"
}

# Helper: check if a string contains a pattern (avoids pipe in run_step args)
_string_contains() {
    local haystack="$1" needle="$2"
    echo "$haystack" | grep -q "$needle"
}

assert_last_commit_contains() {
    local committed_files
    committed_files=$(git -C "$E2E_GIT_REPO_PATH" diff-tree --root --no-commit-id --name-only -r HEAD 2>/dev/null || true)
    for pattern in "$@"; do
        run_step "Backend: last commit contains $pattern" \
            _string_contains "$committed_files" "$pattern"
    done
}

assert_commit_count() {
    local expected="$1"
    local actual
    actual=$(git -C "$E2E_GIT_REPO_PATH" rev-list --count HEAD 2>/dev/null || echo 0)
    run_step "Backend: commit count is $expected" \
        test "$actual" -eq "$expected"
}
