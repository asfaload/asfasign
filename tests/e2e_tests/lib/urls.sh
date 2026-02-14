# --- E2E test URL builders ---
# Derives TEST_NAME from the calling script's $0.
# Provides functions to build URLs for the e2e test repo.

E2E_REPO="asfaload/repo_for_e2e_tests"
TEST_NAME="$(basename "$0" .sh)"

signers_file() {
    local n="$1"
    echo "https://github.com/${E2E_REPO}/blob/master/${TEST_NAME}/signers_file_${n}.json"
}

pending_signers_file() {
    echo "github.com/${E2E_REPO}/asfaload.signers.pending/index.json"
}

release_url() {
    local version="$1"
    echo "https://github.com/${E2E_REPO}/releases/tag/v${version}"
}

release_index() {
    local version="$1"
    echo "github.com/${E2E_REPO}/releases/tag/v${version}/asfaload.index.json"
}

artifact_url() {
    local version="$1"
    echo "https://github.com/${E2E_REPO}/releases/download/v${version}/artifact.bin"
}
