# --- E2E test URL builders ---
# Derives TEST_NAME from the calling script's $0.
# Provides functions to build URLs for the e2e test repo.

E2E_REPO="asfaload/repo_for_e2e_tests"
TEST_NAME="$(basename "$0" .sh)"

# Signers file suffix for the e2e test repo, derived from KEY_TYPE.
# minisign uses no suffix (original files), ed25519 uses "_ed25519".
case "$KEY_TYPE" in
    minisign) _SIGNERS_SUFFIX="" ;;
    ed25519)  _SIGNERS_SUFFIX="_ed25519" ;;
    *)
        printf 'urls.sh: unsupported KEY_TYPE: %s\n' "$KEY_TYPE" >&2
        exit 1
        ;;
esac

signers_file() {
    local n="$1"
    echo "https://github.com/${E2E_REPO}/blob/master/${TEST_NAME}/signers_file_${n}${_SIGNERS_SUFFIX}.json"
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
