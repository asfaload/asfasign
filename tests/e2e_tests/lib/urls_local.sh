# --- Local file server URL builders ---
# Provides the same interface as urls.sh but using a local file server.
# Requires FILE_SERVER_URL to be set (e.g., http://localhost:9090).

_FS_PROJECT="e2e_project"

signers_file() {
    local n="$1"
    echo "${FILE_SERVER_URL}/${_FS_PROJECT}/${HIDDEN_SIGNERS_DIR}/signers_file_${n}${_SIGNERS_SUFFIX}.json"
}

pending_signers_file() {
    echo "$(file_server_host)/${_FS_PROJECT}/asfaload.signers.pending/index.json"
}

release_index() {
    local version="$1"
    echo "$(file_server_host)/${_FS_PROJECT}/releases/v${version}/asfaload.index.json"
}

csum_file_url() {
    local version="$1"
    echo "${FILE_SERVER_URL}/${_FS_PROJECT}/releases/v${version}/SHA256SUMS"
}

artifact_url() {
    local version="$1"
    echo "${FILE_SERVER_URL}/${_FS_PROJECT}/releases/v${version}/artifact.bin"
}

# Helper: extract host from FILE_SERVER_URL for use in backend paths
# Strips scheme and port to match how forge-url and checksum_file_registrar
# derive paths (using url.host_str() which excludes the port).
file_server_host() {
    echo "$FILE_SERVER_URL" | sed 's|^https\?://||; s|:[0-9]*$||'
}
