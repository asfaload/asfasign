# --- Local file server URL builders ---
# Provides the same interface as urls.sh but using a local file server.
# Requires FILE_SERVER_URL to be set (e.g., http://localhost:9090).
# Requires helpers.sh (which sources urls.sh) to be sourced first, as it
# sets _SIGNERS_SUFFIX based on KEY_TYPE ("_asfaload" for asfaload).

_FS_PROJECT="e2e_project"

signers_file() {
    local n="$1"
    echo "${FILE_SERVER_URL}/${_FS_PROJECT}/${HIDDEN_SIGNERS_DIR}/signers_file_${n}${_SIGNERS_SUFFIX}.json"
}

pending_signers_file() {
    echo "$(file_server_origin)/${_FS_PROJECT}/${PENDING_SIGNERS_DIR}/${SIGNERS_FILE}"
}

release_index() {
    local version="$1"
    echo "$(file_server_origin)/${_FS_PROJECT}/releases/v${version}/${INDEX_FILE}"
}

csum_file_url() {
    local version="$1"
    echo "${FILE_SERVER_URL}/${_FS_PROJECT}/releases/v${version}/SHA256SUMS"
}

artifact_url() {
    local version="$1"
    echo "${FILE_SERVER_URL}/${_FS_PROJECT}/releases/v${version}/artifact.bin"
}

# Helper: build origin prefix from FILE_SERVER_URL for backend paths.
# Matches forge-url's path_prefix_from_url: scheme/host/port
file_server_origin() {
    local scheme host port
    scheme=$(echo "$FILE_SERVER_URL" | sed 's|^\(https\?\)://.*|\1|')
    host=$(echo "$FILE_SERVER_URL" | sed 's|^https\?://||; s|:[0-9]*$||')
    port=$(echo "$FILE_SERVER_URL" | grep -oP ':\K[0-9]+$' || { [ "$scheme" = "https" ] && echo "443" || echo "80"; })
    echo "${scheme}/${host}/${port}"
}
