#!/usr/bin/env bash
set -euo pipefail

# --- Constants ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TAPES_DIR="$SCRIPT_DIR/howto"
DEMO_PASSWORD="demo-password-123"
KEEP_FIXTURE="${KEEP_FIXTURE:-}"

# Explicit run order (do not rely on alphabetic order).
TAPES=(
    "generate-keys.tape"
    "create-signers-file.tape"
    "register-repo.tape"
)

# --- Trap state ---
FIXTURE=""
FILE_SERVER_PID=""
REST_API_PID=""

cleanup() {
    if [[ -n "$REST_API_PID" ]] && kill -0 "$REST_API_PID" 2>/dev/null; then
        kill "$REST_API_PID" 2>/dev/null || true
        wait "$REST_API_PID" 2>/dev/null || true
    fi
    if [[ -n "$FILE_SERVER_PID" ]] && kill -0 "$FILE_SERVER_PID" 2>/dev/null; then
        kill "$FILE_SERVER_PID" 2>/dev/null || true
        wait "$FILE_SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$FIXTURE" && -d "$FIXTURE" && -z "$KEEP_FIXTURE" ]]; then
        rm -rf "$FIXTURE"
    elif [[ -n "$FIXTURE" && -n "$KEEP_FIXTURE" ]]; then
        echo "KEEP_FIXTURE=1 set; preserved fixture at $FIXTURE" >&2
    fi
}
trap cleanup EXIT INT TERM

# --- Build binaries ---
echo "Building asfaload-cli, rest-api, test-file-server..." >&2
( cd "$REPO_ROOT" && cargo build --quiet \
    --package client-cli \
    --package rest-api \
    --package test-file-server )

# --- Create fixture ---
FIXTURE="$(mktemp -d -t asfaload-demos.XXXXXX)"
mkdir -p \
    "$FIXTURE/home/.asfaload" \
    "$FIXTURE/fileserver/demo-project/asfaload.signers" \
    "$FIXTURE/git-repo" \
    "$FIXTURE/logs"
printf '%s' "$DEMO_PASSWORD" > "$FIXTURE/home/.asfaload/.demo-password"

echo "Fixture: $FIXTURE" >&2
echo "Driver scaffolding complete. (Servers and tapes land in subsequent tasks.)" >&2
