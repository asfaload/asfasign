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

# --- Start test-file-server ---
FILE_SERVER_LOG="$FIXTURE/logs/fileserver.log"
"$REPO_ROOT/target/debug/test-file-server" \
    --dir "$FIXTURE/fileserver" --port 0 \
    > "$FILE_SERVER_LOG" 2>&1 &
FILE_SERVER_PID=$!

FILE_SERVER_PORT=""
for _ in $(seq 1 75); do  # 75 * 0.2s = 15s
    if [[ -f "$FILE_SERVER_LOG" ]]; then
        FILE_SERVER_PORT="$(grep -oP 'LISTENING_PORT=\K[0-9]+' "$FILE_SERVER_LOG" 2>/dev/null || true)"
        [[ -n "$FILE_SERVER_PORT" ]] && break
    fi
    if ! kill -0 "$FILE_SERVER_PID" 2>/dev/null; then
        echo "test-file-server died. Log: $FILE_SERVER_LOG" >&2
        exit 1
    fi
    sleep 0.2
done

if [[ -z "$FILE_SERVER_PORT" ]]; then
    echo "test-file-server did not report a port within 15s. Log: $FILE_SERVER_LOG" >&2
    exit 1
fi

FILE_SERVER_URL="http://localhost:$FILE_SERVER_PORT"
SIGNERS_URL="$FILE_SERVER_URL/demo-project/asfaload.signers/index.json"
echo "test-file-server: $FILE_SERVER_URL" >&2
