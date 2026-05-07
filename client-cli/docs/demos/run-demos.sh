#!/usr/bin/env bash
set -euo pipefail

# --- Constants ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TAPES_DIR="$SCRIPT_DIR/howto"
DEMO_PASSWORD="demo-password-123"
DEMO_PROJECT="demo-project"
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
    "$FIXTURE/fileserver/$DEMO_PROJECT/asfaload.signers" \
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
SIGNERS_URL="$FILE_SERVER_URL/$DEMO_PROJECT/asfaload.signers/index.json"
echo "test-file-server: $FILE_SERVER_URL" >&2

# --- Initialise the git repo rest-api will commit into ---
git init --quiet "$FIXTURE/git-repo"
git -C "$FIXTURE/git-repo" config user.name "Demo Driver"
git -C "$FIXTURE/git-repo" config user.email "demo@asfaload.local"

# --- Start rest-api with retry on port collision ---
REST_API_LOG="$FIXTURE/logs/rest-api.log"
BACKEND_URL=""
for attempt in 1 2 3; do
    REST_API_PORT=$((3000 + RANDOM % 1000))
    candidate_url="http://localhost:$REST_API_PORT"

    ASFALOAD_SERVER_PORT="$REST_API_PORT" \
    ASFALOAD_GIT_REPO_PATH="$FIXTURE/git-repo" \
    ASFALOAD_GIT_BACKEND="sha1" \
        "$REPO_ROOT/target/debug/rest-api" \
        > "$REST_API_LOG" 2>&1 &
    REST_API_PID=$!

    ready=""
    for _ in $(seq 1 75); do  # 15s
        if curl --silent "$candidate_url" >/dev/null 2>&1 && kill -0 "$REST_API_PID" 2>/dev/null; then
            ready=1
            break
        fi
        if ! kill -0 "$REST_API_PID" 2>/dev/null; then
            break
        fi
        sleep 0.2
    done

    if [[ -n "$ready" ]]; then
        BACKEND_URL="$candidate_url"
        break
    fi

    # Server failed (likely port in use). Reap and retry.
    if kill -0 "$REST_API_PID" 2>/dev/null; then
        kill "$REST_API_PID" 2>/dev/null || true
        wait "$REST_API_PID" 2>/dev/null || true
    fi
    REST_API_PID=""
    echo "rest-api startup attempt $attempt failed on port $REST_API_PORT, retrying..." >&2
done

if [[ -z "$BACKEND_URL" ]]; then
    echo "rest-api did not become ready after 3 attempts. Log: $REST_API_LOG" >&2
    exit 1
fi
echo "rest-api: $BACKEND_URL" >&2
