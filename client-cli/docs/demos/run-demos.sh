#!/usr/bin/env bash
set -euo pipefail

# --- Constants ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TAPES_DIR="$SCRIPT_DIR/howto"
# Matches the password the fixture keys are encrypted with so a single
# --password-file works for every command in every tape.
DEMO_PASSWORD="password"
DEMO_PROJECT="demo-project"
KEEP_FIXTURE="${KEEP_FIXTURE:-}"
FIXTURE_KEYS_DIR="$REPO_ROOT/core/test_helpers/fixtures/keys"

# --- Profile resolution ---
DEMO_PROFILE="${DEMO_PROFILE:-production}"
case "$DEMO_PROFILE" in
    production)
        TYPING_SPEED="20ms"
        SLEEP="Sleep"
        END_PAUSE="6s"
        ;;
    fast)
        TYPING_SPEED="1ms"
        SLEEP="#"
        END_PAUSE="0s"
        ;;
    *)
        echo "unknown DEMO_PROFILE: $DEMO_PROFILE (expected: production, fast)" >&2
        exit 1
        ;;
esac
echo "Profile: $DEMO_PROFILE (typing=$TYPING_SPEED, sleep=$SLEEP, end_pause=$END_PAUSE)" >&2

# Explicit run order (do not rely on alphabetic order).
TAPES=(
    "generate-keys.tape"
    "create-signers-file.tape"
    "register-repo.tape"
    "activate-signers-file.tape"
    "register-release.tape"
    "sign-release.tape"
    "download-with-verification.tape"
    "update-signers-file.tape"
    "revoke-release-initiate.tape"
    "revoke-release-cosign.tape"
)

# Release version used by register/sign/download/revoke demos.
DEMO_RELEASE="v1.0"

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
RELEASE_DIR="$FIXTURE/fileserver/$DEMO_PROJECT/releases/$DEMO_RELEASE"
mkdir -p \
    "$FIXTURE/home/.asfaload" \
    "$FIXTURE/fileserver/$DEMO_PROJECT/asfaload.signers" \
    "$RELEASE_DIR" \
    "$FIXTURE/git-repo" \
    "$FIXTURE/logs"
printf '%s' "$DEMO_PASSWORD" > "$FIXTURE/home/.asfaload/.demo-password"

# Stage fixture keys into $HOME so every tape (except generate-keys) can
# reference real, pre-encrypted keys without depending on an earlier tape
# having created them. Only key_0..key_6 are needed by the current demos.
for n in 0 1 2 3 4 5 6; do
    cp "$FIXTURE_KEYS_DIR/key_$n"     "$FIXTURE/home/.asfaload/key_$n"
    cp "$FIXTURE_KEYS_DIR/key_$n.pub" "$FIXTURE/home/.asfaload/key_$n.pub"
done

# Release artifact + SHA256SUMS so register-release / sign-release / download
# have something real to point at. Deterministic content keeps GIFs reproducible.
printf 'asfaload demo artifact (%s)\n' "$DEMO_RELEASE" > "$RELEASE_DIR/artifact.bin"
( cd "$RELEASE_DIR" && sha256sum artifact.bin > SHA256SUMS )

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
NEW_SIGNERS_URL="$FILE_SERVER_URL/$DEMO_PROJECT/asfaload.signers/index_v2.json"
CSUM_URL="$FILE_SERVER_URL/$DEMO_PROJECT/releases/$DEMO_RELEASE/SHA256SUMS"
ARTIFACT_URL="$FILE_SERVER_URL/$DEMO_PROJECT/releases/$DEMO_RELEASE/artifact.bin"

# Backend-relative paths (scheme/host/port/<path>) are what list-pending /
# sign-pending / revoke take. They mirror the format the howtos display.
ORIGIN_PATH="http/localhost/$FILE_SERVER_PORT/$DEMO_PROJECT"
PENDING_SIGNERS_PATH="$ORIGIN_PATH/asfaload.signers.pending/index.json"
RELEASE_INDEX_PATH="$ORIGIN_PATH/releases/$DEMO_RELEASE/asfaload.index.json"
PENDING_REVOCATION_PATH="$RELEASE_INDEX_PATH.revocation.json.pending"
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

# --- Render tapes ---
mkdir -p "$TAPES_DIR/out"

# Hooks for hidden state-flow steps between tapes. Anything that happens off-camera
# (publishing files, batch-signing rounds the howto delegates to other guides) lives here.

CLI="$REPO_ROOT/target/debug/asfaload-cli"
PASSWORD_FILE="$FIXTURE/home/.asfaload/.demo-password"

asfa_sign_pending() {
    "$CLI" sign-pending --secret-key "$1" \
        --password-file "$PASSWORD_FILE" \
        -u "$BACKEND_URL" "$2" >/dev/null
}

render_tape() {
    # Substitutes $TYPING_SPEED, $SLEEP and $END_PAUSE into a .tape.tmpl,
    # writing the rendered .tape into the throwaway fixture so cleanup removes it.
    local src="$1" dst="$2"
    sed \
        -e "s|\$TYPING_SPEED|$TYPING_SPEED|g" \
        -e "s|\$SLEEP|$SLEEP|g" \
        -e "s|\$END_PAUSE|$END_PAUSE|g" \
        "$src" > "$dst"
}

hidden_step_before() {
    local tape="$1"
    case "$tape" in
        update-signers-file.tape)
            # The howto assumes the new signers file is already pushed; stage the
            # exact content the tape will produce locally, at its forge URL.
            "$CLI" new-signers-file \
                --artifact-signer-file "$FIXTURE/home/.asfaload/key_0.pub" \
                --artifact-signer-file "$FIXTURE/home/.asfaload/key_1.pub" \
                --artifact-signer-file "$FIXTURE/home/.asfaload/key_2.pub" \
                --artifact-signer-file "$FIXTURE/home/.asfaload/key_3.pub" \
                --artifact-threshold 3 \
                --revocation-key-file "$FIXTURE/home/.asfaload/key_4.pub" \
                --revocation-key-file "$FIXTURE/home/.asfaload/key_5.pub" \
                --revocation-key-file "$FIXTURE/home/.asfaload/key_6.pub" \
                --revocation-threshold 2 \
                --output-file "$FIXTURE/fileserver/$DEMO_PROJECT/asfaload.signers/index_v2.json" \
                >/dev/null
            ;;
        *) ;;
    esac
}

hidden_step_after() {
    local tape="$1"
    case "$tape" in
        create-signers-file.tape)
            # Equivalent to "commit and push" in the how-to.
            cp "$FIXTURE/home/signers.json" \
               "$FIXTURE/fileserver/$DEMO_PROJECT/asfaload.signers/index.json"
            ;;
        update-signers-file.tape)
            # Activation round delegated to the activate-signers-file howto;
            # we run it silently so revoke-release has a signers file with revocation keys.
            for n in 0 1 2 3 4 5 6; do
                asfa_sign_pending "$FIXTURE/home/.asfaload/key_$n" "$PENDING_SIGNERS_PATH"
            done
            ;;
        *) ;;
    esac
}

for tape in "${TAPES[@]}"; do
    template="$TAPES_DIR/${tape}.tmpl"
    if [[ ! -f "$template" ]]; then
        echo "Skipping missing template: $template" >&2
        continue
    fi

    rendered="$FIXTURE/$tape"
    render_tape "$template" "$rendered"

    hidden_step_before "$tape"
    echo "Recording $tape ..." >&2
    (
        cd "$TAPES_DIR"
        HOME="$FIXTURE/home" \
        PATH="$REPO_ROOT/target/debug:$PATH" \
        ASFALOAD_DEMO_BACKEND_URL="$BACKEND_URL" \
        ASFALOAD_DEMO_FILESERVER_URL="$FILE_SERVER_URL" \
        ASFALOAD_DEMO_SIGNERS_URL="$SIGNERS_URL" \
        ASFALOAD_DEMO_NEW_SIGNERS_URL="$NEW_SIGNERS_URL" \
        ASFALOAD_DEMO_PENDING_SIGNERS_PATH="$PENDING_SIGNERS_PATH" \
        ASFALOAD_DEMO_RELEASE_INDEX_PATH="$RELEASE_INDEX_PATH" \
        ASFALOAD_DEMO_PENDING_REVOCATION_PATH="$PENDING_REVOCATION_PATH" \
        ASFALOAD_DEMO_CSUM_URL="$CSUM_URL" \
        ASFALOAD_DEMO_ARTIFACT_URL="$ARTIFACT_URL" \
            vhs "$rendered"
    )
    output_name="${tape%.tape}.gif"
    if [[ ! -f "$TAPES_DIR/out/$output_name" ]]; then
        echo "Expected $TAPES_DIR/out/$output_name not produced." >&2
        exit 1
    fi
    hidden_step_after "$tape"
done

echo "All demos rendered to $TAPES_DIR/out/" >&2
