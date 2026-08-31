#!/usr/bin/env bats
# Tests for dev-tools/check-binary-name.sh (ARAS-0017 V-AC-25 probe gate)
# Usage: bats dev-tools/tests/check-binary-name.bats
#
# crates.io and Homebrew checks are pointed at a local fixture HTTP server
# (dev-tools/tests/fixtures/) via CRATES_IO_BASE / BREW_API_BASE so the
# suite is deterministic and offline — it does not depend on the live
# state of the real registries.

SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/check-binary-name.sh"
FIXTURES="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/fixtures"

setup() {
    PORT=$((20000 + RANDOM % 20000))
    python3 -m http.server "$PORT" --bind 127.0.0.1 \
        --directory "$FIXTURES" >/dev/null 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 30); do
        curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
        sleep 0.1
    done
    export CRATES_IO_BASE="http://127.0.0.1:$PORT/crates_io/crates"
    export BREW_API_BASE="http://127.0.0.1:$PORT/brew/formula"
}

teardown() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    ! kill -0 "$SERVER_PID" 2>/dev/null
}

@test "usage error with no arguments exits 2" {
    set -e
    run bash "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "free name on both crates.io and homebrew exits 0" {
    # `free-name` deliberately has NO fixture file, so the server 404s it —
    # which is what crates.io actually does for an unclaimed name.
    #
    # There used to be a `free-name` fixture containing
    # `{"errors":[{"detail":"crate does not exist"}]}`, served with HTTP 200
    # because it was a file on disk. The script grepped the body for
    # `"errors"`, so the fixture agreed with the code and both disagreed with
    # the server. Reality only ever answers 200 or 404 here, so the body was a
    # faithful stand-in for the status — right up until crates.io answered
    # anything else.
    set -e
    run bash "$SCRIPT" free-name
    [ "$status" -eq 0 ]
    [[ "$output" == *"crates.io:  free"* ]]
    [[ "$output" == *"homebrew:   free"* ]]
}

@test "a rate-limited or broken crates.io is never reported as free" {
    # The defect this replaced: every crates.io error body carries `"errors"`,
    # so under a 429 or a 500 the body-grep reported EVERY name as free.
    # Verified against the live registry before the fix — `serde` came back
    # free.
    #
    # "Free" is the permissive answer: it is what licenses an attempt to
    # publish, and a crates.io version that fails is burned permanently. An
    # outage must produce UNKNOWN.
    local port=$((20000 + RANDOM % 20000))
    python3 - "$port" &>/dev/null <<'PYEOF' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"errors":[{"detail":"Too many requests."}]}'
        self.send_response(429)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
    local pid=$!
    for _ in $(seq 1 30); do
        curl -s -o /dev/null "http://127.0.0.1:$port/" && break
        sleep 0.1
    done

    run env CRATES_IO_BASE="http://127.0.0.1:$port/crates" bash "$SCRIPT" any-name
    kill "$pid" 2>/dev/null || true

    [[ "$output" == *"crates.io:  UNKNOWN"* ]]
    [[ "$output" != *"crates.io:  free"* ]]
}

@test "name taken on crates.io exits 1 and reports TAKEN" {
    set -e
    run bash "$SCRIPT" taken-name
    [ "$status" -eq 1 ]
    [[ "$output" == *"crates.io:  TAKEN"* ]]
}

@test "checks multiple candidates in one invocation" {
    set -e
    run bash "$SCRIPT" free-name taken-name
    [ "$status" -eq 1 ]
    [[ "$output" == *"=== free-name ==="* ]]
    [[ "$output" == *"=== taken-name ==="* ]]
}
