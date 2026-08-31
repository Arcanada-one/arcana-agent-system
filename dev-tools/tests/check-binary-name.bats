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
    PIDFILE="$BATS_TEST_TMPDIR/aux-server.pid"
    export CRATES_IO_BASE="http://127.0.0.1:$PORT/crates_io/crates"
    export BREW_API_BASE="http://127.0.0.1:$PORT/brew/formula"
}

stop_aux_server() {
    [[ -s "$PIDFILE" ]] || return 0
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    : > "$PIDFILE"
}

teardown() {
    stop_aux_server
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    ! kill -0 "$SERVER_PID" 2>/dev/null
}

# Start a throwaway server on a free port and echo it. Modes:
#   403  — every request 403s (a registry that cannot answer)
#   ua   — 403 for an absent or default `curl/*` User-Agent, 404 otherwise.
#          That is crates.io's ACTUAL rule, measured: a suppressed header and
#          `curl/8.5.0` both 403; `arcana-check/1.0` and even `Mozilla/5.0`
#          get through. A fixture keyed on "is a User-Agent present" would be
#          satisfied by curl's own default and could never fail.
start_server() {
    local mode="$1" port=$((20000 + RANDOM % 20000))
    python3 - "$port" "$mode" &>/dev/null <<'PYEOF' &
import http.server, sys
mode = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        if mode == "ua" and ua and not ua.startswith("curl/"):
            code, body = 404, b'{"errors":[{"detail":"does not exist"}]}'
        else:
            code, body = 403, b''
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF
    # The caller invokes this as `$(start_server ...)`, a SUBSHELL, so an
    # assignment here could never reach it — the server would leak and the
    # suite would hang on its inherited stdout. The pid goes to a file.
    echo $! > "$PIDFILE"
    for _ in $(seq 1 30); do
        curl -s -o /dev/null "http://127.0.0.1:$port/" && break
        sleep 0.1
    done
    echo "$port"
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

@test "an all-inconclusive run does not exit 0" {
    # `0` reads as "these names are available". A run where no registry could
    # answer observed nothing, and must not say so with the same code as a
    # clean result. Measured before this: every registry 403, every line
    # correctly UNKNOWN, exit 0.
    local port; port=$(start_server 403)
    run env CRATES_IO_BASE="http://127.0.0.1:$port/crates" \
            BREW_API_BASE="http://127.0.0.1:$port/f" \
            bash "$SCRIPT" some-name
    stop_aux_server
    [ "$status" -eq 3 ]
    [[ "$output" == *"UNKNOWN"* ]]
    [[ "$output" != *"crates.io:  free"* ]]
}

@test "a definite TAKEN outranks an unreachable sibling registry" {
    # The actionable answer wins: a name that IS taken is taken whether or not
    # Homebrew answered.
    set -e
    run env BREW_API_BASE="http://127.0.0.1:1/nope" bash "$SCRIPT" taken-name
    [ "$status" -eq 1 ]
    [[ "$output" == *"crates.io:  TAKEN"* ]]
}

@test "the crates.io request carries a User-Agent" {
    # crates.io answers 403 to a UA-less request BEFORE deciding whether the
    # crate exists — the same 403 for a taken name, a free one, and a typo.
    # Verified live: `serde`, `arcana-agent-system` and a nonsense name all 403
    # without a UA; 200/404/404 with one.
    #
    # The rule is specifically about the DEFAULT agent: a suppressed header and
    # `curl/8.5.0` both 403, while any custom string gets through. The first
    # version of this fixture asked only "is a User-Agent present" — which
    # curl satisfies on its own — so it passed with `-A` removed. A fixture
    # that cannot produce production's failure is a test that cannot come
    # back no.
    local port; port=$(start_server ua)
    run env CRATES_IO_BASE="http://127.0.0.1:$port/crates" bash "$SCRIPT" free-name
    stop_aux_server
    [[ "$output" == *"crates.io:  free"* ]]
    [[ "$output" != *"403"* ]]
}

@test "the fixture reproduces crates.io's measured User-Agent rule" {
    # Checks the FIXTURE, not the script — because the fixture is the thing
    # that decides whether the test above can fail, and it has already been
    # wrong once.
    #
    # Measured against the live registry, 2026-08-31:
    #     (header suppressed)  403
    #     curl/8.5.0           403
    #     Mozilla/5.0          200
    #     arcana-check/1.0     200
    #
    # `Mozilla/5.0` is the discriminating case. A rule of "a User-Agent is
    # present" fits the first three observations and is WRONG; only the fourth
    # separates it from "not absent and not the default curl/*". Two data
    # points confirm almost anything.
    local port; port=$(start_server ua)
    local url="http://127.0.0.1:$port/crates/anything"

    [ "$(curl -s -o /dev/null -w '%{http_code}' -H 'User-Agent:' "$url")" = 403 ]
    [ "$(curl -s -o /dev/null -w '%{http_code}' -A 'curl/8.5.0' "$url")" = 403 ]
    [ "$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' "$url")" = 404 ]
    [ "$(curl -s -o /dev/null -w '%{http_code}' -A 'arcana-check/1.0' "$url")" = 404 ]

    stop_aux_server
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
