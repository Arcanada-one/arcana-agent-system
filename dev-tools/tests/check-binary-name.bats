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
    (cd "$FIXTURES" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
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
}

@test "usage error with no arguments exits 2" {
    run bash "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "free name on both crates.io and homebrew exits 0" {
    run bash "$SCRIPT" free-name
    [ "$status" -eq 0 ]
    [[ "$output" == *"crates.io:  free"* ]]
    [[ "$output" == *"homebrew:   free"* ]]
}

@test "name taken on crates.io exits 1 and reports TAKEN" {
    run bash "$SCRIPT" taken-name
    [ "$status" -eq 1 ]
    [[ "$output" == *"crates.io:  TAKEN"* ]]
}

@test "checks multiple candidates in one invocation" {
    run bash "$SCRIPT" free-name taken-name
    [ "$status" -eq 1 ]
    [[ "$output" == *"=== free-name ==="* ]]
    [[ "$output" == *"=== taken-name ==="* ]]
}
