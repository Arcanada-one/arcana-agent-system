#!/usr/bin/env bash
# arcana-smoke.sh — the falsifiable prod-quality-gate instrument (ARAS-0040).
#
# Stages S0–S5 against the release `arcana` binary + the agent-loop driver:
#   S0  build-provenance   embedded GIT_SHA == `git rev-parse --short=7 HEAD`
#   S1  whoami + audit      allow → identity + Allowed record; deny → exit 2 +
#                           Denied{layer} record; real audit log untouched
#   S2  mc-ping             nonce-bound replay success (+ optional live leg)
#   S3  negative controls   pinned ConnectorError Display strings (token unset /
#                           stub-200 / 201-error) — assert the MESSAGE, not the
#                           exit code (run_mc_ping collapses errors to one code)
#   S4  agent-loop e2e      driver drives a scripted task to Completed
#   S5  cost-breaker        driver terminates on MaxCostUsd (unit + replay xcript)
#   +   secret non-leak     secret-value-shaped `strings` arm is empty
#
# Output: TAP version 13 on stdout + a JUnit XML at
# ${ARCANA_SMOKE_OUT:-<tmp>}/arcana-smoke.junit.xml, both from one ledger.
# Tri-state: a leg with no live dependency is SKIP-recorded, never green.
#
# Isolation: every `arcana` invocation runs with HOME / XDG_STATE_HOME /
# XDG_CONFIG_HOME pointed at a throwaway `mktemp -d`; the operator's real
# audit log is asserted untouched. cargo-test stages (S4/S5) use the real
# environment (they self-isolate via tempdirs) so the cargo cache is reused.
#
# Exit: 0 when no stage is `not ok` (SKIPs of optional live legs are allowed);
# non-zero when any mandatory assertion failed.

set -u -o pipefail

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$REPO_ROOT/target/release/arcana"
FIXTURES="$SCRIPT_DIR/fixtures"
REPLAY_SERVER="$SCRIPT_DIR/mc_replay_server.py"

WORK="$(mktemp -d)"
OUT="${ARCANA_SMOKE_OUT:-$WORK}"
mkdir -p "$OUT"
JUNIT="$OUT/arcana-smoke.junit.xml"

# Real (operator) audit log path — captured BEFORE any isolation override so we
# can prove the harness never wrote to it.
REAL_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
REAL_AUDIT="$REAL_STATE_HOME/arcana/audit.log"
real_audit_stamp() { stat -c '%Y' "$REAL_AUDIT" 2>/dev/null || echo "absent"; }
REAL_AUDIT_BEFORE="$(real_audit_stamp)"

REPLAY_PID=""
cleanup() {
    [ -n "$REPLAY_PID" ] && kill "$REPLAY_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Ledger — one entry per assertion: "STATUS<TAB>NAME<TAB>DIAG"
# STATUS ∈ ok | notok | skip
# --------------------------------------------------------------------------
LEDGER=()
record() { # status name diag
    LEDGER+=("$1"$'\t'"$2"$'\t'"${3:-}")
}
pass() { record ok "$1" ""; }
fail() { record notok "$1" "${2:-assertion failed}"; }
skip() { record skip "$1" "${2:-skipped}"; }

# assert_contains NAME HAYSTACK NEEDLE
assert_contains() {
    local name="$1" hay="$2" needle="$3"
    if [[ "$hay" == *"$needle"* ]]; then
        pass "$name"
    else
        fail "$name" "expected to contain: $needle"
    fi
}

# --------------------------------------------------------------------------
# Replay server helpers
# --------------------------------------------------------------------------
REPLAY_PORT=""
start_replay() { # status body_file
    local status="$1" body_file="$2" outfile
    outfile="$(mktemp)"
    MC_STATUS="$status" MC_BODY_FILE="$body_file" \
        python3 "$REPLAY_SERVER" >"$outfile" 2>/dev/null &
    REPLAY_PID=$!
    REPLAY_PORT=""
    local i
    for i in $(seq 1 50); do
        REPLAY_PORT="$(sed -n 's/^PORT=//p' "$outfile" 2>/dev/null | head -1)"
        [ -n "$REPLAY_PORT" ] && break
        sleep 0.1
    done
    rm -f "$outfile"
    [ -n "$REPLAY_PORT" ]
}
stop_replay() {
    [ -n "$REPLAY_PID" ] && kill "$REPLAY_PID" 2>/dev/null
    [ -n "$REPLAY_PID" ] && wait "$REPLAY_PID" 2>/dev/null
    REPLAY_PID=""
}

# Run the arcana binary under an isolated HOME/XDG so it never touches the real
# audit log. Usage: iso_arcana STATE_SUBDIR ENV... -- args...
# Captures combined stdout+stderr into ISO_OUT and the code into ISO_CODE.
ISO_OUT=""
ISO_CODE=0
iso_arcana() {
    local state="$WORK/$1"; shift
    mkdir -p "$state"
    local -a envs=()
    while [ "$1" != "--" ]; do envs+=("$1"); shift; done
    shift # drop --
    ISO_OUT="$(env HOME="$state" XDG_STATE_HOME="$state/state" \
        XDG_CONFIG_HOME="$state/config" "${envs[@]}" "$BIN" "$@" 2>&1)"
    ISO_CODE=$?
    ISO_STATE="$state"
}

# ==========================================================================
# S0 — build provenance
# ==========================================================================
stage_s0() {
    if [ ! -x "$BIN" ]; then
        fail "S0 build-provenance binary-present" "no release binary at $BIN (run: cargo build --release)"
        return
    fi
    local ver code
    ver="$("$BIN" version 2>&1)"; code=$?
    if [ $code -ne 0 ]; then
        fail "S0 build-provenance version-exit-0" "arcana version exited $code"
        return
    fi
    # embedded SHA is the parenthesised token: "arcana 0.1.0 (18373b6) — …"
    local embedded head
    embedded="$(printf '%s' "$ver" | sed -n 's/.*(\([0-9a-f]\{7\}\)).*/\1/p')"
    head="$(git -C "$REPO_ROOT" rev-parse --short=7 HEAD 2>/dev/null)"
    if [ -n "$embedded" ] && [ "$embedded" = "$head" ]; then
        pass "S0 build-provenance GIT_SHA==HEAD"
    else
        fail "S0 build-provenance GIT_SHA==HEAD" "embedded=$embedded head=$head (stale binary?)"
    fi
}

# ==========================================================================
# S1 — whoami + audit side-effect (allow + deny)
# ==========================================================================
stage_s1() {
    # Allow path.
    iso_arcana s1-allow ARCANA_PERMISSION_AUTO=allow -- whoami
    local audit="$ISO_STATE/state/arcana/audit.log"
    if [ $ISO_CODE -eq 0 ]; then pass "S1 whoami-allow exit-0"; else
        fail "S1 whoami-allow exit-0" "exit $ISO_CODE: $ISO_OUT"; fi
    if [[ "$ISO_OUT" != *"cascade denied"* ]]; then pass "S1 whoami-allow not-denied"; else
        fail "S1 whoami-allow not-denied" "unexpected 'cascade denied' on allow: $ISO_OUT"; fi
    if [ -s "$audit" ]; then pass "S1 whoami-allow audit-nonempty"; else
        fail "S1 whoami-allow audit-nonempty" "audit log missing/empty at $audit"; fi
    if grep -q '"tool":"whoami"' "$audit" 2>/dev/null; then pass "S1 whoami-allow audit-has-whoami"; else
        fail "S1 whoami-allow audit-has-whoami" "no whoami record"; fi
    if grep -q '"decision":"Allowed"' "$audit" 2>/dev/null; then pass "S1 whoami-allow audit-Allowed-record"; else
        fail "S1 whoami-allow audit-Allowed-record" "no terminal Allowed decision record"; fi

    # Deny path.
    iso_arcana s1-deny ARCANA_PERMISSION_AUTO=deny -- whoami
    local daudit="$ISO_STATE/state/arcana/audit.log"
    if [ $ISO_CODE -eq 2 ]; then pass "S1 whoami-deny exit-2"; else
        fail "S1 whoami-deny exit-2" "expected 2, got $ISO_CODE: $ISO_OUT"; fi
    if grep -q '"decision":"Denied{interactive_auto}"' "$daudit" 2>/dev/null; then
        pass "S1 whoami-deny audit-Denied-record"; else
        fail "S1 whoami-deny audit-Denied-record" "no Denied{layer} terminal record"; fi
}

# ==========================================================================
# S2 — mc-ping nonce-bound replay (+ optional live leg)
# ==========================================================================
stage_s2() {
    local nonce
    nonce="$(openssl rand -hex 8 2>/dev/null || head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    local body="$WORK/s2-success.json"
    sed "s/__NONCE__/$nonce/" "$FIXTURES/mc-success.json" >"$body"

    if ! start_replay 201 "$body"; then
        fail "S2 mc-ping-replay nonce-bound" "replay server failed to start"
        return
    fi
    iso_arcana s2 ARCANA_MC_BASE_URL="http://127.0.0.1:$REPLAY_PORT" ARCANA_MC_TOKEN=staging -- mc-ping
    stop_replay
    if [ $ISO_CODE -eq 0 ]; then pass "S2 mc-ping-replay exit-0"; else
        fail "S2 mc-ping-replay exit-0" "exit $ISO_CODE: $ISO_OUT"; fi
    assert_contains "S2 mc-ping-replay nonce-bound" "$ISO_OUT" "ARCANA-$nonce"

    # Optional live leg — only when explicitly requested AND a token is present.
    if [ "${ARCANA_MC_LIVE:-0}" = "1" ] && [ -n "${ARCANA_MC_TOKEN:-}" ]; then
        iso_arcana s2-live ARCANA_MC_TOKEN="$ARCANA_MC_TOKEN" -- mc-ping
        if [ $ISO_CODE -eq 0 ] && [[ "$ISO_OUT" == *"result="* ]]; then
            pass "S2 mc-ping-live"
        else
            fail "S2 mc-ping-live" "live mc-ping exit $ISO_CODE: $ISO_OUT"
        fi
    else
        skip "S2 mc-ping-live" "env:mc-live-not-requested (set ARCANA_MC_LIVE=1 + ARCANA_MC_TOKEN)"
    fi
}

# ==========================================================================
# S3 — negative controls (pinned ConnectorError Display strings)
# ==========================================================================
stage_s3() {
    # (a) token unset → MissingApiKey Display. Force ARCANA_MC_TOKEN unset for
    # this leg regardless of the caller's environment.
    mkdir -p "$WORK/s3-tok"
    ISO_OUT="$(env -u ARCANA_MC_TOKEN HOME="$WORK/s3-tok" XDG_STATE_HOME="$WORK/s3-tok/state" \
        XDG_CONFIG_HOME="$WORK/s3-tok/config" "$BIN" mc-ping 2>&1)"; ISO_CODE=$?
    assert_contains "S3 token-unset pinned-Display" "$ISO_OUT" "missing API key (set ARCANA_MC_TOKEN)"

    # (b) stub HTTP 200 → UnexpectedStatus(200) Display.
    if start_replay 200 "$FIXTURES/mc-success.json"; then
        iso_arcana s3-200 ARCANA_MC_BASE_URL="http://127.0.0.1:$REPLAY_PORT" ARCANA_MC_TOKEN=staging -- mc-ping
        stop_replay
        assert_contains "S3 stub-200 pinned-Display" "$ISO_OUT" "unexpected HTTP status 200 (expected 201)"
    else
        fail "S3 stub-200 pinned-Display" "replay server failed to start"
    fi

    # (c) 201 {"status":"error"} → Logical Display.
    if start_replay 201 "$FIXTURES/mc-error.json"; then
        iso_arcana s3-err ARCANA_MC_BASE_URL="http://127.0.0.1:$REPLAY_PORT" ARCANA_MC_TOKEN=staging -- mc-ping
        stop_replay
        assert_contains "S3 201-error pinned-Display" "$ISO_OUT" "upstream logical error ["
    else
        fail "S3 201-error pinned-Display" "replay server failed to start"
    fi
}

# ==========================================================================
# S4 — agent-loop e2e (driver → Completed with a real tool dispatch)
# ==========================================================================
stage_s4() {
    if (cd "$REPO_ROOT" && cargo test -q -p arcana-core --test driver_completes_small_task \
        -- --exact driver_completes_small_task >/dev/null 2>&1); then
        pass "S4 agent-loop-e2e driver-completes"
    else
        fail "S4 agent-loop-e2e driver-completes" "driver_completes_small_task failed"
    fi
}

# ==========================================================================
# S5 — cost-breaker (MaxCostUsd fires on unit + replay transcript)
# ==========================================================================
stage_s5() {
    if (cd "$REPO_ROOT" && cargo test -q -p arcana-core --test driver_cost_accounting \
        -- driver_cost_cap_terminates >/dev/null 2>&1); then
        pass "S5 cost-breaker maxcost-unit"
    else
        fail "S5 cost-breaker maxcost-unit" "driver_cost_cap_terminates failed"
    fi
    if (cd "$REPO_ROOT" && cargo test -q -p arcana-core --test driver_cost_accounting \
        -- driver_cost_breaker_replay_transcript_terminates_on_maxcost >/dev/null 2>&1); then
        pass "S5 cost-breaker maxcost-replay-transcript"
    else
        fail "S5 cost-breaker maxcost-replay-transcript" "replay-transcript breaker test failed"
    fi
}

# ==========================================================================
# Secret non-leak — secret-value-shaped strings arm is empty
# ==========================================================================
stage_secret() {
    if [ ! -x "$BIN" ]; then
        skip "SEC no-secret-in-binary" "no binary"
        return
    fi
    # Secret-value-shaped, HEX-anchored (F6, corrected). A word-boundary anchor
    # is useless here: rustc concatenates every &str literal into one contiguous
    # rodata blob with no separators, so `strings` emits them as a single line
    # and a real leaked token would be glued to its neighbours (no boundary).
    # Instead we key on token SHAPE: `mc-` immediately followed by ≥8 lowercase
    # hex chars. Honest code literals such as the rustls CMC-OID symbols
    # (`id-cmc-identityProof`, `id-cmc-revokeRequest`, …) carry non-hex camelCase
    # after `mc-` and never match; a real `mc-<hex>` token / the `mc-deadbeef…`
    # canary matches even when glued. Proven able to fire (canary) AND empty on
    # an honest build in dev-tools/smoke/mutation-matrix.md.
    local hits
    hits="$(strings "$BIN" 2>/dev/null | grep -oE 'mc-[0-9a-f]{8,}' || true)"
    if [ -z "$hits" ]; then
        pass "SEC no-secret-in-binary"
    else
        fail "SEC no-secret-in-binary" "secret-value-shaped token found in binary: $hits"
    fi
}

# ==========================================================================
# Isolation — the real operator audit log is byte-for-byte untouched
# ==========================================================================
stage_isolation() {
    local after; after="$(real_audit_stamp)"
    if [ "$after" = "$REAL_AUDIT_BEFORE" ]; then
        pass "ISO real-audit-log-untouched"
    else
        fail "ISO real-audit-log-untouched" "real audit mtime changed: $REAL_AUDIT_BEFORE -> $after ($REAL_AUDIT)"
    fi
}

# --------------------------------------------------------------------------
# Run all stages
# --------------------------------------------------------------------------
stage_s0
stage_s1
stage_s2
stage_s3
stage_s4
stage_s5
stage_secret
stage_isolation

# --------------------------------------------------------------------------
# Emit TAP
# --------------------------------------------------------------------------
xml_escape() { sed -e 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

N=${#LEDGER[@]}
echo "TAP version 13"
echo "1..$N"
fails=0
skips=0
idx=0
for entry in "${LEDGER[@]}"; do
    idx=$((idx + 1))
    IFS=$'\t' read -r status name diag <<<"$entry"
    case "$status" in
        ok)   echo "ok $idx - $name" ;;
        skip) echo "ok $idx - $name # SKIP($diag)"; skips=$((skips + 1)) ;;
        notok)
            echo "not ok $idx - $name"
            echo "  ---"
            echo "  message: $diag"
            echo "  ---"
            fails=$((fails + 1))
            ;;
    esac
done
echo "# tests $N  pass $((N - fails - skips))  fail $fails  skip $skips"

# --------------------------------------------------------------------------
# Emit JUnit (same ledger — single source, no drift)
# --------------------------------------------------------------------------
{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo "<testsuite name=\"arcana-smoke\" tests=\"$N\" failures=\"$fails\" skipped=\"$skips\">"
    for entry in "${LEDGER[@]}"; do
        IFS=$'\t' read -r status name diag <<<"$entry"
        jname="$(printf '%s' "$name" | tr ' ' '-' | xml_escape)"
        case "$status" in
            ok)   echo "  <testcase name=\"$jname\" classname=\"arcana.smoke\"/>" ;;
            skip)
                echo "  <testcase name=\"$jname\" classname=\"arcana.smoke\">"
                echo "    <skipped message=\"$(printf '%s' "$diag" | xml_escape)\"/>"
                echo "  </testcase>"
                ;;
            notok)
                echo "  <testcase name=\"$jname\" classname=\"arcana.smoke\">"
                echo "    <failure message=\"$(printf '%s' "$diag" | xml_escape)\"/>"
                echo "  </testcase>"
                ;;
        esac
    done
    echo "</testsuite>"
} >"$JUNIT"

echo "# JUnit: $JUNIT"

[ "$fails" -eq 0 ]
