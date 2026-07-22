#!/usr/bin/env bats
# Harness-of-the-harness for dev-tools/smoke/arcana-smoke.sh (ARAS-0040).
#
# Asserts the SCRIPT'S OWN contract — TAP plan line, per-stage ok/not-ok rows,
# the tri-state SKIP row, well-formed JUnit XML, and a clean exit — rather than
# re-testing the binary. It runs the real harness once (replay mode, no live
# mesh) in setup_file and inspects the captured artefacts.
#
# Usage: bats dev-tools/tests/arcana-smoke.bats

setup_file() {
    REPO="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    SMOKE="$REPO/dev-tools/smoke/arcana-smoke.sh"
    export REPO SMOKE

    # S0 needs the release binary; build it once if absent.
    if [ ! -x "$REPO/target/release/arcana" ]; then
        (cd "$REPO" && cargo build --release >/dev/null 2>&1)
    fi

    OUTDIR="$(mktemp -d)"
    export OUTDIR
    export TAP="$OUTDIR/tap.txt"
    export JUNIT="$OUTDIR/arcana-smoke.junit.xml"
    ARCANA_SMOKE_OUT="$OUTDIR" bash "$SMOKE" >"$TAP" 2>&1
    echo "$?" >"$OUTDIR/exit"
}

teardown_file() {
    rm -rf "$OUTDIR"
}

@test "harness exits 0 in replay mode (no live mesh)" {
    [ "$(cat "$OUTDIR/exit")" -eq 0 ]
}

@test "emits a TAP version 13 header" {
    head -1 "$TAP" | grep -qx "TAP version 13"
}

@test "emits a well-formed TAP plan line covering all rows" {
    plan="$(grep -E '^1\.\.[0-9]+$' "$TAP" | head -1)"
    [ -n "$plan" ]
    n="${plan#1..}"
    [ "$n" -ge 15 ]
    # The number of ok/not-ok rows must equal the plan count (no drift).
    rows="$(grep -cE '^(ok|not ok) ' "$TAP")"
    [ "$rows" -eq "$n" ]
}

@test "covers stages S0 through S5" {
    grep -qE '^ok [0-9]+ - S0 build-provenance' "$TAP"
    grep -qE '^(ok|not ok) [0-9]+ - S1 whoami' "$TAP"
    grep -qE '^(ok|not ok) [0-9]+ - S2 mc-ping' "$TAP"
    grep -qE '^(ok|not ok) [0-9]+ - S3 ' "$TAP"
    grep -qE '^(ok|not ok) [0-9]+ - S4 ' "$TAP"
    grep -qE '^(ok|not ok) [0-9]+ - S5 ' "$TAP"
}

@test "records a tri-state SKIP row (SKIP != green)" {
    grep -qE '# SKIP\(' "$TAP"
}

@test "the S1 deny stage asserts a Denied audit record naming the layer" {
    grep -qE '^ok [0-9]+ - S1 whoami-deny audit-Denied-record' "$TAP"
}

@test "the secret non-leak arm is present and green on an honest build" {
    grep -qE '^ok [0-9]+ - SEC no-secret-in-binary' "$TAP"
}

@test "asserts the real audit log is untouched (isolation)" {
    grep -qE '^ok [0-9]+ - ISO real-audit-log-untouched' "$TAP"
}

@test "writes a JUnit XML file" {
    [ -f "$JUNIT" ]
}

@test "the JUnit XML is well-formed and self-consistent" {
    python3 - "$JUNIT" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
assert root.tag == "testsuite", root.tag
tests = int(root.attrib["tests"])
cases = root.findall("testcase")
assert len(cases) == tests, (len(cases), tests)
failures = sum(1 for c in cases if c.find("failure") is not None)
skipped = sum(1 for c in cases if c.find("skipped") is not None)
assert failures == int(root.attrib["failures"]), (failures, root.attrib["failures"])
assert skipped == int(root.attrib["skipped"]), (skipped, root.attrib["skipped"])
PY
}

@test "the JUnit failure count matches the TAP not-ok count" {
    tap_fail="$(grep -cE '^not ok ' "$TAP" || true)"
    junit_fail="$(python3 -c "import xml.etree.ElementTree as ET,sys; print(ET.parse('$JUNIT').getroot().attrib['failures'])")"
    [ "$tap_fail" -eq "$junit_fail" ]
}
