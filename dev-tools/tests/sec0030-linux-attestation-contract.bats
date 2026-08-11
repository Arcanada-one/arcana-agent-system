#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
PROBE="$REPO_ROOT/packaging/tests/linux-live-attestation.sh"
HARNESS="$REPO_ROOT/packaging/tests/fixtures/linux-seqpacket-attestation.py"
SENDER="$REPO_ROOT/packaging/tests/fixtures/linux-seqpacket-sender.c"

@test "live attestation probe requires real seqpacket credentials and enforcing AppArmor" {
    set -e
    [ -x "$PROBE" ]
    [ -f "$HARNESS" ]
    [ -f "$SENDER" ]
    grep -Fq 'SOCK_SEQPACKET' "$HARNESS"
    grep -Fq 'SO_PASSCRED' "$HARNESS"
    grep -Fq 'SCM_CREDENTIALS' "$HARNESS"
    grep -Fq '(enforce)' "$PROBE"
}

@test "fd-handoff negative control expects the actual sender and wrong-label denial" {
    set -e
    grep -Fq 'credential_pid != trusted.pid' "$HARNESS"
    grep -Fq 'wrong-label sender unexpectedly delivered a packet' "$HARNESS"
    grep -Fq 'deny unix (send) type=seqpacket' "$REPO_ROOT/packaging/tests/fixtures/sec0030-apparmor.profile.in"
}

@test "probe reports ancillary security-label availability without substituting sampled identity" {
    set -e
    grep -Fq 'credential_label_ancillary=' "$HARNESS"
    ! grep -Fq '/proc/' "$HARNESS"
    ! grep -Fq 'SO_PEERSEC' "$HARNESS"
    grep -Fq 'cleanup || status=1' "$PROBE"
    grep -Fq 'apparmor_parser -R "$profile_file"' "$PROBE"
    ! grep -Fq 'profile_loaded' "$PROBE"
    grep -Fq 'SEC0030_LINUX_ATTESTATION_CLEANUP_PASS' "$PROBE"
}

@test "bounded sender timeout reaps a hanging helper" {
    set -e
    python3 - "$HARNESS" <<'PY'
import importlib.util
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("sec0030_attestation", path)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
process = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
try:
    module.communicate_bounded(process, timeout=0.01)
except SystemExit as error:
    assert "sender timed out" in str(error)
else:
    raise AssertionError("hanging helper unexpectedly completed")
assert process.poll() is not None, "timed-out helper survived bounded cleanup"
PY
}
