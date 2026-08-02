#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
PROBE="$REPO_ROOT/packaging/tests/linux-live-attestation.sh"
HARNESS="$REPO_ROOT/packaging/tests/fixtures/linux-seqpacket-attestation.py"
SENDER="$REPO_ROOT/packaging/tests/fixtures/linux-seqpacket-sender.c"

@test "live attestation probe requires real seqpacket credentials and enforcing AppArmor" {
    [ -x "$PROBE" ]
    [ -f "$HARNESS" ]
    [ -f "$SENDER" ]
    grep -Fq 'SOCK_SEQPACKET' "$HARNESS"
    grep -Fq 'SO_PASSCRED' "$HARNESS"
    grep -Fq 'SCM_CREDENTIALS' "$HARNESS"
    grep -Fq '(enforce)' "$PROBE"
}

@test "fd-handoff negative control expects the actual sender and wrong-label denial" {
    grep -Fq 'credential_pid != trusted.pid' "$HARNESS"
    grep -Fq 'wrong-label sender unexpectedly delivered a packet' "$HARNESS"
    grep -Fq 'deny unix (send) type=seqpacket' "$REPO_ROOT/packaging/tests/fixtures/sec0030-apparmor.profile.in"
}

@test "probe reports ancillary security-label availability without substituting sampled identity" {
    grep -Fq 'credential_label_ancillary=' "$HARNESS"
    ! grep -Fq '/proc/' "$HARNESS"
    ! grep -Fq 'SO_PEERSEC' "$HARNESS"
}
