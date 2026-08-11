#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
PROBE="$REPO_ROOT/packaging/tests/linux-live-containment.sh"

@test "live containment probe uses a bounded nondelegated cgroup service" {
    set -e
    [ -x "$PROBE" ]
    for contract in \
      'Type=exec' \
      'ExitType=cgroup' \
      'KillMode=control-group' \
      'Delegate=no' \
      'ProtectControlGroups=yes' \
      'SendSIGKILL=yes' \
      'RuntimeMaxSec=30s' \
      'TasksMax=32' \
      'MemoryMax=64M'; do
        grep -Fq "$contract" "$PROBE"
    done
}

@test "probe contains a causal process-group escape and cgroup teardown check" {
    set -e
    grep -Fq 'kill -- "-$leader_pid"' "$PROBE"
    grep -Fq 'marker advanced after process-group kill' "$PROBE"
    grep -Fq 'populated 0' "$PROBE"
    grep -Fq 'start time changed' "$PROBE"
    grep -Fq 'cgroup.procs write unexpectedly succeeded' "$PROBE"
}

@test "probe repeats and cleans only its uniquely named resources" {
    set -e
    grep -Fq 'for iteration in 1 2 3 4 5' "$PROBE"
    grep -Fq 'sec0030-containment-' "$PROBE"
    grep -Fq 'sudo -n systemctl reset-failed "$unit"' "$PROBE"
    grep -Fq 'sudo -n systemctl stop "$unit"' "$PROBE"
    grep -Fq 'systemd_property "$unit" LoadState' "$PROBE"
    grep -Fq 'systemd_property "$unit" ActiveState' "$PROBE"
    grep -Fq "grep -qx 'populated 0'" "$PROBE"
    ! grep -Fq 'systemctl is-active --quiet' "$PROBE"
    grep -Fq 'cleanup || status=1' "$PROBE"
    grep -Fq 'SEC0030_LINUX_CONTAINMENT_CLEANUP_PASS' "$PROBE"
}
