#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
LIFECYCLE="$REPO_ROOT/packaging/broker-lifecycle.sh"

@test "macOS disable persists the override before unloading and proves endpoint absence" {
    set -e
    disable_line=$(grep -nF 'launchctl disable system/one.arcanada.credential-broker' "$LIFECYCLE" | cut -d: -f1)
    bootout_line=$(grep -nF 'launchctl bootout system/one.arcanada.credential-broker' "$LIFECYCLE" | cut -d: -f1)
    [ -n "$disable_line" ]
    [ -n "$bootout_line" ]
    [ "$disable_line" -lt "$bootout_line" ]
    grep -Fq 'launchctl print-disabled system' "$LIFECYCLE"
    grep -Fq 'launchd_broker_disabled || die' "$LIFECYCLE"
    grep -Fq '[ ! -S "$SOCKET_PATH" ] || die' "$LIFECYCLE"
}

@test "activation failure routes through the same terminal disable contract" {
    set -e
    grep -Fq 'disable_broker' "$LIFECYCLE"
    grep -Fq 'activation failed verification; terminal state is disabled' "$LIFECYCLE"
    grep -Fq 'rollback generation failed verification; terminal state is disabled' "$LIFECYCLE"
}

@test "Linux disable proves persistent unit state and endpoint absence" {
    set -e
    grep -Fq 'systemctl disable --now "$managed"' "$LIFECYCLE"
    grep -Fq 'systemctl show "$managed" --property=LoadState --value' "$LIFECYCLE"
    grep -Fq 'if [ "$load_state" = not-found ]' "$LIFECYCLE"
    grep -Fq '[ "$load_state" = loaded ] || die' "$LIFECYCLE"
    grep -Fq 'systemctl is-enabled "$managed"' "$LIFECYCLE"
    grep -Fq '[ "$enabled" = disabled ] || die' "$LIFECYCLE"
    grep -Fq 'systemctl show "$managed" --property=ActiveState --value' "$LIFECYCLE"
    grep -Fq '[ "$active" = inactive ] || die' "$LIFECYCLE"
    grep -Fq '[ ! -S "$SOCKET_PATH" ] || die "systemd broker socket remains after disable"' "$LIFECYCLE"
}
