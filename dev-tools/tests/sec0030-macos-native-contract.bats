#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
PROBE="$REPO_ROOT/packaging/tests/macos-live-xpc-sandbox.sh"
SERVER="$REPO_ROOT/packaging/tests/fixtures/macos-xpc-server.c"
CLIENT="$REPO_ROOT/packaging/tests/fixtures/macos-xpc-client.c"

@test "macOS proof uses message-bound XPC audit-token code validation" {
    set -e
    [ -x "$PROBE" ]
    grep -Fq 'SecCodeCreateWithXPCMessage' "$SERVER"
    grep -Fq 'SecCodeCheckValidity' "$SERVER"
    grep -Fq 'xpc_connection_create_mach_service' "$SERVER"
    ! grep -Fq 'getpid' "$SERVER"
    ! grep -Fq '/proc/' "$SERVER"
}

@test "macOS XPC controls include exact cdhash identity and zero-handler negatives" {
    set -e
    grep -Fq 'cdhash H' "$PROBE"
    grep -Fq 'identifier "one.arcanada.sec0030.trusted"' "$PROBE"
    grep -Fq 'wrong-code-hash fixture did not mutate code identity' "$PROBE"
    grep -Fq 'wrong code identity reached the accepted handler' "$PROBE"
    grep -Fq 'codesign --verify --strict' "$PROBE"
    ! grep -Eq 'security (add-trusted-cert|remove-trusted-cert|delete-certificate)' "$PROBE"
    ! grep -Fq '/Library/Keychains' "$PROBE"
}

@test "macOS entitlement control uses sandbox inheritance with paired positive controls" {
    set -e
    grep -Fq 'com.apple.security.app-sandbox' "$PROBE"
    grep -Fq 'com.apple.security.inherit' "$PROBE"
    grep -Fq 'adhoc_sign_binary one.arcanada.sec0030.sandbox' "$PROBE"
    grep -Fq 'sandbox positive control failed' "$PROBE"
    grep -Fq 'sandboxed descendant escaped' "$PROBE"
    grep -Fq 'launchctl bootout "$domain" "$launch_plist"' "$PROBE"
    grep -Fq 'if cleanup; then' "$PROBE"
    grep -Fq 'SEC0030_MACOS_NATIVE_CLEANUP_PASS' "$PROBE"
}

@test "native PASS is emitted only after cleanup succeeds" {
    set -e
    cleanup_line=$(grep -nF 'if cleanup; then' "$PROBE" | cut -d: -f1)
    pass_line=$(grep -nF "printf '%s\\n' 'SEC0030_MACOS_NATIVE_PASS" "$PROBE" | cut -d: -f1)
    [ -n "$cleanup_line" ]
    [ -n "$pass_line" ]
    [ "$cleanup_line" -lt "$pass_line" ]
    grep -Fq 'if (( status == 0 && probe_pass == 1 )); then' "$PROBE"
    [ "$(grep -Fc 'SEC0030_MACOS_NATIVE_PASS' "$PROBE")" -eq 1 ]
}
