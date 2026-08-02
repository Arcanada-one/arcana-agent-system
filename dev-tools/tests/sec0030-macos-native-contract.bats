#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
PROBE="$REPO_ROOT/packaging/tests/macos-live-xpc-sandbox.sh"
SERVER="$REPO_ROOT/packaging/tests/fixtures/macos-xpc-server.c"
CLIENT="$REPO_ROOT/packaging/tests/fixtures/macos-xpc-client.c"

@test "macOS proof uses message-bound XPC audit-token code validation" {
    [ -x "$PROBE" ]
    grep -Fq 'SecCodeCreateWithXPCMessage' "$SERVER"
    grep -Fq 'SecCodeCheckValidity' "$SERVER"
    grep -Fq 'xpc_connection_create_mach_service' "$SERVER"
    ! grep -Fq 'getpid' "$SERVER"
    ! grep -Fq '/proc/' "$SERVER"
}

@test "macOS XPC controls include exact signer identity and zero-handler negatives" {
    grep -Fq 'certificate leaf = H' "$PROBE"
    grep -Fq 'identifier "one.arcanada.sec0030.trusted"' "$PROBE"
    grep -Fq 'one.arcanada.sec0030.executor' "$PROBE"
    grep -Fq 'wrong signer or entitlement reached the accepted handler' "$PROBE"
    grep -Fq 'codesign --verify --strict' "$PROBE"
}

@test "macOS entitlement control uses sandbox inheritance with paired positive controls" {
    grep -Fq 'com.apple.security.app-sandbox' "$PROBE"
    grep -Fq 'com.apple.security.inherit' "$PROBE"
    grep -Fq 'sandbox positive control failed' "$PROBE"
    grep -Fq 'sandboxed descendant escaped' "$PROBE"
    grep -Fq 'launchctl bootout "$domain" "$launch_plist"' "$PROBE"
}
