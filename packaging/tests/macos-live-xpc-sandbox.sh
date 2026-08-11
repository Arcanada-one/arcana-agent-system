#!/usr/bin/env bash
# Hosted-macOS native proof: XPC audit-token code identity plus inherited App
# Sandbox denial. All ad-hoc code identities are ephemeral and the host trust
# store is never mutated.
set -euo pipefail
IFS=$'\n\t'
umask 077

fail() {
  printf 'SEC0030_MACOS_NATIVE_FAIL: %s\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == Darwin ]] || fail 'macOS host required'
for tool in awk clang codesign launchctl log plutil python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool unavailable: $tool"
done

script_dir=$(cd "$(dirname "$0")" && pwd)
fixture_dir="$script_dir/fixtures"
scratch=$(mktemp -d /tmp/sec0030-macos-native.XXXXXX)
run_id="sec0030.$(date +%s).$$"
[[ "$run_id" =~ ^sec0030\.[0-9]+\.[0-9]+$ ]] || fail 'unsafe run identifier'
service="one.arcanada.$run_id.xpc"
launch_plist="$scratch/$service.plist"
domain=''
listener_pid=''
probe_pass=0

cleanup() {
  local cleanup_status=0
  if [[ "$listener_pid" =~ ^[1-9][0-9]*$ ]]; then
    if kill -0 "$listener_pid" >/dev/null 2>&1; then
      kill "$listener_pid" >/dev/null 2>&1 || cleanup_status=1
    fi
    for _ in {1..100}; do
      kill -0 "$listener_pid" >/dev/null 2>&1 || break
      sleep 0.01
    done
    if kill -0 "$listener_pid" >/dev/null 2>&1; then
      kill -KILL "$listener_pid" >/dev/null 2>&1 || cleanup_status=1
    fi
    for _ in {1..100}; do
      kill -0 "$listener_pid" >/dev/null 2>&1 || break
      sleep 0.01
    done
    if kill -0 "$listener_pid" >/dev/null 2>&1; then
      cleanup_status=1
    else
      wait "$listener_pid" >/dev/null 2>&1 || true
    fi
    listener_pid=''
  fi
  if [[ -n "$domain" && -f "$launch_plist" ]]; then
    launchctl bootout "$domain" "$launch_plist" >/dev/null 2>&1 || true
    if launchctl print "$domain/$service" >/dev/null 2>&1; then
      printf 'SEC0030_MACOS_NATIVE_FAIL: launchd cleanup did not remove exact service\n' >&2
      cleanup_status=1
    fi
  fi
  find "$scratch" -depth -mindepth 1 -delete || cleanup_status=1
  rmdir "$scratch" || cleanup_status=1
  if (( cleanup_status != 0 )); then
    printf '%s\n' 'SEC0030_MACOS_NATIVE_CLEANUP_FAIL' >&2
    return 1
  fi
  printf '%s\n' 'SEC0030_MACOS_NATIVE_CLEANUP_PASS launchd=absent listener=absent trust_store=untouched scratch=absent'
}
on_exit() {
  local status=$?
  trap - EXIT
  if cleanup; then
    if (( status == 0 && probe_pass == 1 )); then
      printf '%s\n' 'SEC0030_MACOS_NATIVE_PASS xpc_exact_identity=3 xpc_wrong_identity=denied sandbox_descendant_file=denied sandbox_descendant_network=denied cleanup=pass'
    fi
  else
    status=1
  fi
  exit "$status"
}
trap on_exit EXIT

clang -O2 -Wall -Wextra -Werror -fblocks \
  -framework CoreFoundation -framework Security \
  -o "$scratch/xpc-server" "$fixture_dir/macos-xpc-server.c"
clang -O2 -Wall -Wextra -Werror -fblocks \
  -o "$scratch/xpc-client" "$fixture_dir/macos-xpc-client.c"
clang -O2 -Wall -Wextra -Werror -fblocks -DSEC0030_BUILD_VARIANT=1 \
  -o "$scratch/xpc-client-variant" "$fixture_dir/macos-xpc-client.c"
clang -O2 -Wall -Wextra -Werror \
  -o "$scratch/sandbox-parent" "$fixture_dir/macos-sandbox-parent.c"
clang -O2 -Wall -Wextra -Werror \
  -o "$scratch/sandbox-child" "$fixture_dir/macos-sandbox-child.c"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE binaries-built'

sign_binary() {
  local identifier="$1" entitlements="$2" target="$3"
  if [[ -n "$entitlements" ]]; then
    codesign --force --sign - \
      --identifier "$identifier" --entitlements "$entitlements" "$target" >/dev/null
  else
    codesign --force --sign - \
      --identifier "$identifier" "$target" >/dev/null
  fi
  codesign --verify --strict "$target"
}

adhoc_sign_binary() {
  local identifier="$1" entitlements="$2" target="$3"
  codesign --force --sign - --identifier "$identifier" \
    --entitlements "$entitlements" "$target" >/dev/null
  codesign --verify --strict "$target"
}

cp "$scratch/xpc-client" "$scratch/trusted-client"
cp "$scratch/xpc-client" "$scratch/wrong-identifier-client"
cp "$scratch/xpc-client-variant" "$scratch/wrong-code-hash-client"
sign_binary one.arcanada.sec0030.trusted '' "$scratch/trusted-client"
cp "$scratch/trusted-client" "$scratch/trusted-client-copy"
sign_binary one.arcanada.sec0030.wrong '' "$scratch/wrong-identifier-client"
sign_binary one.arcanada.sec0030.trusted '' "$scratch/wrong-code-hash-client"
sign_binary one.arcanada.sec0030.server '' "$scratch/xpc-server"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE signatures-ready'

trusted_cdhash=$(codesign -d --verbose=4 "$scratch/trusted-client" 2>&1 \
  | awk -F= '/^CDHash=/ {print $2; exit}')
[[ "$trusted_cdhash" =~ ^[0-9a-fA-F]{40}$ ]] || fail 'trusted XPC client cdhash unavailable'
wrong_cdhash=$(codesign -d --verbose=4 "$scratch/wrong-code-hash-client" 2>&1 \
  | awk -F= '/^CDHash=/ {print $2; exit}')
[[ "$wrong_cdhash" =~ ^[0-9a-fA-F]{40}$ ]] || fail 'negative XPC client cdhash unavailable'
[[ "$wrong_cdhash" != "$trusted_cdhash" ]] || fail 'wrong-code-hash fixture did not mutate code identity'
requirement='cdhash H"'"$trusted_cdhash"'" and identifier "one.arcanada.sec0030.trusted"'
counter="$scratch/accepted-count"
sed \
  -e "s|@@SERVICE@@|$service|g" \
  -e "s|@@SERVER@@|$scratch/xpc-server|g" \
  -e "s|@@REQUIREMENT@@|$requirement|g" \
  -e "s|@@COUNTER@@|$counter|g" \
  "$fixture_dir/sec0030-launch-agent.plist.in" > "$launch_plist"
plutil -lint "$launch_plist" >/dev/null
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE launch-agent-prepared'
uid=$(id -u)
if launchctl print "gui/$uid" >/dev/null 2>&1; then
  domain="gui/$uid"
else
  domain="user/$uid"
fi
launchctl bootstrap "$domain" "$launch_plist"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE launch-agent-bootstrapped'
launchctl kickstart -k "$domain/$service"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE launch-agent-kickstarted'
for _ in {1..100}; do
  launchctl print "$domain/$service" >/dev/null 2>&1 && break
  sleep 0.05
done
launchctl print "$domain/$service" >/dev/null 2>&1 || fail 'XPC launch agent did not start'
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE xpc-service-ready'

printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE trusted-client-start'
set +e
"$scratch/trusted-client" "$service" 2
trusted_client_status=$?
set -e
if (( trusted_client_status != 0 )); then
  printf 'SEC0030_MACOS_NATIVE_DIAGNOSTIC trusted_client_status=%s\n' "$trusted_client_status" >&2
  log show --last 1m --style compact \
    --predicate '(process == "trusted-client") OR (process == "taskgated-helper") OR (process == "amfid") OR (process == "syspolicyd") OR (subsystem == "com.apple.xpc")' \
    | tail -n 80 >&2 || true
  fail 'trusted XPC client did not complete'
fi
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE trusted-client-pass messages=2'
"$scratch/trusted-client-copy" "$service" 1
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE trusted-client-copy-pass messages=1'
before_negative=$(awk 'END {print NR}' "$counter")
[[ "$before_negative" == 3 ]] || fail 'trusted XPC messages did not reach the accepted handler'
if "$scratch/wrong-identifier-client" "$service" 1; then
  fail 'wrong code identity was accepted'
fi
if "$scratch/wrong-code-hash-client" "$service" 1; then
  fail 'wrong code identity was accepted'
fi
after_negative=$(awk 'END {print NR}' "$counter")
[[ "$after_negative" == "$before_negative" ]] || fail 'wrong code identity reached the accepted handler'

# Pair every App Sandbox denial with an unsandboxed positive control while the
# same file and loopback listener are available.
sentinel="$scratch/outside-sandbox-sentinel"
printf '%s\n' sec0030 > "$sentinel"
port_file="$scratch/listener-port"
network_count="$scratch/network-count"
python3 - "$port_file" "$network_count" <<'PY' &
import socket
from pathlib import Path
import sys
import time

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(2)
listener.settimeout(4)
Path(sys.argv[1]).write_text(str(listener.getsockname()[1]) + "\n", encoding="ascii")
count = 0
deadline = time.monotonic() + 4
while time.monotonic() < deadline:
    try:
        connection, _ = listener.accept()
    except TimeoutError:
        break
    connection.close()
    count += 1
Path(sys.argv[2]).write_text(str(count) + "\n", encoding="ascii")
PY
listener_pid=$!
for _ in {1..100}; do
  [[ -s "$port_file" ]] && break
  sleep 0.05
done
[[ -s "$port_file" ]] || fail 'loopback positive-control listener did not start'
port=$(<"$port_file")

cp "$scratch/sandbox-child" "$scratch/unsandboxed-child"
sign_binary one.arcanada.sec0030.unsandboxed-child '' "$scratch/unsandboxed-child"
positive=$("$scratch/unsandboxed-child" "$sentinel" "$port" 1)
[[ "$positive" == 'file=allowed network=allowed' ]] || fail 'sandbox positive control failed'

app="$scratch/SEC0030Sandbox.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers"
cp "$scratch/sandbox-parent" "$app/Contents/MacOS/SEC0030Sandbox"
cp "$scratch/sandbox-child" "$app/Contents/Helpers/SEC0030SandboxChild"
/usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string one.arcanada.sec0030.sandbox' \
  -c 'Add :CFBundleExecutable string SEC0030Sandbox' \
  -c 'Add :CFBundlePackageType string APPL' \
  "$app/Contents/Info.plist"
adhoc_sign_binary one.arcanada.sec0030.sandbox-child "$fixture_dir/sec0030-sandbox-child.entitlements" \
  "$app/Contents/Helpers/SEC0030SandboxChild"
adhoc_sign_binary one.arcanada.sec0030.sandbox "$fixture_dir/sec0030-sandbox-parent.entitlements" \
  "$app/Contents/MacOS/SEC0030Sandbox"
codesign --force --sign - \
  --identifier one.arcanada.sec0030.sandbox \
  --entitlements "$fixture_dir/sec0030-sandbox-parent.entitlements" "$app" >/dev/null
codesign --verify --strict --deep "$app"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE sandbox-app-signed'
codesign -d --entitlements :- "$app/Contents/MacOS/SEC0030Sandbox" \
  > "$scratch/parent-entitlements.plist" 2>/dev/null
codesign -d --entitlements :- "$app/Contents/Helpers/SEC0030SandboxChild" \
  > "$scratch/child-entitlements.plist" 2>/dev/null
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE sandbox-entitlements-extracted'
plutil -p "$scratch/parent-entitlements.plist"
plutil -p "$scratch/child-entitlements.plist"
python3 - "$scratch/parent-entitlements.plist" "$scratch/child-entitlements.plist" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    parent = plistlib.load(stream)
with open(sys.argv[2], "rb") as stream:
    child = plistlib.load(stream)
if parent.get("com.apple.security.app-sandbox") is not True:
    raise SystemExit("parent App Sandbox entitlement is not boolean true")
if child.get("com.apple.security.app-sandbox") is not True:
    raise SystemExit("child App Sandbox entitlement is not boolean true")
if child.get("com.apple.security.inherit") is not True:
    raise SystemExit("child sandbox inheritance entitlement is not boolean true")
PY
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE sandbox-entitlements-verified'

set +e
sandbox_result=$("$app/Contents/MacOS/SEC0030Sandbox" \
  "$app/Contents/Helpers/SEC0030SandboxChild" "$sentinel" "$port")
sandbox_status=$?
set -e
if (( sandbox_status != 0 )); then
  printf 'SEC0030_MACOS_NATIVE_DIAGNOSTIC sandbox_parent_status=%s\n' "$sandbox_status" >&2
  log show --last 1m --style compact \
    --predicate '(process == "SEC0030Sandbox") OR (process == "SEC0030SandboxChild") OR (process == "taskgated-helper") OR (process == "amfid") OR (process == "syspolicyd") OR (subsystem == "com.apple.sandbox")' \
    | tail -n 80 >&2 || true
  fail 'sandbox parent did not complete'
fi
[[ "$sandbox_result" == 'file=denied network=denied' ]] || fail 'sandboxed descendant escaped'
for _ in {1..500}; do
  kill -0 "$listener_pid" >/dev/null 2>&1 || break
  sleep 0.01
done
kill -0 "$listener_pid" >/dev/null 2>&1 && fail 'paired loopback listener did not terminate'
wait "$listener_pid"
listener_pid=''
[[ "$(<"$network_count")" == 1 ]] || fail 'sandboxed descendant reached the paired loopback endpoint'

launchctl bootout "$domain" "$launch_plist"
if launchctl print "$domain/$service" >/dev/null 2>&1; then
  fail 'launchd service remained after exact bootout'
fi

probe_pass=1
