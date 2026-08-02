#!/usr/bin/env bash
# Hosted-macOS native proof: XPC audit-token code identity plus inherited App
# Sandbox denial. All identities and keychains are ephemeral and test-only.
set -euo pipefail
IFS=$'\n\t'
umask 077

fail() {
  printf 'SEC0030_MACOS_NATIVE_FAIL: %s\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == Darwin ]] || fail 'macOS host required'
for tool in awk clang codesign launchctl log openssl perl plutil python3 security sudo; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool unavailable: $tool"
done
sudo -n true >/dev/null 2>&1 || fail 'non-interactive ephemeral trust authority required'

run_bounded() {
  local seconds="$1"
  shift
  perl -e '$timeout = shift @ARGV; alarm $timeout; exec @ARGV; exit 127' \
    "$seconds" "$@"
}

script_dir=$(cd "$(dirname "$0")" && pwd)
fixture_dir="$script_dir/fixtures"
scratch=$(mktemp -d /tmp/sec0030-macos-native.XXXXXX)
run_id="sec0030.$(date +%s).$$"
[[ "$run_id" =~ ^sec0030\.[0-9]+\.[0-9]+$ ]] || fail 'unsafe run identifier'
service="one.arcanada.$run_id.xpc"
keychain="$scratch/sec0030.keychain-db"
keychain_password="sec0030-ephemeral-$run_id"
launch_plist="$scratch/$service.plist"
domain=''
certificate_sha=''
listener_pid=''
original_keychains=()
while IFS= read -r original_keychain; do
  original_keychains+=("$original_keychain")
done < <(security list-keychains -d user | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//')
(( ${#original_keychains[@]} > 0 )) || fail 'user keychain search list is empty'

cleanup() {
  local cleanup_status=0 search_list_after certificates_after
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
  if (( ${#original_keychains[@]} > 0 )); then
    run_bounded 15 security list-keychains -d user -s "${original_keychains[@]}" \
      >/dev/null 2>&1 || cleanup_status=1
    if ! search_list_after=$(run_bounded 15 security list-keychains -d user 2>/dev/null); then
      cleanup_status=1
    elif grep -Fq "$keychain" <<<"$search_list_after"; then
      cleanup_status=1
    fi
  fi
  if [[ -f "$scratch/codesign.crt" && "$certificate_sha" =~ ^[0-9A-F]{40}$ ]]; then
    run_bounded 15 sudo -n security remove-trusted-cert -d \
      "$scratch/codesign.crt" >/dev/null 2>&1 || true
    run_bounded 15 sudo -n security delete-certificate -Z \
      "$certificate_sha" /Library/Keychains/System.keychain >/dev/null 2>&1 \
      || true
    if ! certificates_after=$(run_bounded 15 sudo -n security find-certificate -a -Z \
      /Library/Keychains/System.keychain 2>/dev/null); then
      cleanup_status=1
    elif grep -Fqi "$certificate_sha" <<<"$certificates_after"; then
      cleanup_status=1
    fi
    if ! run_bounded 15 sudo -n security dump-trust-settings -d \
      >"$scratch/admin-trust-after.txt" 2>/dev/null; then
      cleanup_status=1
    elif grep -Eqi "$certificate_sha|SEC0030 Ephemeral Code Signing" \
      "$scratch/admin-trust-after.txt"; then
      cleanup_status=1
    fi
  fi
  if [[ -e "$keychain" ]]; then
    security delete-keychain "$keychain" >/dev/null 2>&1 || cleanup_status=1
    [[ ! -e "$keychain" ]] || cleanup_status=1
  fi
  find "$scratch" -depth -mindepth 1 -delete || cleanup_status=1
  rmdir "$scratch" || cleanup_status=1
  if (( cleanup_status != 0 )); then
    printf '%s\n' 'SEC0030_MACOS_NATIVE_CLEANUP_FAIL' >&2
    return 1
  fi
  printf '%s\n' 'SEC0030_MACOS_NATIVE_CLEANUP_PASS launchd=absent listener=absent search_list=restored trusted_certificate=absent keychain=absent scratch=absent'
}
on_exit() {
  local status=$?
  trap - EXIT
  cleanup || status=1
  exit "$status"
}
trap on_exit EXIT

clang -O2 -Wall -Wextra -Werror -fblocks \
  -framework CoreFoundation -framework Security \
  -o "$scratch/xpc-server" "$fixture_dir/macos-xpc-server.c"
clang -O2 -Wall -Wextra -Werror -fblocks \
  -o "$scratch/xpc-client" "$fixture_dir/macos-xpc-client.c"
clang -O2 -Wall -Wextra -Werror \
  -o "$scratch/sandbox-parent" "$fixture_dir/macos-sandbox-parent.c"
clang -O2 -Wall -Wextra -Werror \
  -o "$scratch/sandbox-child" "$fixture_dir/macos-sandbox-child.c"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE binaries-built'

openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 \
  -keyout "$scratch/codesign.key" \
  -out "$scratch/codesign.crt" \
  -config "$fixture_dir/sec0030-code-signing-openssl.cnf" >/dev/null 2>&1
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE certificate-generated'
openssl pkcs12 -export \
  -inkey "$scratch/codesign.key" \
  -in "$scratch/codesign.crt" \
  -out "$scratch/codesign.p12" \
  -keypbe PBE-SHA1-3DES \
  -certpbe PBE-SHA1-3DES \
  -macalg sha1 \
  -passout "pass:$keychain_password" >/dev/null 2>&1
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE pkcs12-exported'
security create-keychain -p "$keychain_password" "$keychain"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE keychain-created'
security unlock-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 900 "$keychain"
security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
security import "$scratch/codesign.p12" \
  -k "$keychain" -P "$keychain_password" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -s \
  -k "$keychain_password" "$keychain" >/dev/null
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE identity-imported'
certificate_sha=$(openssl x509 -in "$scratch/codesign.crt" -noout -fingerprint -sha1 \
  | sed 's/^.*=//; s/://g')
[[ "$certificate_sha" =~ ^[0-9A-F]{40}$ ]] || fail 'ephemeral signing certificate unavailable'
run_bounded 15 sudo -n security add-trusted-cert -d -r trustRoot -p codeSign \
  -k /Library/Keychains/System.keychain "$scratch/codesign.crt"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE trust-added'
run_bounded 15 security find-identity -v -p codesigning "$keychain" | grep -Fqi "$certificate_sha" \
  || fail 'ephemeral code-signing identity unavailable'
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE certificate-derived'

sign_binary() {
  local identifier="$1" entitlements="$2" target="$3"
  if [[ -n "$entitlements" ]]; then
    codesign --force --sign 'SEC0030 Ephemeral Code Signing' \
      --identifier "$identifier" --entitlements "$entitlements" "$target" >/dev/null
  else
    codesign --force --sign 'SEC0030 Ephemeral Code Signing' \
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
cp "$scratch/xpc-client" "$scratch/trusted-client-copy"
cp "$scratch/xpc-client" "$scratch/wrong-identifier-client"
cp "$scratch/xpc-client" "$scratch/wrong-signer-client"
sign_binary one.arcanada.sec0030.trusted '' "$scratch/trusted-client"
sign_binary one.arcanada.sec0030.trusted '' "$scratch/trusted-client-copy"
sign_binary one.arcanada.sec0030.wrong '' "$scratch/wrong-identifier-client"
codesign --force --sign - --identifier one.arcanada.sec0030.trusted \
  "$scratch/wrong-signer-client" >/dev/null
codesign --verify --strict "$scratch/wrong-signer-client"
sign_binary one.arcanada.sec0030.server '' "$scratch/xpc-server"
printf '%s\n' 'SEC0030_MACOS_NATIVE_STAGE signatures-ready'

requirement='certificate leaf = H"'"$certificate_sha"'" and identifier "one.arcanada.sec0030.trusted"'
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
if "$scratch/wrong-signer-client" "$service" 1; then
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

printf '%s\n' 'SEC0030_MACOS_NATIVE_PASS xpc_exact_identity=3 xpc_wrong_identity=denied sandbox_descendant_file=denied sandbox_descendant_network=denied cleanup=pass'
