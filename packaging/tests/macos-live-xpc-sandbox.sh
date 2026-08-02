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
for tool in clang codesign launchctl openssl plutil security; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool unavailable: $tool"
done

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
bootstrapped=0
keychain_created=0

cleanup() {
  if (( bootstrapped == 1 )); then
    launchctl bootout "$domain" "$launch_plist" >/dev/null 2>&1 || true
    if launchctl print "$domain/$service" >/dev/null 2>&1; then
      printf 'SEC0030_MACOS_NATIVE_FAIL: launchd cleanup did not remove exact service\n' >&2
    fi
  fi
  if (( keychain_created == 1 )); then
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
  fi
  find "$scratch" -depth -mindepth 1 -delete
  rmdir "$scratch"
}
trap cleanup EXIT

clang -O2 -Wall -Wextra -Werror -fblocks \
  -framework CoreFoundation -framework Security \
  -o "$scratch/xpc-server" "$fixture_dir/macos-xpc-server.c"
clang -O2 -Wall -Wextra -Werror -fblocks \
  -o "$scratch/xpc-client" "$fixture_dir/macos-xpc-client.c"
clang -O2 -Wall -Wextra -Werror \
  -o "$scratch/sandbox-parent" "$fixture_dir/macos-sandbox-parent.c"
clang -O2 -Wall -Wextra -Werror \
  -o "$scratch/sandbox-child" "$fixture_dir/macos-sandbox-child.c"

openssl req -new -newkey rsa:2048 -nodes -x509 -days 1 \
  -keyout "$scratch/codesign.key" \
  -out "$scratch/codesign.crt" \
  -config "$fixture_dir/sec0030-code-signing-openssl.cnf" >/dev/null 2>&1
openssl pkcs12 -export \
  -inkey "$scratch/codesign.key" \
  -in "$scratch/codesign.crt" \
  -out "$scratch/codesign.p12" \
  -passout "pass:$keychain_password" >/dev/null 2>&1
security create-keychain -p "$keychain_password" "$keychain"
keychain_created=1
security unlock-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 900 "$keychain"
security import "$scratch/codesign.p12" \
  -k "$keychain" -P "$keychain_password" -T /usr/bin/codesign >/dev/null
certificate_sha=$(openssl x509 -in "$scratch/codesign.crt" -noout -fingerprint -sha1 \
  | sed 's/^.*=//; s/://g')
[[ "$certificate_sha" =~ ^[0-9A-F]{40}$ ]] || fail 'ephemeral signing certificate unavailable'

sign_binary() {
  local identifier="$1" entitlements="$2" target="$3"
  codesign --force --keychain "$keychain" --sign "$certificate_sha" \
    --identifier "$identifier" --entitlements "$entitlements" "$target" >/dev/null
  codesign --verify --strict "$target"
}

cp "$scratch/xpc-client" "$scratch/trusted-client"
cp "$scratch/xpc-client" "$scratch/trusted-client-copy"
cp "$scratch/xpc-client" "$scratch/wrong-identifier-client"
cp "$scratch/xpc-client" "$scratch/missing-entitlement-client"
sign_binary one.arcanada.sec0030.trusted "$fixture_dir/sec0030-trusted.entitlements" "$scratch/trusted-client"
sign_binary one.arcanada.sec0030.trusted "$fixture_dir/sec0030-trusted.entitlements" "$scratch/trusted-client-copy"
sign_binary one.arcanada.sec0030.wrong "$fixture_dir/sec0030-trusted.entitlements" "$scratch/wrong-identifier-client"
codesign --force --keychain "$keychain" --sign "$certificate_sha" \
  --identifier one.arcanada.sec0030.trusted "$scratch/missing-entitlement-client" >/dev/null
codesign --verify --strict "$scratch/missing-entitlement-client"
sign_binary one.arcanada.sec0030.server "$fixture_dir/sec0030-trusted.entitlements" "$scratch/xpc-server"

requirement='certificate leaf = H"'"$certificate_sha"'" and identifier "one.arcanada.sec0030.trusted" and entitlement["one.arcanada.sec0030.executor"] = true'
counter="$scratch/accepted-count"
sed \
  -e "s|@@SERVICE@@|$service|g" \
  -e "s|@@SERVER@@|$scratch/xpc-server|g" \
  -e "s|@@REQUIREMENT@@|$requirement|g" \
  -e "s|@@COUNTER@@|$counter|g" \
  "$fixture_dir/sec0030-launch-agent.plist.in" > "$launch_plist"
plutil -lint "$launch_plist" >/dev/null
uid=$(id -u)
if launchctl print "gui/$uid" >/dev/null 2>&1; then
  domain="gui/$uid"
else
  domain="user/$uid"
fi
launchctl bootstrap "$domain" "$launch_plist"
bootstrapped=1
launchctl kickstart -k "$domain/$service"
for _ in {1..100}; do
  launchctl print "$domain/$service" >/dev/null 2>&1 && break
  sleep 0.05
done
launchctl print "$domain/$service" >/dev/null 2>&1 || fail 'XPC launch agent did not start'

"$scratch/trusted-client" "$service" 2
"$scratch/trusted-client-copy" "$service" 1
before_negative=$(wc -l < "$counter")
[[ "$before_negative" == 3 ]] || fail 'trusted XPC messages did not reach the accepted handler'
if "$scratch/wrong-identifier-client" "$service" 1; then
  fail 'wrong signer or entitlement was accepted'
fi
if "$scratch/missing-entitlement-client" "$service" 1; then
  fail 'wrong signer or entitlement was accepted'
fi
after_negative=$(wc -l < "$counter")
[[ "$after_negative" == "$before_negative" ]] || fail 'wrong signer or entitlement reached the accepted handler'

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
sign_binary one.arcanada.sec0030.unsandboxed-child "$fixture_dir/sec0030-trusted.entitlements" "$scratch/unsandboxed-child"
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
sign_binary one.arcanada.sec0030.sandbox-child "$fixture_dir/sec0030-sandbox-child.entitlements" \
  "$app/Contents/Helpers/SEC0030SandboxChild"
sign_binary one.arcanada.sec0030.sandbox "$fixture_dir/sec0030-sandbox-parent.entitlements" \
  "$app/Contents/MacOS/SEC0030Sandbox"
codesign --force --keychain "$keychain" --sign "$certificate_sha" \
  --identifier one.arcanada.sec0030.sandbox \
  --entitlements "$fixture_dir/sec0030-sandbox-parent.entitlements" "$app" >/dev/null
codesign --verify --strict --deep "$app"
codesign -d --entitlements :- "$app/Contents/MacOS/SEC0030Sandbox" \
  > "$scratch/parent-entitlements.plist" 2>/dev/null
codesign -d --entitlements :- "$app/Contents/Helpers/SEC0030SandboxChild" \
  > "$scratch/child-entitlements.plist" 2>/dev/null
plutil -extract com.apple.security.app-sandbox raw "$scratch/parent-entitlements.plist" | grep -qx true
plutil -extract com.apple.security.app-sandbox raw "$scratch/child-entitlements.plist" | grep -qx true
plutil -extract com.apple.security.inherit raw "$scratch/child-entitlements.plist" | grep -qx true

sandbox_result=$("$app/Contents/MacOS/SEC0030Sandbox" \
  "$app/Contents/Helpers/SEC0030SandboxChild" "$sentinel" "$port")
[[ "$sandbox_result" == 'file=denied network=denied' ]] || fail 'sandboxed descendant escaped'
wait "$listener_pid"
[[ "$(<"$network_count")" == 1 ]] || fail 'sandboxed descendant reached the paired loopback endpoint'

launchctl bootout "$domain" "$launch_plist"
bootstrapped=0
if launchctl print "$domain/$service" >/dev/null 2>&1; then
  fail 'launchd service remained after exact bootout'
fi

printf '%s\n' 'SEC0030_MACOS_NATIVE_PASS xpc_exact_identity=3 xpc_wrong_identity=denied sandbox_descendant_file=denied sandbox_descendant_network=denied cleanup=pass'
