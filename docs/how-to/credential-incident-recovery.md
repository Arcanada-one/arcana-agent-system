# How to recover from a provider-credential exposure

This is the runbook for the case where a provider API credential has reached an
agent's environment and been emitted into terminal output or durable
transcripts. It is written from a real incident; the ordering is not arbitrary.

## The two rules that matter most

**A balance failure is not a revocation.** If the provider returns `402
Insufficient Balance` on a billable call but `200` on a metadata call, the
credential still authenticates. Its authority returns the moment anyone funds
the account — which does not require holding the key. Never record an exhausted
balance as invalidation.

**Deleting a local copy is not a retraction.** Redacting transcripts reduces the
number of places the value sits. It does nothing to the credential's validity.
Only the provider authority can do that.

## Order of operations

Copy cleanup and rotation are sequenced deliberately.

1. **Stop credentialed execution.** Do not restart a credential-bearing
   executor until step 4 is authoritative.
2. **Inventory copies.** Paths and counts only — never content. Classify each
   copy as *inert* (transcripts, shell snapshots, file history) or
   *distribution* (shell rc, env files, secret stores).
3. **Redact inert copies now.** They serve no consumer, so removing them cannot
   break anything. Do this immediately; every hour they persist is exposure.
4. **Rotate at the provider.** Create the replacement, then invalidate the old
   credential, then prove the old one is rejected and the new one works — with
   status codes only.
5. **Distribute the replacement through the canonical secret store**, never back
   into shell rc or env files.
6. **Only then remove the distribution copies**, and restart every dependent
   process.

Step 6 comes last because removing the distribution path before a replacement
exists leaves the host with no credential path at all and no way to restore one.
Step 3 does not have that problem, which is why it does not wait.

Do not create a dummy value at the production destination merely to make the
path “exist.” A placeholder creates a real secret version, can make consumers
mistake path existence for credential readiness, and pollutes the audit/version
history. It is safe to pre-stage policy or metadata only when data reads still
report absent. The first data version at the destination must be the actual
console-issued replacement, written with the store's create-only/CAS guard.

For a new KV-v2 destination, use the single Mac-side handoff below. It [creates
blank metadata][vault-kv-metadata] with check-and-set required, then performs
the first [create-only data write][vault-kv-put]. Run it only on the trusted
physical Mac in a local desktop session with input auditing and screen/session
recording disabled. Never run it through an agent, SSH, tmux, `script`, CI, or
a recorded terminal. Do not use the clipboard.

Keep topology and destination pins out of the shipped repository. Before
rotation, install these operator-private assets:

- `/Library/SEC0030/Tailscale.app`: a notarized copy of the official app,
  recursively `root:wheel`, with no symlinks, ACLs, or group/world-writable
  entries.
- `/Library/SEC0030/vault-handoff.env`: a non-symlink `root:wheel` mode-0600
  file containing exactly the six assignments below, populated with private
  values rather than the placeholders shown:

```text
VAULT_IP=<vault-tailnet-ip>
VAULT_NODE_KEY=<vault-tailnet-node-key>
VAULT_DNS=<vault-tailnet-dns-name>
VAULT_VERSION=<vault-server-version>
VAULT_MOUNT=<tenant-kv-mount>
VAULT_SECRET_PATH=<provider-secret-path>
```

Vault may intentionally serve plain HTTP inside a tailnet. Before either
hidden credential prompt and every authenticated request, this handoff verifies
the pinned Apple requirement and notarization, exact peer identity, local
Tailscale interface, ICMP-over-WireGuard reachability, and route-bound Vault
health. Every request is bound to that interface. Exact response codes and
metadata are validated before PASS. The clean shell uses an empty home and
absolute macOS system binaries; `curl -q` loads no user configuration and both
credentials reach it through pipes, never argv or the environment:

```sh
/usr/bin/env -i \
  HOME=/var/empty \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  TERM=dumb \
  /bin/bash --noprofile --norc <<'SEC0030_VAULT_HANDOFF'
set -euo pipefail
set +x
ulimit -c 0
private_root=/Library/SEC0030
private_config=$private_root/vault-handoff.env
tailscale_app=$private_root/Tailscale.app
tailscale_bin=$tailscale_app/Contents/MacOS/Tailscale

no_acl() {
  test "$(/bin/ls -lde "$1" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 1
}
for directory in /Library "$private_root"; do
  test ! -L "$directory"
  test "$(/usr/bin/stat -f '%Su:%Sg:%Sp' "$directory")" = \
    'root:wheel:drwxr-xr-x'
  no_acl "$directory"
done
test ! -L "$private_config"
test "$(/usr/bin/stat -f '%Su:%Sg:%Sp' "$private_config")" = \
  'root:wheel:-rw-------'
no_acl "$private_config"

while IFS= read -r -d '' item; do
  test ! -L "$item"
  test "$(/usr/bin/stat -f '%Su:%Sg' "$item")" = 'root:wheel'
  permissions=$(/usr/bin/stat -f '%Sp' "$item")
  case "$permissions" in
    ?????w????|????????w?) exit 1 ;;
  esac
  no_acl "$item"
done < <(/usr/bin/find "$tailscale_app" -print0)

vault_ip=
vault_node_key=
vault_dns=
vault_version=
vault_mount=
vault_secret_path=
seen='|'
while IFS='=' read -r key value; do
  case "$seen" in *"|${key}|"*) exit 1 ;; esac
  seen="${seen}${key}|"
  case "$key" in
    VAULT_IP) vault_ip=$value ;;
    VAULT_NODE_KEY) vault_node_key=$value ;;
    VAULT_DNS) vault_dns=$value ;;
    VAULT_VERSION) vault_version=$value ;;
    VAULT_MOUNT) vault_mount=$value ;;
    VAULT_SECRET_PATH) vault_secret_path=$value ;;
    *) exit 1 ;;
  esac
done < "$private_config"
test "$seen" = \
  '|VAULT_IP|VAULT_NODE_KEY|VAULT_DNS|VAULT_VERSION|VAULT_MOUNT|VAULT_SECRET_PATH|'
builtin printf '%s' "$vault_ip" |
  /usr/bin/grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
builtin printf '%s' "$vault_node_key" |
  /usr/bin/grep -Eq '^nodekey:[0-9a-f]{64}$'
case "$vault_dns" in ''|*[!A-Za-z0-9.-]*) exit 1 ;; esac
case "$vault_version" in ''|*[!A-Za-z0-9.+-]*) exit 1 ;; esac
case "$vault_mount" in ''|*[!A-Za-z0-9_-]*) exit 1 ;; esac
case "$vault_secret_path" in ''|/*|*/|*..*|*[!A-Za-z0-9_/-]*) exit 1 ;; esac

signature=$(/usr/bin/codesign -dv --verbose=4 "$tailscale_app" 2>&1)
identifier=$(builtin printf '%s\n' "$signature" |
  /usr/bin/awk -F= '$1 == "Identifier" {print $2}')
case "$identifier" in
  io.tailscale.ipn.macsys|io.tailscale.ipn.macos) ;;
  *) exit 1 ;;
esac
requirement="anchor apple generic and certificate leaf[subject.OU] = \"W5364U7YZB\" and identifier \"${identifier}\""
/usr/bin/codesign --verify --deep --strict --check-notarization \
  -R="$requirement" "$tailscale_app"
/usr/sbin/spctl --assess --type execute "$tailscale_app"

peer_value() {
  builtin printf '%s' "$status_json" |
    /usr/bin/plutil -extract "Peer.${vault_node_key}.$1" raw -o - -
}
assert_tailnet_path() {
  local self_ip health_response health_status health_body
  status_json=$("$tailscale_bin" status --json)
  test "$(peer_value DNSName)" = "$vault_dns"
  test "$(peer_value TailscaleIPs.0)" = "$vault_ip"
  test "$(peer_value Online)" = true
  self_ip=$(builtin printf '%s' "$status_json" |
    /usr/bin/plutil -extract Self.TailscaleIPs.0 raw -o - -)
  route_interface=$(/sbin/route -n get "$vault_ip" |
    /usr/bin/awk '$1 == "interface:" {print $2; exit}')
  case "$route_interface" in
    utun[0-9]*) ;;
    *) exit 1 ;;
  esac
  /sbin/ifconfig "$route_interface" |
    /usr/bin/awk -v expected="$self_ip" '
      $1 == "inet" && $2 == expected {found = 1}
      END {exit found ? 0 : 1}
    '
  "$tailscale_bin" ping --icmp --c=1 --timeout=5s "$vault_ip" >/dev/null
  health_response=$(/usr/bin/curl -q --silent --show-error \
    --connect-timeout 5 --max-time 10 \
    --max-redirs 0 --proto '=http' \
    --interface "$route_interface" \
    --write-out $'\n%{http_code}' \
    "http://${vault_ip}:8200/v1/sys/health")
  health_status=${health_response##*$'\n'}
  health_body=${health_response%$'\n'*}
  test "$health_status" = 200
  test "$(builtin printf '%s' "$health_body" |
    /usr/bin/plutil -extract initialized raw -o - -)" = true
  test "$(builtin printf '%s' "$health_body" |
    /usr/bin/plutil -extract sealed raw -o - -)" = false
  test "$(builtin printf '%s' "$health_body" |
    /usr/bin/plutil -extract version raw -o - -)" = "$vault_version"
}

assert_tailnet_path

vault_token=$(/usr/bin/osascript -e \
  'text returned of (display dialog "Authorized Vault token" default answer "" with hidden answer buttons {"Continue"} default button "Continue")')
case "$vault_token" in
  ''|*[!A-Za-z0-9._-]*) exit 1 ;;
esac
test "${#vault_token}" -ge 20

vault_request() {
  local method=$1 endpoint=$2 body=$3 response
  assert_tailnet_path
  if [ "$method" = POST ]; then
    response=$(builtin printf '%s' "$body" |
      /usr/bin/curl -q --silent --show-error \
        --connect-timeout 5 --max-time 10 \
        --max-redirs 0 --proto '=http' \
        --interface "$route_interface" \
        --request POST \
        --url "http://${vault_ip}:8200${endpoint}" \
        --config /dev/fd/3 \
        --header 'Content-Type: application/json' \
        --data-binary @- \
        --write-out $'\n%{http_code}' \
        3< <(builtin printf 'header = "X-Vault-Token: %s"\n' "$vault_token"))
  else
    test "$method" = GET
    response=$(/usr/bin/curl -q --silent --show-error \
      --connect-timeout 5 --max-time 10 \
      --max-redirs 0 --proto '=http' \
      --interface "$route_interface" \
      --request GET \
      --url "http://${vault_ip}:8200${endpoint}" \
      --config /dev/fd/3 \
      --write-out $'\n%{http_code}' \
      3< <(builtin printf 'header = "X-Vault-Token: %s"\n' "$vault_token"))
  fi
  vault_status=${response##*$'\n'}
  vault_body=${response%$'\n'*}
}

metadata_endpoint="/v1/${vault_mount}/metadata/${vault_secret_path}"
data_endpoint="/v1/${vault_mount}/data/${vault_secret_path}"
vault_request POST "$metadata_endpoint" \
  '{"cas_required":true}'
test "$vault_status" = 204
test -z "$vault_body"
vault_request GET "$metadata_endpoint" ''
test "$vault_status" = 200
test "$(builtin printf '%s' "$vault_body" |
  /usr/bin/plutil -extract data.cas_required raw -o - -)" = true
test "$(builtin printf '%s' "$vault_body" |
  /usr/bin/plutil -extract data.current_version raw -o - -)" = 0

assert_tailnet_path
replacement=$(/usr/bin/osascript -e \
  'text returned of (display dialog "Replacement DeepSeek API key" default answer "" with hidden answer buttons {"Store"} default button "Store")')
case "$replacement" in
  ''|*[!A-Za-z0-9._-]*) exit 1 ;;
esac
test "${#replacement}" -ge 12
data_body='{"options":{"cas":0},"data":{"api_key":"'"$replacement"'"}}'
vault_request POST "$data_endpoint" "$data_body"
test "$vault_status" = 200
test "$(builtin printf '%s' "$vault_body" |
  /usr/bin/plutil -extract data.version raw -o - -)" = 1
vault_request GET "$metadata_endpoint" ''
test "$vault_status" = 200
test "$(builtin printf '%s' "$vault_body" |
  /usr/bin/plutil -extract data.cas_required raw -o - -)" = true
test "$(builtin printf '%s' "$vault_body" |
  /usr/bin/plutil -extract data.current_version raw -o - -)" = 1
unset data_body replacement vault_token status_json signature vault_body
builtin printf '%s\n' SEC0030_VAULT_CREATE_PASS
SEC0030_VAULT_HANDOFF
```

Open the provider console first and keep the newly issued replacement visible.
Type the existing authorized Vault token and the replacement into the two
hidden dialogs. The handoff fails if metadata/data authorization, route
identity, input shape, or create-only CAS fails. Return to the same provider
console session, revoke the exposed credential, then read back only Vault
version metadata and prove the old credential rejects the same provider
metadata request accepted by the replacement. Never print either value.

[vault-kv-metadata]: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
[vault-kv-put]: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2

## Inventorying copies without leaking them

Read the credential from the process environment inside your script — never pass
it as an argument, or it appears in `/proc/<pid>/cmdline` and in shell history.
Emit paths and counts, never matched content.

```python
secret = os.environ.get("PROVIDER_API_KEY", "")
if len(secret) < 12:
    sys.exit(2)              # fail closed rather than match everything
needle = secret.encode()
# ... count occurrences per file; print path and count only
```

Agent transcript stores dominate the count in practice. No `.gitignore`
protects them, and they are exactly the surface the execution boundary exists to
close. Expect the count to *grow* while the credential remains in the shell
environment — each new agent session writes more copies. That growth is the
signal that step 6 is genuinely necessary, not optional cleanup.

## Proving revocation without printing anything

Use a metadata endpoint and compare status codes against a deliberately invalid
control:

| Probe | Before rotation | After rotation |
|---|---|---|
| Old credential, metadata endpoint | `200` | `401` |
| Invalid control credential | `401` | `401` |
| Replacement, through the broker | n/a | `200` |

The invalid control matters: without it, a `401` could equally mean the endpoint
moved. Never log the request headers.

## When the provider has no key-management API

Some providers offer only console-based key management, and account-scoped keys
with no per-key scope, spend cap, or expiry. Two consequences:

- Rotation cannot be automated. Say so in the runbook rather than implying
  parity with providers that support it — under incident pressure, the
  difference will be forgotten.
- Least privilege cannot be enforced upstream, so it must be enforced at your
  own boundary: the broker constrains provider, model, operation, quota and
  expiry on top of an unscoped upstream key. This constrains what the *agent*
  can request. It does not constrain what a *key holder* can do, and that
  residual risk should be written down and accepted explicitly.

See `docs/explanation/provider-capability-gap-deepseek.md` for a worked example.

## Auditing an unrelated token caught in the blast radius

Audit by **accessor**, never by token value. Enumerate live accessors and
account for each one: display name, policies, TTL. Confirm no derived or child
authority survives, no lease references the incident, and no long-TTL token has
wrong-host capability. A revoked token simply does not appear.

Two failure modes that look like an outage but are not:

- The secret store may be reachable from one host and not another. Probe from
  the host the store actually trusts.
- A store speaking plain HTTP behind `VAULT_ADDR=https://…` returns *"server
  gave HTTP response to HTTPS client"*, which reads like a service failure and
  is a scheme mismatch.

Both cost real time in this incident. Check them before concluding an audit is
blocked.

## The root cause is usually distribution, not disclosure

Ask where the credential lived. If it was distributed by shell rc and env files
rather than through the secret store, then it had no accessor, no lease, no TTL
and no revocation path — which is *why* the exposure was unbounded, not merely
how it happened.

Re-issuing the replacement into the same place reproduces the incident with a
new value. The replacement must land in the secret store first.

## Verifying the sweep actually ran

A secret-scanning script that fails to start reports "no findings" — which is
indistinguishable from success. In this incident a sweep had been silently dead
on one platform for an unknown period because it used a bash 4 feature under
bash 3.2, exiting before scanning anything.

Make the tool distinguish *clean* from *never ran*, and fail closed on the
latter.
