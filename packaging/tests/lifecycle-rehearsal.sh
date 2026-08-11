#!/usr/bin/env bash
# Live, unprivileged install/activate/rollback rehearsal with a real broker
# process and Unix socket. Uses no credential and touches only a temp root.

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
broker="$repo/target/debug/arcana-credential-broker"
lifecycle="$repo/packaging/broker-lifecycle.sh"
false_binary=$(type -P false)
[ -x "$broker" ] || { printf 'broker binary missing: run cargo build first\n' >&2; exit 1; }
[ -x "$false_binary" ] || { printf 'external false executable missing\n' >&2; exit 1; }

if [ "$(uname -s)" = Darwin ]; then
  # macOS AF_UNIX paths are much shorter than Linux paths, while the default
  # TMPDIR lives under a long /var/folders hierarchy. Keep the live socket
  # fixture below the portable path-length ceiling.
  scratch=$(mktemp -d /tmp/arcana-sec0030.XXXXXX)
  state_root="$scratch/root/var/db/arcana-credential-broker"
  control_root="$scratch/root/var/db/arcana-credential-broker-control"
  generation_root="$scratch/root/var/db/arcana-credential-broker-generations"
  installed_binary_root="$scratch/root/usr/local/libexec/arcana"
  socket_path="$scratch/root/var/run/arcana-credential-broker/broker.sock"
else
  scratch=$(mktemp -d)
  state_root="$scratch/root/var/lib/arcana-credential-broker"
  control_root="$scratch/root/var/lib/arcana-credential-broker-control"
  generation_root="$scratch/root/var/lib/arcana-credential-broker-generations"
  installed_binary_root="$scratch/root/usr/libexec/arcana"
  socket_path="$scratch/root/run/arcana-credential-broker/broker.sock"
fi
first_release=''
replacement_release=''
waiter_owner_read_resume=''
waiter_observation_resume=''
lock_holder=''
lock_waiter=''
replacement_holder=''
cleanup() {
  if [ -n "$first_release" ]; then : > "$first_release"; fi
  if [ -n "$replacement_release" ]; then : > "$replacement_release"; fi
  if [ -n "$waiter_owner_read_resume" ]; then : > "$waiter_owner_read_resume"; fi
  if [ -n "$waiter_observation_resume" ]; then : > "$waiter_observation_resume"; fi
  for child in "$lock_holder" "$lock_waiter" "$replacement_holder"; do
    [ -n "$child" ] || continue
    kill -TERM "$child" 2>/dev/null || true
  done
  cleanup_attempts=0
  while [ "$cleanup_attempts" -lt 500 ]; do
    child_running=0
    for child in "$lock_holder" "$lock_waiter" "$replacement_holder"; do
      [ -n "$child" ] || continue
      if kill -0 "$child" 2>/dev/null; then child_running=1; fi
    done
    [ "$child_running" = 1 ] || break
    sleep 0.02
    cleanup_attempts=$((cleanup_attempts + 1))
  done
  for child in "$lock_holder" "$lock_waiter" "$replacement_holder"; do
    [ -n "$child" ] || continue
    if kill -0 "$child" 2>/dev/null; then kill -KILL "$child" 2>/dev/null || true; fi
    wait "$child" 2>/dev/null || true
  done
  ARCANA_ROOT="$scratch/root" SERVICE_MODE=rehearsal \
    bash "$lifecycle" disable >/dev/null 2>&1 || true
  rm -rf -- "$scratch"
}
trap cleanup EXIT

policy_one="$scratch/policy-one.toml"
policy_two="$scratch/policy-two.toml"
cp "$repo/packaging/policy/capability-policy.example.toml" "$policy_one"
cp "$policy_one" "$policy_two"
chmod 0644 "$policy_one" "$policy_two"

run_lifecycle() {
  ARCANA_ROOT="$scratch/root" SERVICE_MODE=rehearsal \
    bash "$lifecycle" "$@"
}

digest_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

run_lifecycle install one "$broker" "$policy_one"
run_lifecycle activate
run_lifecycle verify

# Prove a healthy staged update actually switches the running generation.
run_lifecycle install two "$broker" "$policy_two"
run_lifecycle activate
run_lifecycle verify
[ "$(sed -n '1p' "$control_root/generation")" = two ]

# Retrying an identical immutable generation must still disable the running
# broker and repair the pending/service-asset phase instead of returning early.
run_lifecycle install two "$broker" "$policy_two"
[ ! -s "$state_root/rehearsal.pid" ]
[ ! -S "$socket_path" ]
run_lifecycle activate
run_lifecycle verify

# A generation name is an immutable binary+policy identity. Reusing it with a
# different artifact must fail without replacing the known-good generation.
if run_lifecycle install two "$false_binary" "$policy_two"; then
  printf 'mutable generation name unexpectedly accepted\n' >&2
  exit 1
fi
[ ! -s "$state_root/rehearsal.pid" ]
[ ! -S "$socket_path" ]
run_lifecycle rollback two
run_lifecycle verify

# Install a bad third image, then prove rollback restores both binary and config.
run_lifecycle install three "$false_binary" "$policy_two"
if run_lifecycle activate; then
  printf 'bad generation unexpectedly activated\n' >&2
  exit 1
fi
[ ! -s "$state_root/rehearsal.pid" ]
[ ! -S "$socket_path" ]
run_lifecycle rollback two
run_lifecycle verify

# If a switch fails after the old ledger was archived but before the selected
# generation token changes, rollback must reconcile state by its independent
# generation marker and restore the byte-identical old quota/idempotency ledger.
runtime_state="$state_root/broker-state.json"
run_lifecycle install seven "$broker" "$policy_two"
printf '%s\n' '{"ledger":{"generation":1,"quota_limit":1000,"quota_spent":0,"committed":{},"next_outcome":1,"max_entries":4096},"cached":{}}' > "$runtime_state"
chmod 0600 "$runtime_state"
state_digest=$(digest_file "$runtime_state")
chmod 0555 "$installed_binary_root"
if run_lifecycle activate; then
  printf 'activation unexpectedly ignored an unwritable binary-link directory\n' >&2
  exit 1
fi
chmod 0755 "$installed_binary_root"
[ "$(sed -n '1p' "$control_root/generation")" = two ]
[ "$(sed -n '1p' "$control_root/runtime-state-generation")" = seven ]
run_lifecycle rollback two
[ "$(digest_file "$runtime_state")" = "$state_digest" ]
run_lifecycle verify

# A command failure inside activation must quarantine the invalid broker-owned
# object, leave the authoritative snapshot path free, and allow rollback
# without manual root cleanup.
run_lifecycle install four "$broker" "$policy_two"
rm -f -- "$runtime_state"
mkdir "$runtime_state"
if run_lifecycle activate; then
  printf 'activation ignored a state-transition failure\n' >&2
  exit 1
fi
[ "$(sed -n '1p' "$control_root/generation")" = two ]
[ ! -s "$state_root/rehearsal.pid" ]
[ ! -S "$socket_path" ]
[ ! -e "$control_root/runtime-generations/two-broker-state.json" ]
compgen -G "$control_root/runtime-generations/two-broker-state.json.rejected.*" >/dev/null
run_lifecycle rollback two
run_lifecycle verify

# State archival must rename, not copy, a broker-owned object. A source symlink
# is moved into the root-control namespace and rejected without opening its
# target, so a privileged production run cannot disclose a root-readable file.
run_lifecycle install six "$broker" "$policy_two"
victim="$scratch/root-only-victim"
printf 'must remain untouched\n' > "$victim"
victim_digest=$(digest_file "$victim")
rm -f -- "$runtime_state"
ln -s "$victim" "$runtime_state"
if run_lifecycle activate; then
  printf 'symlink runtime state unexpectedly accepted\n' >&2
  exit 1
fi
[ "$(digest_file "$victim")" = "$victim_digest" ]
[ ! -e "$control_root/runtime-generations/two-broker-state.json" ]
run_lifecycle rollback two
run_lifecycle verify

# Every mutating command shares one cross-process lock. Hold it in one
# rehearsal process, force a waiter to miss the released lock, then let a
# third process acquire it before the waiter rechecks. The waiter must treat
# both owner transitions as transient and publish only after both release.
first_release="$control_root/release-first-holder"
ARCANA_ROOT="$scratch/root" SERVICE_MODE=rehearsal \
  LIFECYCLE_REHEARSAL_HOLD_LOCK_UNTIL_FILE="$first_release" \
  bash "$lifecycle" disable >/dev/null &
lock_holder=$!
attempts=0
while [ ! -f "$control_root/lifecycle.lock" ] && [ "$attempts" -lt 500 ]; do
  sleep 0.02
  attempts=$((attempts + 1))
done
[ -f "$control_root/lifecycle.lock" ]
waiter_owner_read_resume="$control_root/resume-waiter-owner-read"
waiter_observation_resume="$control_root/resume-waiter-after-observation-failure"
waiter_observed="$control_root/waiter-observed-owner"
ARCANA_ROOT="$scratch/root" SERVICE_MODE=rehearsal \
  LIFECYCLE_REHEARSAL_PRE_OWNER_READ_UNTIL_FILE="$waiter_owner_read_resume" \
  LIFECYCLE_REHEARSAL_POST_OBSERVATION_FAILURE_UNTIL_FILE="$waiter_observation_resume" \
  LIFECYCLE_REHEARSAL_OBSERVED_OWNER_FILE="$waiter_observed" \
  bash "$lifecycle" install eight "$broker" "$policy_two" &
lock_waiter=$!
owner_read_ready="$control_root/rehearsal-pre-owner-read-ready"
attempts=0
while [ ! -f "$owner_read_ready" ] && [ "$attempts" -lt 500 ]; do
  sleep 0.02
  attempts=$((attempts + 1))
done
[ -f "$owner_read_ready" ] || { printf 'waiter did not reach owner-read barrier\n' >&2; exit 1; }
: > "$first_release"
wait "$lock_holder"
lock_holder=''
: > "$waiter_owner_read_resume"
observation_failed="$control_root/rehearsal-observation-link-failed"
attempts=0
while [ ! -f "$observation_failed" ] && [ "$attempts" -lt 500 ]; do
  sleep 0.02
  attempts=$((attempts + 1))
done
[ -f "$observation_failed" ] || { printf 'waiter did not reach observation-failure barrier\n' >&2; exit 1; }
replacement_release="$control_root/release-replacement-holder"
ARCANA_ROOT="$scratch/root" SERVICE_MODE=rehearsal \
  LIFECYCLE_REHEARSAL_HOLD_LOCK_UNTIL_FILE="$replacement_release" \
  bash "$lifecycle" disable >/dev/null &
replacement_holder=$!
attempts=0
while [ "$attempts" -lt 500 ]; do
  replacement_owner=$(sed -n '1p' "$control_root/lifecycle.lock" 2>/dev/null || true)
  case "$replacement_owner" in "$replacement_holder:"*) break ;; esac
  sleep 0.02
  attempts=$((attempts + 1))
done
case "$replacement_owner" in
  "$replacement_holder:"*) ;;
  *) printf 'replacement holder did not acquire lifecycle lock\n' >&2; exit 1 ;;
esac
: > "$waiter_observation_resume"
attempts=0
while [ ! -f "$waiter_observed" ] && [ "$attempts" -lt 500 ]; do
  sleep 0.02
  attempts=$((attempts + 1))
done
[ -f "$waiter_observed" ] || { printf 'waiter did not record replacement owner\n' >&2; exit 1; }
[ "$(sed -n '1p' "$waiter_observed")" = "$replacement_owner" ] || {
  printf 'waiter observed an unexpected lifecycle owner\n' >&2
  exit 1
}
kill -0 "$lock_waiter" 2>/dev/null
[ ! -s "$control_root/pending-generation" ]
: > "$replacement_release"
wait "$replacement_holder"
replacement_holder=''
wait "$lock_waiter"
lock_waiter=''
[ "$(sed -n '1p' "$control_root/pending-generation")" = eight ]
run_lifecycle rollback two
run_lifecycle verify

# Pre-manifest debris is not an immutable generation and can be recovered by an
# exact retry. A durable manifest, once present, is never rewritten.
incomplete="$generation_root/five"
mkdir -p "$incomplete"
cp "$broker" "$installed_binary_root/arcana-credential-broker-five"
run_lifecycle install five "$broker" "$policy_two"
[ -f "$incomplete/manifest.sha256" ]

# Alternate roots are rehearsal-only and must never redirect live service-manager
# or tmpfiles operations.
if ARCANA_ROOT="$scratch/unsafe-root" SERVICE_MODE=auto bash "$lifecycle" disable; then
  printf 'production alternate root unexpectedly accepted\n' >&2
  exit 1
fi

# Config-axis drill: corrupt the active policy, prove verification catches it,
# then prove rollback restores the archived known-good config and service.
active="$scratch/root/etc/arcana/credential-broker/capability-policy.toml"
printf '\n# deliberate config-axis drill\n' >> "$active"
if run_lifecycle verify; then
  printf 'corrupt active policy unexpectedly verified\n' >&2
  exit 1
fi
run_lifecycle rollback two
cmp -s "$active" "$policy_two"
run_lifecycle verify
run_lifecycle disable
printf 'LIFECYCLE_REHEARSAL_PASS\n'
