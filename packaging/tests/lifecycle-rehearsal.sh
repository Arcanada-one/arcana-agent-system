#!/usr/bin/env bash
# Live, unprivileged install/activate/rollback rehearsal with a real broker
# process and Unix socket. Uses no credential and touches only a temp root.

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
broker="$repo/target/debug/arcana-credential-broker"
lifecycle="$repo/packaging/broker-lifecycle.sh"
[ -x "$broker" ] || { printf 'broker binary missing: run cargo build first\n' >&2; exit 1; }

scratch=$(mktemp -d)
cleanup() {
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

run_lifecycle install one "$broker" "$policy_one"
run_lifecycle activate
run_lifecycle verify

# Install a second image/config generation, then prove rollback restores both.
run_lifecycle install two /bin/false "$policy_two"
if run_lifecycle activate; then
  printf 'bad generation unexpectedly activated\n' >&2
  exit 1
fi
run_lifecycle rollback one
run_lifecycle verify

# Config-axis drill: corrupt the active policy, prove verification catches it,
# then prove rollback restores the archived known-good config and service.
active="$scratch/root/etc/arcana/credential-broker/capability-policy.toml"
printf '\n# deliberate config-axis drill\n' >> "$active"
if run_lifecycle verify; then
  printf 'corrupt active policy unexpectedly verified\n' >&2
  exit 1
fi
run_lifecycle rollback one
cmp -s "$active" "$policy_one"
run_lifecycle verify
run_lifecycle disable
printf 'LIFECYCLE_REHEARSAL_PASS\n'
