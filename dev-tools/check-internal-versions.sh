#!/usr/bin/env bash
# Assert the two manifest facts that keep `cargo publish` possible (#101).
#
# 1. Every internal dependency version in `[workspace.dependencies]` equals
#    `workspace.package.version`. They are separate strings that must agree;
#    a release bumps one and cargo will happily publish 0.3.0 crates that
#    depend on 0.2.0 of their own siblings.
#
# 2. `crates/skills`'s dev-dependency on `arcana-tools` carries NO version.
#    That edge closes the only cycle in the published graph
#    (tools -> connectors -> skills -> tools). Cargo drops a version-less
#    dev-dependency when publishing, which breaks the cycle; give it a version
#    and `cargo publish --workspace` can no longer order the crates.
#
# Cheap enough to run anywhere, so it does not need a network or a registry.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0

workspace_version="$(
  awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *=/{print; exit}' \
    "$root/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/'
)"
if [[ -z "$workspace_version" ]]; then
  echo "FAIL: could not read workspace.package.version" >&2
  exit 1
fi

found=0
while IFS= read -r line; do
  found=$(( found + 1 ))
  name="${line%% *}"
  declared="$(sed -E 's/.*version *= *"([^"]+)".*/\1/' <<<"$line")"
  if [[ "$declared" != "$workspace_version" ]]; then
    echo "FAIL: [workspace.dependencies] $name is $declared, workspace is $workspace_version" >&2
    status=1
  fi
done < <(
  awk '/^\[workspace\.dependencies\]/{f=1;next} /^\[/{f=0} f && /^arcana-/{print}' \
    "$root/Cargo.toml"
)
if (( found == 0 )); then
  # An empty read loop is silent success, which is how a guard stops guarding:
  # rename the section and every assertion above vacuously passes.
  echo "FAIL: no arcana-* entries under [workspace.dependencies]" >&2
  status=1
fi

# Asked of the RESOLVED graph, not of the text. A first version of this check
# grepped the declaration for the string "version" and was defeated by
# `{ workspace = true }`, which inherits one without spelling it — the check
# passed while `cargo publish --workspace --dry-run` failed. `cargo metadata`
# reports a dependency with no version requirement as `*`, whatever syntax
# produced it.
back_edge_req="$(
  cargo metadata --no-deps --format-version 1 --manifest-path "$root/Cargo.toml" \
    | python3 -c '
import json, sys
meta = json.load(sys.stdin)
for pkg in meta["packages"]:
    if pkg["name"] != "arcana-skills":
        continue
    for dep in pkg["dependencies"]:
        if dep["name"] == "arcana-tools" and dep["kind"] == "dev":
            print(dep["req"])
            break
'
)"
if [[ -z "$back_edge_req" ]]; then
  echo "FAIL: arcana-skills no longer has a dev-dependency on arcana-tools;" >&2
  echo "      re-check whether the published cycle still exists." >&2
  status=1
elif [[ "$back_edge_req" != "*" ]]; then
  echo "FAIL: arcana-skills' dev-dependency on arcana-tools requires '$back_edge_req'." >&2
  echo "      It must carry NO version requirement. That edge closes the" >&2
  echo "      tools -> connectors -> skills cycle; cargo drops a version-less" >&2
  echo "      dev-dependency when publishing, which is what lets" >&2
  echo "      'cargo publish --workspace' order the crates at all." >&2
  status=1
fi

if (( status == 0 )); then
  echo "ok: internal dependency versions all $workspace_version; cycle back edge version-less"
fi
exit "$status"
