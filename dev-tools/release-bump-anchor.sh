#!/usr/bin/env bash
# Print the commit timestamp of the commit that set `[workspace.package]`
# version to the version currently in Cargo.toml.
#
# Extracted from `release-pending` in ci.yml so it can be tested. The
# anchoring is subtle enough that an inline, untestable copy is how it went
# wrong once already.
#
# Usage: release-bump-anchor.sh [repo-root]   -> epoch seconds on stdout
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
version="$(grep -m1 -E '^version = "' "$root/Cargo.toml" | cut -d'"' -f2)"
if [[ -z "$version" ]]; then
  echo "could not read the workspace version from $root/Cargo.toml" >&2
  exit 1
fi

# Anchored to the `[workspace.package]` line, and it has to be.
#
# This was `-S"version = \"$version\""`, a pickaxe on the bare string, correct
# while the root manifest held exactly one of them. It no longer does:
# `[workspace.dependencies]` carries the same string on eight internal crates,
# and `check-internal-versions.sh` GUARANTEES they stay textually identical to
# the package version. `-S` fires on a change to the COUNT, so adding a tenth
# internal crate re-anchored the grace clock to that commit — granting another
# three days silently, and able to do so after the check had begun failing.
# A guard an unrelated edit can disarm is not a guard.
#
# `-G` with the regex anchored at line start matches only the
# `[workspace.package]` line; a dependency carries its version mid-line.
escaped="$(printf '%s' "$version" | sed -E 's/[][^$.*+?(){}|\\]/\\&/g')"
anchor="$(git -C "$root" log -1 --format=%ct -G"^version = \"${escaped}\"" -- Cargo.toml)"
if [[ -z "$anchor" ]]; then
  echo "no commit sets [workspace.package] version to ${version}" >&2
  exit 1
fi
printf '%s\n' "$anchor"
