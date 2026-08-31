#!/usr/bin/env bats
#
# `release-pending`'s grace clock must be anchored to the commit that bumped
# the PACKAGE version, and to nothing else.
#
# It was not. The root manifest carries the same version string on eight
# internal crates in `[workspace.dependencies]`, and `check-internal-versions.sh`
# guarantees they stay textually identical to the package version. A `-S`
# pickaxe fires on a change to the COUNT of a string, so adding one internal
# crate re-anchored the clock to that commit — granting another three days, and
# able to do so after the check had already begun failing.

setup() {
  SCRIPT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/release-bump-anchor.sh"
  REPO="$(mktemp -d)"
  git -C "$REPO" init -q .
  git -C "$REPO" config user.email test@example.invalid
  git -C "$REPO" config user.name test
}

teardown() {
  rm -rf "$REPO"
}

# Write a root manifest with $1 as the package version and $2.. as internal
# dependency lines.
manifest() {
  local version="$1"; shift
  {
    printf '[workspace]\nmembers = ["crates/a"]\n\n'
    printf '[workspace.package]\nversion = "%s"\n\n' "$version"
    printf '[workspace.dependencies]\n'
    printf '%s\n' "$@"
  } > "$REPO/Cargo.toml"
}

commit() {
  git -C "$REPO" add -A
  git -C "$REPO" commit -qm "$1"
  git -C "$REPO" rev-parse HEAD
}

@test "the anchor is the commit that bumped the package version" {
  manifest 0.1.0 'arcana-a = { path = "crates/a", version = "0.1.0" }'
  commit "0.1.0" >/dev/null
  manifest 0.2.0 'arcana-a = { path = "crates/a", version = "0.2.0" }'
  local bump; bump="$(commit "bump to 0.2.0")"

  run "$SCRIPT" "$REPO"
  [ "$status" -eq 0 ]
  [ "$output" = "$(git -C "$REPO" log -1 --format=%ct "$bump")" ]
}

@test "an unrelated [workspace.dependencies] edit does not reset the clock" {
  # The regression. Adding an internal crate changes the COUNT of the version
  # string without touching the package version.
  manifest 0.2.0 'arcana-a = { path = "crates/a", version = "0.2.0" }'
  local bump; bump="$(commit "bump to 0.2.0")"
  sleep 1
  manifest 0.2.0 \
    'arcana-a = { path = "crates/a", version = "0.2.0" }' \
    'arcana-b = { path = "crates/b", version = "0.2.0" }'
  local later; later="$(commit "add a second internal crate")"

  run "$SCRIPT" "$REPO"
  [ "$status" -eq 0 ]
  [ "$output" = "$(git -C "$REPO" log -1 --format=%ct "$bump")" ]
  [ "$output" != "$(git -C "$REPO" log -1 --format=%ct "$later")" ]
}

@test "REMOVING an internal crate does not reset the clock either" {
  # The same defect in the other direction: `-S` fires on any count change.
  manifest 0.2.0 \
    'arcana-a = { path = "crates/a", version = "0.2.0" }' \
    'arcana-b = { path = "crates/b", version = "0.2.0" }'
  local bump; bump="$(commit "bump to 0.2.0")"
  sleep 1
  manifest 0.2.0 'arcana-a = { path = "crates/a", version = "0.2.0" }'
  commit "drop an internal crate" >/dev/null

  run "$SCRIPT" "$REPO"
  [ "$status" -eq 0 ]
  [ "$output" = "$(git -C "$REPO" log -1 --format=%ct "$bump")" ]
}

@test "a version with regex metacharacters is matched literally" {
  # Build metadata is legal in a Cargo version and contains `+`. Unescaped,
  # `0+` means "one or more 0s", so the regex does NOT match the literal
  # `1.0.0+build.5` line and the anchor comes back EMPTY — the script's own
  # failure branch, not a wrong date.
  #
  # A `0.3.0-rc.1` version does not test this: `.` unescaped still matches a
  # literal dot, so that case passes with or without the escaping. It was the
  # first version of this test, and it survived the mutation.
  manifest '1.0.0+build.5' 'arcana-a = { path = "crates/a", version = "1.0.0+build.5" }'
  local bump; bump="$(commit "bump to 1.0.0+build.5")"

  run "$SCRIPT" "$REPO"
  [ "$status" -eq 0 ]
  [ "$output" = "$(git -C "$REPO" log -1 --format=%ct "$bump")" ]
}

@test "a version no commit ever set fails loudly rather than printing nothing" {
  # An empty anchor would make `age_days` a shell arithmetic error, or worse,
  # zero — a permanently-green release-pending.
  manifest 0.2.0 'arcana-a = { path = "crates/a", version = "0.2.0" }'
  commit "0.2.0" >/dev/null
  sed -i 's/^version = "0.2.0"$/version = "9.9.9"/' "$REPO/Cargo.toml"

  run "$SCRIPT" "$REPO"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no commit sets"* ]]
}
