#!/usr/bin/env bats
#
# The manifest facts that keep `cargo publish` possible (#101), and the
# mutations that must break them.
#
# Each case copies the real workspace into a temporary directory and edits one
# manifest, so the assertions run against the actual repository layout rather
# than a hand-built fixture that could drift from it.

setup() {
  REPO="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  WORK="$(mktemp -d)"
  # Manifests and the script only — no target/, no .git. Fast, and enough:
  # the checks read Cargo.toml files and ask `cargo metadata`.
  mkdir -p "$WORK/dev-tools" "$WORK/crates"
  cp "$REPO/Cargo.toml" "$WORK/Cargo.toml"
  cp "$REPO/dev-tools/check-internal-versions.sh" "$WORK/dev-tools/"
  for dir in "$REPO"/crates/*/; do
    name="$(basename "$dir")"
    mkdir -p "$WORK/crates/$name/src"
    cp "$dir/Cargo.toml" "$WORK/crates/$name/Cargo.toml"
    # `cargo metadata` needs a target to exist; the contents never compile here.
    : > "$WORK/crates/$name/src/lib.rs"
    if [ -f "$dir/build.rs" ]; then : > "$WORK/crates/$name/build.rs"; fi
    if grep -q '^\[\[bin\]\]' "$dir/Cargo.toml"; then
      mkdir -p "$WORK/crates/$name/src/bin"
      awk '/^path = "/{gsub(/^path = "|"$/,"");print}' "$dir/Cargo.toml" \
        | while read -r p; do
            case "$p" in src/*) mkdir -p "$WORK/crates/$name/$(dirname "$p")"
                                 : > "$WORK/crates/$name/$p" ;;
            esac
          done
    fi
  done
}

teardown() {
  rm -rf "$WORK"
}

run_check() {
  run "$WORK/dev-tools/check-internal-versions.sh"
}

@test "the workspace as committed passes" {
  run_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"cycle back edge version-less"* ]]
}

@test "an internal version left behind by a release bump fails" {
  sed -i 's|arcana-core = { path = "crates/core", version = "[^"]*" }|arcana-core = { path = "crates/core", version = "0.1.0" }|' "$WORK/Cargo.toml"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"arcana-core is 0.1.0"* ]]
}

@test "bumping the workspace without bumping the internal deps fails" {
  sed -i '0,/^version = "/s|^version = "[^"]*"|version = "0.3.0"|' "$WORK/Cargo.toml"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"workspace is 0.3.0"* ]]
}

@test "renaming the section does not turn the check into a silent pass" {
  # An empty read loop is how a guard stops guarding while still exiting 0.
  sed -i 's|^\[workspace.dependencies\]$|[workspace.dependencies-renamed]|' "$WORK/Cargo.toml"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"no arcana-* entries"* ]]
}

@test "versioning the cycle back edge fails, however it is spelled" {
  # `{ workspace = true }` inherits a version without containing the word.
  # An earlier version of the check grepped for "version" and passed this
  # while `cargo publish --workspace --dry-run` failed.
  for spelling in '{ workspace = true }' '{ path = "../tools", version = "0.2.0" }'; do
    cp "$REPO/crates/skills/Cargo.toml" "$WORK/crates/skills/Cargo.toml"
    sed -i "s|^arcana-tools = { path = \"../tools\" }$|arcana-tools = $spelling|" \
      "$WORK/crates/skills/Cargo.toml"
    run_check
    [ "$status" -eq 1 ] || { echo "spelling accepted: $spelling"; return 1; }
    [[ "$output" == *"must carry NO version requirement"* ]]
  done
}

@test "deleting the back edge fails rather than passing vacuously" {
  sed -i '/^arcana-tools = { path = "\.\.\/tools" }$/d' "$WORK/crates/skills/Cargo.toml"
  run_check
  [ "$status" -eq 1 ]
  [[ "$output" == *"no longer has a dev-dependency"* ]]
}
