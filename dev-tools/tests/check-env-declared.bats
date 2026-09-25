#!/usr/bin/env bats
#
# A2-361. `.env.example` is this repository's env source for graph admission (`v-config-schema`).
# Before it existed the verifier answered `not_measured` for every config entity: there was nothing
# to compare the reads against. Each case below runs the checker against a hand-written tree, so
# each rule is shown going red on its own defect and green on its own fix; the last case runs it
# against the real repository.

setup() {
  REPO="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  CHECK="$REPO/dev-tools/check-env-declared.py"
  WORK="$(mktemp -d)"
  mkdir -p "$WORK/crates/a/src" "$WORK/crates/b/src" "$WORK/dev-tools"
  cat > "$WORK/crates/a/src/lib.rs" <<'RS'
const ENV_BASE_URL: &str = "A_BASE_URL";
pub fn a() { let _ = std::env::var(ENV_BASE_URL); let _ = std::env::var("A_TOKEN"); }
RS
  cat > "$WORK/crates/b/src/lib.rs" <<'RS'
const ENV_BASE_URL: &str = "B_BASE_URL";
pub fn b() { let _ = std::env::var(ENV_BASE_URL); }
RS
  printf 'import os\nX = os.environ.get("PY_KEY", "")\n' > "$WORK/dev-tools/tool.py"
  printf '# names only\nA_BASE_URL=\nA_TOKEN=\nB_BASE_URL=\nPY_KEY=\n' > "$WORK/.env.example"
}

teardown() {
  rm -rf "$WORK"
}

@test "green: every read declared, every declaration read" {
  run "$CHECK" "$WORK"
  [ "$status" -eq 0 ]
  [[ "$output" == *"4 key(s) read, 4 declared, 0 failure(s)"* ]]
}

@test "red: a new read through a const, undeclared — the case the graph verifier cannot see" {
  printf 'const ENV_NEW: &str = "A_NEW_KEY";\npub fn n() { let _ = std::env::var(ENV_NEW); }\n' >> "$WORK/crates/a/src/lib.rs"
  run "$CHECK" "$WORK"
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL UNDECLARED A_NEW_KEY"* ]]
  echo 'A_NEW_KEY=' >> "$WORK/.env.example"
  run "$CHECK" "$WORK"
  [ "$status" -eq 0 ]
}

@test "red: a const name shared by two modules resolves per file, not to the first one found" {
  sed -i '/^B_BASE_URL=/d' "$WORK/.env.example"
  run "$CHECK" "$WORK"
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL UNDECLARED B_BASE_URL"* ]]
}

@test "red: a python dev-tool read, undeclared" {
  sed -i '/^PY_KEY=/d' "$WORK/.env.example"
  run "$CHECK" "$WORK"
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL UNDECLARED PY_KEY"* ]]
}

@test "red: a declared name nothing reads is stale" {
  echo 'GONE_KEY=' >> "$WORK/.env.example"
  run "$CHECK" "$WORK"
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL STALE GONE_KEY"* ]]
}

@test "red: no .env.example at all" {
  rm "$WORK/.env.example"
  run "$CHECK" "$WORK"
  [ "$status" -eq 1 ]
}

@test "this repository: every env read is declared in .env.example" {
  run "$CHECK" "$REPO"
  echo "$output"
  [ "$status" -eq 0 ]
}
