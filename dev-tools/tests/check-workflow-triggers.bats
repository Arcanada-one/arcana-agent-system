#!/usr/bin/env bats
#
# A2-238. The gate that keeps a stacked pull request from being silently unchecked.
#
# The failure it guards is not a red check — it is an EMPTY check list. PR #196 was based on the
# unmerged branch of #195 (our ordinary way of stacking cards) and, because both workflows triggered
# on `pull_request: branches: [main]`, GitHub started nothing for it: no `ci`, no `graph-admission`,
# and no signal anywhere that a rule had been skipped rather than satisfied.
#
# Every case below runs the checker against a hand-written workflow directory, so each rule is shown
# going red on its own defect and green on its own fix. The last two cases run it against the real
# `.github/workflows/` — the assertion that this repository actually complies.

setup() {
  REPO="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  CHECK="$REPO/dev-tools/check-workflow-triggers.sh"
  WORK="$(mktemp -d)"
  mkdir -p "$WORK/wf"
}

teardown() {
  rm -rf "$WORK"
}

# A workflow that satisfies all three rules, written out so a case can break exactly one of them.
good() {
  cat > "$WORK/wf/ci.yml" <<'YAML'
name: ci

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: echo ok
  changelog:
    runs-on: ubuntu-24.04
    if: github.event_name == 'pull_request' || github.event_name == 'workflow_dispatch'
    steps:
      - run: echo ok
YAML
}

@test "the compliant fixture passes — the checker is not simply always red" {
  good
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 0 ]
  [[ "$output" == *"contract holds"* ]]
}

@test "R1: a branch filter on pull_request is refused, and named by line" {
  good
  # The exact defect measured on ci.yml:6-7 and graph-admission-call.yml:28-29.
  perl -0pi -e 's/  pull_request:\n/  pull_request:\n    branches: [main]\n/' "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"ci.yml:7"* ]]
  [[ "$output" == *"based on any other branch gets NO checks"* ]]
}

@test "R1: branches-ignore is the same defect written the other way round" {
  good
  perl -0pi -e 's/  pull_request:\n/  pull_request:\n    branches-ignore: [wip\/**]\n/' "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"carries a branch filter"* ]]
}

@test "R2: dropping the push filter is refused — R1 is not 'triggers are noise'" {
  good
  perl -0pi -e 's/  push:\n    branches: \[main\]\n/  push:\n/' "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"is unrestricted"* ]]
}

@test "R2: a push filter that no longer covers main is refused" {
  good
  perl -0pi -e 's/branches: \[main\]/branches: [release]/' "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no longer covers main"* ]]
}

@test "R3: a job narrowed to one event by equality is refused" {
  good
  perl -0pi -e "s/    if: github.event_name == 'pull_request' \|\| github.event_name == 'workflow_dispatch'\n/    if: github.event_name == 'pull_request'\n/" "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"SKIPPED (and reported as a success)"* ]]
}

@test "R3: a negation widens rather than narrows, and stays allowed" {
  good
  perl -0pi -e "s/    if: github.event_name == 'pull_request' \|\| github.event_name == 'workflow_dispatch'\n/    if: github.event_name != 'pull_request'\n/" "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 0 ]
}

@test "a workflow whose triggers cannot be parsed fails rather than passes" {
  good
  perl -0pi -e 's/^on:\n(  .*\n)+/on: [push, pull_request]\n/m' "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"this checker reads only the block form"* ]]
}

@test "a workflow with no on: block at all fails" {
  printf 'name: ci\njobs:\n  test:\n    runs-on: ubuntu-24.04\n' > "$WORK/wf/ci.yml"
  run "$CHECK" "$WORK/wf"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no \`on:\` block"* ]]
}

@test "this repository's own workflows comply" {
  run "$CHECK"
  [ "$status" -eq 0 ]
}

@test "graph-admission is reachable from a pull request based on any branch" {
  # The rule the whole card exists for, asserted on the real file rather than through the checker:
  # «нет receipt — нет мержа» must not be enforced only on pull requests that happen to target main.
  # Read with awk rather than a YAML library, because this must hold on any runner image.
  run awk '/^on:/{o=1;next} /^[^[:space:]]/{o=0} o && $1 !~ /^#/' \
    "$REPO/.github/workflows/graph-admission-call.yml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"pull_request:"* ]]
  [[ "$output" != *"branches"* ]]
}
