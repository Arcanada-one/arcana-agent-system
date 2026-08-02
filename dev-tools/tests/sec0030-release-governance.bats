#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
RELEASE="$REPO_ROOT/.github/workflows/release.yml"

@test "release workflow carries no governance credential" {
    ! grep -Fq SEC0030_GOVERNANCE_TOKEN "$RELEASE"
    ! grep -Eq 'Administration write|fine-grained token' "$RELEASE"
}

@test "preflight verifies a signed exact-SHA witness with only the workflow token" {
    grep -Fq 'GH_TOKEN: ${{ github.token }}' "$RELEASE"
    grep -Fq 'sec0030-governance-witness-verify.sh' "$RELEASE"
    grep -Fq '.github/sec0030-governance-witness.pub' "$RELEASE"
    grep -Fq 'repos/${GITHUB_REPOSITORY}/issues/${pull_number}/comments?per_page=100' "$RELEASE"
    grep -Fq -- '--sha "$GITHUB_SHA"' "$RELEASE"
}

@test "release workflow grants only read access before the protected environment" {
    grep -Fq 'checks: read' "$RELEASE"
    grep -Fq 'issues: read' "$RELEASE"
    grep -Fq 'pull-requests: read' "$RELEASE"
    grep -Fq 'environment: sec0030-protected-release' "$RELEASE"
}
