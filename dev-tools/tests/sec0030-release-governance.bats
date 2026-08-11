#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
RELEASE="$REPO_ROOT/.github/workflows/release.yml"

@test "release workflow carries no governance credential" {
    set -e
    ! grep -Fq SEC0030_GOVERNANCE_TOKEN "$RELEASE"
    ! grep -Eq 'Administration write|fine-grained token' "$RELEASE"
}

@test "preflight verifies a signed exact-SHA witness with only the workflow token" {
    set -e
    grep -Fq 'GH_TOKEN: ${{ github.token }}' "$RELEASE"
    grep -Fq 'sec0030-governance-witness-verify.sh' "$RELEASE"
    grep -Fq '.github/sec0030-governance-witness.pub' "$RELEASE"
    grep -Fq 'repos/${GITHUB_REPOSITORY}/issues/${pull_number}/comments?per_page=100' "$RELEASE"
    grep -Fq -- '--sha "$GITHUB_SHA"' "$RELEASE"
}

@test "release workflow grants only read access before the protected environment" {
    set -e
    grep -Fq 'checks: read' "$RELEASE"
    grep -Fq 'issues: read' "$RELEASE"
    grep -Fq 'pull-requests: read' "$RELEASE"
    grep -Fq 'environment: sec0030-protected-release' "$RELEASE"
}

@test "release rechecks current main and dereferenced tag after attestations and before publication" {
    set -e
    attest_line=$(grep -nF 'Attest build provenance for packages and SBOMs' "$RELEASE" | cut -d: -f1)
    recheck_line=$(grep -nF 'Recheck current main and tag immediately before publication' "$RELEASE" | cut -d: -f1)
    publish_line=$(grep -nF 'Publish GitHub Release' "$RELEASE" | cut -d: -f1)
    [ -n "$attest_line" ]
    [ -n "$recheck_line" ]
    [ -n "$publish_line" ]
    [ "$attest_line" -lt "$recheck_line" ]
    [ "$recheck_line" -lt "$publish_line" ]
    step=$(sed -n "${recheck_line},$((publish_line - 1))p" "$RELEASE")
    grep -Fq 'repos/${GITHUB_REPOSITORY}/git/ref/heads/main' <<<"$step"
    grep -Fq 'test "$GITHUB_SHA" = "$current_main"' <<<"$step"
    grep -Fq 'repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}' <<<"$step"
    grep -Fq 'repos/${GITHUB_REPOSITORY}/git/tags/${tag_sha}' <<<"$step"
    grep -Fq 'test "$GITHUB_SHA" = "$tag_sha"' <<<"$step"
}
