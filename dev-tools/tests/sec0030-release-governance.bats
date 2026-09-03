#!/usr/bin/env bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
RELEASE="$REPO_ROOT/.github/workflows/release.yml"

@test "release workflow carries no governance credential" {
    set -e
    if grep -Fq SEC0030_GOVERNANCE_TOKEN "$RELEASE"; then
        echo "release workflow carries a governance credential" >&2
        return 1
    fi
    ! grep -Eq 'Administration write|fine-grained token' "$RELEASE"
}

@test "preflight gates on machine-checkable facts with only the workflow token" {
    set -e
    grep -Fq 'GH_TOKEN: ${{ github.token }}' "$RELEASE"
    # The tagged SHA must be the tip of main, and exactly one merged PR into
    # main must have produced it.
    grep -Fq 'repos/${GITHUB_REPOSITORY}/git/ref/heads/main' "$RELEASE"
    grep -Fq 'merge_commit_sha' "$RELEASE"
    # All six protected checks, successful on that exact SHA, from app id 15368.
    grep -Fq 'commits/${GITHUB_SHA}/check-runs' "$RELEASE"
    grep -Fq '.app.id == 15368' "$RELEASE"
    for check in \
        'lint-test' \
        'network-exposure-lint / network-exposure-lint' \
        'platform-native-negative-controls / macos-xpc-sandbox' \
        'platform-contract-mock / linux' \
        'platform-contract-mock / macos' \
        'security-audit / security-audit (rust_cargo)'; do
        grep -Fq "\"$check\"" "$RELEASE"
    done
}

@test "the release path carries no human-signature requirement" {
    # Control downgrade, 2026-09-02 -- see docs/how-to/deployment.md. The gate
    # demanded an APPROVED review from a configured reviewer, that reviewer's
    # presence in CODEOWNERS, and a signed governance witness. None was
    # required by a vendor, and as configured none was satisfiable: main
    # carries no required_pull_request_reviews block. This test fails if the
    # requirement returns without that record being updated, in either
    # direction -- a silent re-arm is as much a surprise as a silent removal.
    set -e
    for token in \
        'SEC0030_RELEASE_REVIEWER' \
        'sec0030-governance-witness-verify.sh' \
        'CODEOWNERS' \
        'APPROVED'; do
        if grep -Fq "$token" "$RELEASE"; then
            echo "human-signature token back in release.yml: $token" >&2
            return 1
        fi
    done
    grep -Fq 'Control downgrade, 2026-09-02' "$REPO_ROOT/docs/how-to/deployment.md"
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
