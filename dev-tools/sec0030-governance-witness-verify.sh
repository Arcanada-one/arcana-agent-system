#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
    printf '%s\n' 'SEC0030_GOVERNANCE_WITNESS_FAIL: no valid governance witness' >&2
    exit 1
}

usage() {
    printf '%s\n' \
        'usage: sec0030-governance-witness-verify.sh --comments FILE --public-key FILE' \
        '       --expected-author LOGIN --repository OWNER/REPO --repository-id ID' \
        '       --sha SHA --pull-number NUMBER --pull-head-sha SHA --reviewer LOGIN --now EPOCH' >&2
    exit 2
}

comments=''
public_key=''
expected_author=''
repository=''
repository_id=''
sha=''
pull_number=''
pull_head_sha=''
reviewer=''
now=''

while (( $# > 0 )); do
    case "$1" in
        --comments) comments="${2:-}"; shift 2 ;;
        --public-key) public_key="${2:-}"; shift 2 ;;
        --expected-author) expected_author="${2:-}"; shift 2 ;;
        --repository) repository="${2:-}"; shift 2 ;;
        --repository-id) repository_id="${2:-}"; shift 2 ;;
        --sha) sha="${2:-}"; shift 2 ;;
        --pull-number) pull_number="${2:-}"; shift 2 ;;
        --pull-head-sha) pull_head_sha="${2:-}"; shift 2 ;;
        --reviewer) reviewer="${2:-}"; shift 2 ;;
        --now) now="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done

for tool in base64 jq mktemp ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 || fail
done

[[ -f "$comments" && -r "$comments" ]] || fail
[[ -f "$public_key" && -r "$public_key" ]] || fail
[[ "$expected_author" =~ ^[A-Za-z0-9-]{1,39}$ ]] || fail
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail
[[ "$repository_id" =~ ^[1-9][0-9]*$ ]] || fail
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "$pull_number" =~ ^[1-9][0-9]*$ ]] || fail
[[ "$pull_head_sha" =~ ^[0-9a-f]{40}$ ]] || fail
[[ "$reviewer" =~ ^[A-Za-z0-9-]{1,39}$ ]] || fail
[[ "$now" =~ ^[0-9]+$ ]] || fail
jq -e 'type == "array"' "$comments" >/dev/null 2>&1 || fail

scratch=$(mktemp -d)
cleanup() {
    find "$scratch" -mindepth 1 -maxdepth 1 -type f -delete
    rmdir "$scratch"
}
trap cleanup EXIT

public_key_line=$(awk 'NF >= 2 && $1 ~ /^(ssh-ed25519|ecdsa-sha2-|sk-ssh-ed25519|sk-ecdsa-sha2-)/ {print; exit}' "$public_key")
[[ -n "$public_key_line" ]] || fail
printf 'sec0030 %s\n' "$public_key_line" > "$scratch/allowed-signers"

mapfile -t candidates < <(
    jq -rc --arg author "$expected_author" '
      .[] |
      select(.author.login == $author) |
      .body as $body |
      try ($body | fromjson) catch empty |
      select(.type == "SEC0030_GOVERNANCE_WITNESS_V1") |
      [.manifest_b64, .signature_b64] | @tsv
    ' "$comments"
)

for candidate in "${candidates[@]}"; do
    IFS=$'\t' read -r manifest_b64 signature_b64 <<<"$candidate"
    [[ -n "$manifest_b64" && -n "$signature_b64" ]] || continue
    printf '%s' "$manifest_b64" | base64 --decode > "$scratch/manifest" 2>/dev/null || continue
    printf '%s' "$signature_b64" | base64 --decode > "$scratch/signature" 2>/dev/null || continue

    ssh-keygen -Y verify \
        -f "$scratch/allowed-signers" \
        -I sec0030 \
        -n sec0030-governance \
        -s "$scratch/signature" \
        < "$scratch/manifest" >/dev/null 2>&1 || continue

    if jq -e \
        --arg repository "$repository" \
        --arg reviewer "$reviewer" \
        --arg sha "$sha" \
        --arg pull_head_sha "$pull_head_sha" \
        --argjson repository_id "$repository_id" \
        --argjson pull_number "$pull_number" \
        --argjson now "$now" '
      .schema == 1 and
      .repository == {id: $repository_id, full_name: $repository} and
      .subject == {
        sha: $sha,
        pull_number: $pull_number,
        pull_head_sha: $pull_head_sha
      } and
      (.issued_at | type) == "number" and
      (.expires_at | type) == "number" and
      .issued_at <= $now and
      $now < .expires_at and
      (.expires_at - .issued_at) > 0 and
      (.expires_at - .issued_at) <= 120 and
      ($now - .issued_at) <= 120 and
      .branch_protection.strict_checks == true and
      ([.branch_protection.checks[]] | sort_by(.context)) == ([
        {context: "lint-test", app_id: 15368},
        {context: "network-exposure-lint / network-exposure-lint", app_id: 15368},
        {context: "platform-contract-mock / linux", app_id: 15368},
        {context: "platform-contract-mock / macos", app_id: 15368},
        {context: "security-audit / security-audit (rust_cargo)", app_id: 15368}
      ] | sort_by(.context)) and
      .branch_protection.dismiss_stale_reviews == true and
      .branch_protection.require_code_owner_reviews == true and
      .branch_protection.require_last_push_approval == true and
      .branch_protection.required_approving_review_count == 1 and
      .branch_protection.bypass_pull_request_allowances == {users: [], teams: [], apps: []} and
      .branch_protection.enforce_admins == true and
      .branch_protection.required_linear_history == true and
      .branch_protection.allow_force_pushes == false and
      .branch_protection.allow_deletions == false and
      .branch_protection.restrictions == null and
      .version_tag_ruleset.name == "Protect version tags" and
      .version_tag_ruleset.target == "tag" and
      .version_tag_ruleset.enforcement == "active" and
      .version_tag_ruleset.bypass_actors == [] and
      .version_tag_ruleset.include == ["refs/tags/v*"] and
      .version_tag_ruleset.exclude == [] and
      (.version_tag_ruleset.rules | sort) == ([
        "deletion", "non_fast_forward", "required_signatures", "update"
      ] | sort) and
      .release_environment.name == "sec0030-protected-release" and
      .release_environment.prevent_self_review == true and
      .release_environment.reviewers == [$reviewer] and
      .release_environment.tag_policies == ["v*"]
    ' "$scratch/manifest" >/dev/null 2>&1; then
        printf '%s\n' 'SEC0030_GOVERNANCE_WITNESS_PASS'
        exit 0
    fi
done

fail
