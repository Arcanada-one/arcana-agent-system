#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077
ulimit -c 0

die() {
    printf 'SEC0030_GOVERNANCE_WITNESS_CAPTURE_FAIL: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf '%s\n' \
        'usage: sec0030-governance-witness-capture.sh --github-token-fd FD' \
        '       --signing-key-fd FD --public-key FILE --repository OWNER/REPO' \
        '       --sha SHA --pull-number NUMBER --reviewer LOGIN [--now EPOCH]' \
        '       --key-not-before EPOCH --key-not-after EPOCH' >&2
    exit 2
}

github_token_fd=''
signing_key_fd=''
public_key=''
repository=''
sha=''
pull_number=''
reviewer=''
now=''
key_not_before=''
key_not_after=''

while (( $# > 0 )); do
    case "$1" in
        --github-token-fd) github_token_fd="${2:-}"; shift 2 ;;
        --signing-key-fd) signing_key_fd="${2:-}"; shift 2 ;;
        --public-key) public_key="${2:-}"; shift 2 ;;
        --repository) repository="${2:-}"; shift 2 ;;
        --sha) sha="${2:-}"; shift 2 ;;
        --pull-number) pull_number="${2:-}"; shift 2 ;;
        --reviewer) reviewer="${2:-}"; shift 2 ;;
        --now) now="${2:-}"; shift 2 ;;
        --key-not-before) key_not_before="${2:-}"; shift 2 ;;
        --key-not-after) key_not_after="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done

for tool in base64 curl jq mktemp python3 ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool unavailable: $tool"
done
[[ "$github_token_fd" =~ ^[3-9][0-9]*$ ]] || die 'GitHub token must arrive on a non-standard file descriptor'
[[ "$signing_key_fd" =~ ^[3-9][0-9]*$ ]] || die 'signing key must arrive on a non-standard file descriptor'
[[ "$github_token_fd" != "$signing_key_fd" ]] || die 'credential file descriptors must be distinct'
[[ -r "$public_key" ]] || die 'pinned public key is unreadable'
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'invalid repository'
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die 'invalid release SHA'
[[ "$pull_number" =~ ^[1-9][0-9]*$ ]] || die 'invalid pull number'
[[ "$reviewer" =~ ^[A-Za-z0-9-]{1,39}$ ]] || die 'invalid reviewer'
if [[ -z "$now" ]]; then
    now=$(date +%s)
fi
[[ "$now" =~ ^[0-9]+$ ]] || die 'invalid issuance time'
[[ "$key_not_before" =~ ^[0-9]+$ ]] || die 'invalid signing-key not-before time'
[[ "$key_not_after" =~ ^[0-9]+$ ]] || die 'invalid signing-key not-after time'
(( key_not_before <= now && now <= key_not_after )) || die 'signing key is outside its approved lifetime'

scratch=$(mktemp -d)
cleanup() {
    find "$scratch" -mindepth 1 -maxdepth 1 -type f -delete
    rmdir "$scratch"
}
trap cleanup EXIT

github_token=''
IFS= read -r github_token <&"$github_token_fd" || [[ -n "$github_token" ]]
[[ "$github_token" =~ ^[A-Za-z0-9_]+$ ]] || die 'invalid GitHub credential encoding'
curl_config() {
    printf '%s\n' \
        'silent' \
        'show-error' \
        'fail' \
        'header = "Accept: application/vnd.github+json"' \
        'header = "X-GitHub-Api-Version: 2022-11-28"' \
        "header = \"Authorization: Bearer $github_token\""
}

api_get() {
    local path="$1" target="$2"
    curl_config | curl --config - "https://api.github.com/$path" > "$target"
    jq -e . "$target" >/dev/null 2>&1 || die "GitHub returned invalid JSON for $path"
}

api_get user "$scratch/actor.json"
actor=$(jq -r '.login // empty' "$scratch/actor.json")
[[ "$actor" == Arcanada ]] || die 'capture credential is not owned by the governance machine account'

api_get "repos/$repository" "$scratch/repository.json"
repository_id=$(jq -r --arg repository "$repository" 'select(.full_name == $repository) | .id // empty' "$scratch/repository.json")
[[ "$repository_id" =~ ^[1-9][0-9]*$ ]] || die 'repository identity mismatch'

api_get "repos/$repository/collaborators/$actor/permission" "$scratch/permission.json"
jq -e --arg actor "$actor" '.permission == "admin" and .user.login == $actor' "$scratch/permission.json" >/dev/null \
    || die 'capture credential lacks the admin read authority needed to observe hidden governance'

api_get "repos/$repository/pulls/$pull_number" "$scratch/pull.json"
pull_head_sha=$(jq -r --argjson number "$pull_number" --arg sha "$sha" '
  select(
    .number == $number and
    .state == "closed" and
    .merged_at != null and
    .merge_commit_sha == $sha and
    .base.ref == "main"
  ) | .head.sha // empty
' "$scratch/pull.json")
[[ "$pull_head_sha" =~ ^[0-9a-f]{40}$ ]] || die 'merged pull request does not match the release subject'

api_get "repos/$repository/branches/main/protection" "$scratch/protection.json"
api_get "repos/$repository/rulesets" "$scratch/rulesets.json"
ruleset_id=$(jq -r '
  [.[] | select(.name == "Protect version tags" and .target == "tag" and .enforcement == "active")] |
  if length == 1 then .[0].id else empty end
' "$scratch/rulesets.json")
[[ "$ruleset_id" =~ ^[1-9][0-9]*$ ]] || die 'active version-tag ruleset is missing or ambiguous'
api_get "repos/$repository/rulesets/$ruleset_id" "$scratch/ruleset.json"
api_get "repos/$repository/environments/sec0030-protected-release" "$scratch/environment.json"
api_get "repos/$repository/environments/sec0030-protected-release/deployment-branch-policies" "$scratch/policies.json"
api_get "users/$reviewer" "$scratch/reviewer.json"
reviewer_id=$(jq -r --arg reviewer "$reviewer" 'select(.login == $reviewer) | .id // empty' "$scratch/reviewer.json")
[[ "$reviewer_id" =~ ^[1-9][0-9]*$ ]] || die 'release reviewer identity mismatch'

expires_at=$((now + 120))
jq -nS \
    --arg repository "$repository" \
    --arg reviewer "$reviewer" \
    --arg sha "$sha" \
    --arg pull_head_sha "$pull_head_sha" \
    --argjson repository_id "$repository_id" \
    --argjson pull_number "$pull_number" \
    --argjson ruleset_id "$ruleset_id" \
    --argjson issued_at "$now" \
    --argjson expires_at "$expires_at" \
    --slurpfile protection "$scratch/protection.json" \
    --slurpfile ruleset "$scratch/ruleset.json" \
    --slurpfile environment "$scratch/environment.json" \
    --slurpfile policies "$scratch/policies.json" '
  ($protection[0]) as $p |
  ($ruleset[0]) as $r |
  ($environment[0]) as $e |
  ($policies[0]) as $ep |
  {
    schema: 1,
    repository: {id: $repository_id, full_name: $repository},
    subject: {sha: $sha, pull_number: $pull_number, pull_head_sha: $pull_head_sha},
    issued_at: $issued_at,
    expires_at: $expires_at,
    branch_protection: {
      strict_checks: $p.required_status_checks.strict,
      checks: $p.required_status_checks.checks,
      dismiss_stale_reviews: $p.required_pull_request_reviews.dismiss_stale_reviews,
      require_code_owner_reviews: $p.required_pull_request_reviews.require_code_owner_reviews,
      require_last_push_approval: $p.required_pull_request_reviews.require_last_push_approval,
      required_approving_review_count: $p.required_pull_request_reviews.required_approving_review_count,
      bypass_pull_request_allowances: {
        users: ($p.required_pull_request_reviews.bypass_pull_request_allowances.users // []),
        teams: ($p.required_pull_request_reviews.bypass_pull_request_allowances.teams // []),
        apps: ($p.required_pull_request_reviews.bypass_pull_request_allowances.apps // [])
      },
      enforce_admins: $p.enforce_admins.enabled,
      required_linear_history: $p.required_linear_history.enabled,
      allow_force_pushes: $p.allow_force_pushes.enabled,
      allow_deletions: $p.allow_deletions.enabled,
      restrictions: $p.restrictions
    },
    version_tag_ruleset: {
      id: $ruleset_id,
      name: $r.name,
      target: $r.target,
      enforcement: $r.enforcement,
      bypass_actors: $r.bypass_actors,
      include: $r.conditions.ref_name.include,
      exclude: $r.conditions.ref_name.exclude,
      rules: [$r.rules[].type]
    },
    release_environment: {
      name: $e.name,
      prevent_self_review: ($e.protection_rules[] | select(.type == "required_reviewers") | .prevent_self_review),
      reviewers: [
        $e.protection_rules[] |
        select(.type == "required_reviewers") |
        .reviewers[] |
        {type: .type, identity: (.reviewer.login // .reviewer.slug // "")}
      ],
      tag_policies: [$ep.branch_policies[] | select(.type == "tag") | .name]
    }
  }
' > "$scratch/manifest.json"

script_dir=$(cd "$(dirname "$0")" && pwd)
python3 "$script_dir/sec0030-ssh-sign-from-fd.py" \
    --key-fd "$signing_key_fd" \
    --public-key "$public_key" \
    --manifest "$scratch/manifest.json"
manifest_b64=$(base64 < "$scratch/manifest.json" | tr -d '\n')
signature_b64=$(base64 < "$scratch/manifest.json.sig" | tr -d '\n')
body=$(jq -cn \
    --arg manifest_b64 "$manifest_b64" \
    --arg signature_b64 "$signature_b64" \
    '{type:"SEC0030_GOVERNANCE_WITNESS_V1",manifest_b64:$manifest_b64,signature_b64:$signature_b64}')
unset manifest_b64 signature_b64
jq -n --arg actor "$actor" --arg body "$body" '[{user:{login:$actor},body:$body}]' > "$scratch/comments.json"

bash "$script_dir/sec0030-governance-witness-verify.sh" \
    --comments "$scratch/comments.json" \
    --public-key "$public_key" \
    --expected-author "$actor" \
    --repository "$repository" \
    --repository-id "$repository_id" \
    --sha "$sha" \
    --pull-number "$pull_number" \
    --pull-head-sha "$pull_head_sha" \
    --reviewer "$reviewer" \
    --now "$now" \
    --key-not-before "$key_not_before" \
    --key-not-after "$key_not_after" >/dev/null \
    || die 'captured governance does not satisfy the pinned release contract'

jq -n --arg body "$body" '{body:$body}' > "$scratch/post.json"
unset body
curl_config | curl --config - \
    --request POST \
    --data-binary=@"$scratch/post.json" \
    "https://api.github.com/repos/$repository/issues/$pull_number/comments" > "$scratch/comment-response.json"
comment_id=$(jq -r '.id // empty' "$scratch/comment-response.json")
[[ "$comment_id" =~ ^[1-9][0-9]*$ ]] || die 'GitHub did not confirm the governance witness comment'
unset github_token

printf 'SEC0030_GOVERNANCE_WITNESS_CAPTURE_PASS comment_id=%s expires_at=%s\n' "$comment_id" "$expires_at"
