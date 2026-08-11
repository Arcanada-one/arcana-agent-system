#!/usr/bin/env bats

CAPTURE_SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/sec0030-governance-witness-capture.sh"

setup() {
    export HOME="$BATS_TEST_TMPDIR/home"
    export FIXTURES="$BATS_TEST_TMPDIR/fixtures"
    export CURL_LOG="$BATS_TEST_TMPDIR/curl.log"
    export CAPTURED_POST="$BATS_TEST_TMPDIR/post.json"
    mkdir -p "$HOME" "$FIXTURES" "$BATS_TEST_TMPDIR/bin"
    ssh-keygen -q -t ed25519 -N '' -C sec0030-test -f "$BATS_TEST_TMPDIR/key"
    printf '%s\n' 'github_pat_SYNTHETIC_DO_NOT_LOG' > "$BATS_TEST_TMPDIR/token"

    jq -n '{login:"Arcanada"}' > "$FIXTURES/actor.json"
    jq -n '{id:101,full_name:"Arcanada-one/arcana-agent-system"}' > "$FIXTURES/repository.json"
    jq -n '{permission:"admin",user:{login:"Arcanada"}}' > "$FIXTURES/permission.json"
    jq -n '{
      number:43,state:"closed",merged_at:"2026-08-02T00:00:00Z",
      merge_commit_sha:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      head:{sha:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},base:{ref:"main"}
    }' > "$FIXTURES/pull.json"
    jq -n '{
      required_status_checks:{strict:true,checks:[
        {context:"lint-test",app_id:15368},
        {context:"network-exposure-lint / network-exposure-lint",app_id:15368},
        {context:"platform-native-negative-controls / macos-xpc-sandbox",app_id:15368},
        {context:"platform-contract-mock / linux",app_id:15368},
        {context:"platform-contract-mock / macos",app_id:15368},
        {context:"security-audit / security-audit (rust_cargo)",app_id:15368}
      ]},
      required_pull_request_reviews:{
        dismiss_stale_reviews:true,
        require_code_owner_reviews:true,
        require_last_push_approval:true,
        required_approving_review_count:1
      },
      enforce_admins:{enabled:true},
      required_linear_history:{enabled:true},
      allow_force_pushes:{enabled:false},
      allow_deletions:{enabled:false},
      restrictions:null
    }' > "$FIXTURES/protection.json"
    jq -n '[{id:202,name:"Protect version tags",target:"tag",enforcement:"active"}]' > "$FIXTURES/rulesets.json"
    jq -n '{
      id:202,name:"Protect version tags",target:"tag",enforcement:"active",bypass_actors:[],
      conditions:{ref_name:{include:["refs/tags/v*"],exclude:[]}},
      rules:[{type:"deletion"},{type:"non_fast_forward"},{type:"required_signatures"},{type:"update"}]
    }' > "$FIXTURES/ruleset.json"
    jq -n '{
      name:"sec0030-protected-release",
      can_admins_bypass:false,
      protection_rules:[{type:"required_reviewers",prevent_self_review:true,reviewers:[{type:"User",reviewer:{id:303,login:"PavelValentov"}}]}],
      deployment_branch_policy:{protected_branches:false,custom_branch_policies:true}
    }' > "$FIXTURES/environment.json"
    jq -n '{total_count:1,branch_policies:[{name:"v*",type:"tag"}]}' > "$FIXTURES/policies.json"
    jq -n '{id:303,login:"PavelValentov"}' > "$FIXTURES/reviewer.json"

    cat > "$BATS_TEST_TMPDIR/bin/date" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 1 && "$1" == +%s ]]
printf '%s\n' 1000
SH

    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
config=$(cat)
[[ "$config" == *'Authorization: Bearer github_pat_SYNTHETIC_DO_NOT_LOG'* ]]
printf '%q ' "$@" >> "$CURL_LOG"
printf '\n' >> "$CURL_LOG"
url="${*: -1}"
case "$url" in
  https://api.github.com/user) cat "$FIXTURES/actor.json" ;;
  https://api.github.com/repos/Arcanada-one/arcana-agent-system) cat "$FIXTURES/repository.json" ;;
  */collaborators/Arcanada/permission) cat "$FIXTURES/permission.json" ;;
  */pulls/43) cat "$FIXTURES/pull.json" ;;
  */branches/main/protection) cat "$FIXTURES/protection.json" ;;
  */rulesets/202) cat "$FIXTURES/ruleset.json" ;;
  */rulesets) cat "$FIXTURES/rulesets.json" ;;
  */deployment-branch-policies\?per_page=100\&page=1) cat "$FIXTURES/policies.json" ;;
  */environments/sec0030-protected-release) cat "$FIXTURES/environment.json" ;;
  https://api.github.com/users/PavelValentov) cat "$FIXTURES/reviewer.json" ;;
  */issues/43/comments)
    for argument in "$@"; do
      case "$argument" in --data-binary=@*) cp "${argument#--data-binary=@}" "$CAPTURED_POST" ;; esac
    done
    body=$(jq -r '.body' "$CAPTURED_POST")
    jq -n --arg body "$body" '{
      id:77,
      user:{login:"Arcanada"},
      created_at:"1970-01-01T00:16:40Z",
      body:$body
    }'
    ;;
  *) printf 'unexpected URL: %s\n' "$url" >&2; exit 22 ;;
esac
SH
    chmod +x "$BATS_TEST_TMPDIR/bin/curl" "$BATS_TEST_TMPDIR/bin/date"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

run_capture() {
    run bash -c 'exec 3<"$1" 4<"$2"; script="$3"; public_key="$4"; shift 4; exec bash "$script" \
      --github-token-fd 3 \
      --signing-key-fd 4 \
      --public-key "$public_key" \
      --repository Arcanada-one/arcana-agent-system \
      --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      --pull-number 43 \
      --reviewer PavelValentov \
      --key-not-before 900 \
      --key-not-after 2000 "$@"' _ \
      "$BATS_TEST_TMPDIR/token" "$BATS_TEST_TMPDIR/key" "$CAPTURE_SCRIPT" "$BATS_TEST_TMPDIR/key.pub" "$@"
}

run_capture_xtrace() {
    run bash -c 'exec 3<"$1" 4<"$2"; script="$3"; public_key="$4"; shift 4; exec bash -x "$script" \
      --github-token-fd 3 \
      --signing-key-fd 4 \
      --public-key "$public_key" \
      --repository Arcanada-one/arcana-agent-system \
      --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      --pull-number 43 \
      --reviewer PavelValentov \
      --key-not-before 900 \
      --key-not-after 2000 "$@"' _ \
      "$BATS_TEST_TMPDIR/token" "$BATS_TEST_TMPDIR/key" "$CAPTURE_SCRIPT" "$BATS_TEST_TMPDIR/key.pub" "$@"
}

@test "captures, validates, signs, and posts an exact governance witness" {
    set -e
    run_capture

    [ "$status" -eq 0 ]
    [[ "$output" == *"SEC0030_GOVERNANCE_WITNESS_CAPTURE_PASS comment_id=77 expires_at=1120"* ]]
    [ -f "$CAPTURED_POST" ]
    body=$(jq -r '.body' "$CAPTURED_POST")
    [ "$(jq -r '.type' <<<"$body")" = SEC0030_GOVERNANCE_WITNESS_V1 ]
    jq -r '.manifest_b64' <<<"$body" | base64 --decode > "$BATS_TEST_TMPDIR/manifest.json"
    jq -e '
      .repository.id == 101 and
      .subject.pull_head_sha == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and
      .issued_at == 1000 and .expires_at == 1120 and
      .version_tag_ruleset.bypass_actors == [] and
      .release_environment.reviewers == [{type:"User",identity:"PavelValentov"}]
    ' "$BATS_TEST_TMPDIR/manifest.json" >/dev/null
    ! grep -Fq github_pat_SYNTHETIC_DO_NOT_LOG "$CURL_LOG"
    ! find "$BATS_TEST_TMPDIR" -type f \
      ! -path "$BATS_TEST_TMPDIR/token" \
      ! -path "$BATS_TEST_TMPDIR/key" \
      -exec grep -lF github_pat_SYNTHETIC_DO_NOT_LOG {} + | grep -q .
    ! find "$BATS_TEST_TMPDIR" -type f \
      ! -path "$BATS_TEST_TMPDIR/key" \
      -exec grep -lF 'BEGIN OPENSSH PRIVATE KEY' {} + | grep -q .
    ! grep -Fq '"$scratch/curl.conf"' "$CAPTURE_SCRIPT"
    ! grep -Fq '"$scratch/signing-key"' "$CAPTURE_SCRIPT"
}

@test "disables inherited xtrace before reading or expanding credentials" {
    set -e
    run_capture_xtrace

    [ "$status" -eq 0 ]
    [[ "$output" != *github_pat_SYNTHETIC_DO_NOT_LOG* ]]
    [[ "$output" != *'BEGIN OPENSSH PRIVATE KEY'* ]]
}

@test "disables operator curl configuration before injecting authorization" {
    set -e
    printf '%s\n' 'trace-ascii = "curlrc-exfiltration.log"' > "$HOME/.curlrc"

    run_capture

    [ "$status" -eq 0 ]
    [ ! -e "$HOME/curlrc-exfiltration.log" ]
    awk '{ if ($1 != "-q") exit 1 }' "$CURL_LOG"
    [ "$(grep -Fc -- '--proto =https' "$CURL_LOG")" -eq 11 ]
    [ "$(grep -Fc -- '--noproxy \*' "$CURL_LOG")" -eq 11 ]
    [[ "$output" != *github_pat_SYNTHETIC_DO_NOT_LOG* ]]
}

@test "refuses a caller-supplied future issuance time" {
    set -e
    run_capture --now 9999999999

    [ "$status" -eq 2 ]
    [ ! -e "$CAPTURED_POST" ]
}

@test "refuses to sign when bounded governance reads exhaust the witness lifetime" {
    set -e
    export DATE_CALLS="$BATS_TEST_TMPDIR/date-calls"
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      '[[ "$#" -eq 1 && "$1" == +%s ]]' \
      'calls=$(cat "$DATE_CALLS" 2>/dev/null || printf 0)' \
      'calls=$((calls + 1))' \
      'printf "%s\n" "$calls" > "$DATE_CALLS"' \
      'if (( calls == 1 )); then printf "%s\n" 1000; else printf "%s\n" 1120; fi' \
      > "$BATS_TEST_TMPDIR/bin/date"
    chmod +x "$BATS_TEST_TMPDIR/bin/date"

    run_capture

    [ "$status" -ne 0 ]
    [[ "$output" == *'governance witness expired before signing'* ]]
    [ ! -e "$CAPTURED_POST" ]
}

@test "refuses a hidden tag-ruleset bypass actor without posting" {
    set -e
    jq '.bypass_actors = [{actor_type:"Team",actor_id:7}]' "$FIXTURES/ruleset.json" > "$BATS_TEST_TMPDIR/ruleset-bypass.json"
    mv "$BATS_TEST_TMPDIR/ruleset-bypass.json" "$FIXTURES/ruleset.json"

    run_capture

    [ "$status" -ne 0 ]
    [ ! -e "$CAPTURED_POST" ]
}

@test "refuses an additional protected-environment reviewer without posting" {
    set -e
    jq '.protection_rules[0].reviewers += [{type:"User",reviewer:{id:404,login:"Mallory"}}]' \
      "$FIXTURES/environment.json" > "$BATS_TEST_TMPDIR/environment-extra.json"
    mv "$BATS_TEST_TMPDIR/environment-extra.json" "$FIXTURES/environment.json"

    run_capture

    [ "$status" -ne 0 ]
    [ ! -e "$CAPTURED_POST" ]
}

@test "refuses an environment whose administrators can bypass review" {
    set -e
    jq '.can_admins_bypass = true' "$FIXTURES/environment.json" > "$BATS_TEST_TMPDIR/environment-bypass.json"
    mv "$BATS_TEST_TMPDIR/environment-bypass.json" "$FIXTURES/environment.json"

    run_capture

    [ "$status" -ne 0 ]
    [ ! -e "$CAPTURED_POST" ]
}

@test "refuses an overflow deployment policy page" {
    set -e
    jq '.total_count = 101 | .branch_policies = [range(0;100) | {name:"v*",type:"tag"}]' \
      "$FIXTURES/policies.json" > "$BATS_TEST_TMPDIR/policies-overflow.json"
    mv "$BATS_TEST_TMPDIR/policies-overflow.json" "$FIXTURES/policies.json"

    run_capture

    [ "$status" -ne 0 ]
    [ ! -e "$CAPTURED_POST" ]
}

@test "refuses an additional branch deployment policy" {
    set -e
    jq '.total_count = 2 | .branch_policies += [{name:"main",type:"branch"}]' \
      "$FIXTURES/policies.json" > "$BATS_TEST_TMPDIR/policies-branch.json"
    mv "$BATS_TEST_TMPDIR/policies-branch.json" "$FIXTURES/policies.json"

    run_capture

    [ "$status" -ne 0 ]
    [ ! -e "$CAPTURED_POST" ]
}
