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
      protection_rules:[{type:"required_reviewers",prevent_self_review:true,reviewers:[{type:"User",reviewer:{id:303,login:"PavelValentov"}}]}],
      deployment_branch_policy:{protected_branches:false,custom_branch_policies:true}
    }' > "$FIXTURES/environment.json"
    jq -n '{branch_policies:[{name:"v*",type:"tag"}]}' > "$FIXTURES/policies.json"
    jq -n '{id:303,login:"PavelValentov"}' > "$FIXTURES/reviewer.json"

    cat > "$BATS_TEST_TMPDIR/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
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
  */deployment-branch-policies) cat "$FIXTURES/policies.json" ;;
  */environments/sec0030-protected-release) cat "$FIXTURES/environment.json" ;;
  https://api.github.com/users/PavelValentov) cat "$FIXTURES/reviewer.json" ;;
  */issues/43/comments)
    for argument in "$@"; do
      case "$argument" in --data-binary=@*) cp "${argument#--data-binary=@}" "$CAPTURED_POST" ;; esac
    done
    jq -n '{id:77}'
    ;;
  *) printf 'unexpected URL: %s\n' "$url" >&2; exit 22 ;;
esac
SH
    chmod +x "$BATS_TEST_TMPDIR/bin/curl"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

run_capture() {
    run bash -c 'exec 3<"$1" 4<"$2"; exec bash "$3" \
      --github-token-fd 3 \
      --signing-key-fd 4 \
      --public-key "$4" \
      --repository Arcanada-one/arcana-agent-system \
      --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      --pull-number 43 \
      --reviewer PavelValentov \
      --now 1000' _ \
      "$BATS_TEST_TMPDIR/token" "$BATS_TEST_TMPDIR/key" "$CAPTURE_SCRIPT" "$BATS_TEST_TMPDIR/key.pub"
}

@test "captures, validates, signs, and posts an exact governance witness" {
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
      .release_environment.reviewers == ["PavelValentov"]
    ' "$BATS_TEST_TMPDIR/manifest.json" >/dev/null
    ! grep -Fq github_pat_SYNTHETIC_DO_NOT_LOG "$CURL_LOG"
}

@test "refuses a hidden tag-ruleset bypass actor without posting" {
    jq '.bypass_actors = [{actor_type:"Team",actor_id:7}]' "$FIXTURES/ruleset.json" > "$BATS_TEST_TMPDIR/ruleset-bypass.json"
    mv "$BATS_TEST_TMPDIR/ruleset-bypass.json" "$FIXTURES/ruleset.json"

    run_capture

    [ "$status" -ne 0 ]
    [ ! -e "$CAPTURED_POST" ]
}
