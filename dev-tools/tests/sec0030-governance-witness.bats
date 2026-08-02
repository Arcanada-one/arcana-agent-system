#!/usr/bin/env bats

VERIFY_SCRIPT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)/sec0030-governance-witness-verify.sh"

setup() {
    export HOME="$BATS_TEST_TMPDIR/home"
    mkdir -p "$HOME"
    PRIVATE_KEY="$BATS_TEST_TMPDIR/witness-key"
    PUBLIC_KEY="$BATS_TEST_TMPDIR/witness-key.pub"
    ssh-keygen -q -t ed25519 -N '' -C sec0030-test -f "$PRIVATE_KEY"
}

write_manifest() {
    local target="$1"
    jq -nS '
      {
        schema: 1,
        repository: {
          id: 101,
          full_name: "Arcanada-one/arcana-agent-system"
        },
        subject: {
          sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          pull_number: 43,
          pull_head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        issued_at: 1000,
        expires_at: 1120,
        branch_protection: {
          strict_checks: true,
          checks: [
            {context: "lint-test", app_id: 15368},
            {context: "network-exposure-lint / network-exposure-lint", app_id: 15368},
            {context: "platform-contract-mock / linux", app_id: 15368},
            {context: "platform-contract-mock / macos", app_id: 15368},
            {context: "security-audit / security-audit (rust_cargo)", app_id: 15368}
          ],
          dismiss_stale_reviews: true,
          require_code_owner_reviews: true,
          require_last_push_approval: true,
          required_approving_review_count: 1,
          bypass_pull_request_allowances: {users: [], teams: [], apps: []},
          enforce_admins: true,
          required_linear_history: true,
          allow_force_pushes: false,
          allow_deletions: false,
          restrictions: null
        },
        version_tag_ruleset: {
          id: 202,
          name: "Protect version tags",
          target: "tag",
          enforcement: "active",
          bypass_actors: [],
          include: ["refs/tags/v*"],
          exclude: [],
          rules: ["deletion", "non_fast_forward", "required_signatures", "update"]
        },
        release_environment: {
          name: "sec0030-protected-release",
          prevent_self_review: true,
          reviewers: ["PavelValentov"],
          tag_policies: ["v*"]
        }
      }
    ' > "$target"
}

sign_comment() {
    local manifest="$1" comments="$2" author="${3:-Arcanada}"
    local manifest_b64 signature_b64 body
    ssh-keygen -q -Y sign -f "$PRIVATE_KEY" -n sec0030-governance "$manifest"
    manifest_b64=$(base64 -w 0 "$manifest")
    signature_b64=$(base64 -w 0 "${manifest}.sig")
    body=$(jq -cn \
      --arg manifest_b64 "$manifest_b64" \
      --arg signature_b64 "$signature_b64" \
      '{type:"SEC0030_GOVERNANCE_WITNESS_V1",manifest_b64:$manifest_b64,signature_b64:$signature_b64}')
    jq -n --arg author "$author" --arg body "$body" \
      '[{author:{login:$author},body:$body,created_at:"2026-08-02T00:00:00Z"}]' > "$comments"
}

run_verify() {
    local comments="$1"
    run env HOME="$HOME" bash "$VERIFY_SCRIPT" \
      --comments "$comments" \
      --public-key "$PUBLIC_KEY" \
      --expected-author Arcanada \
      --repository Arcanada-one/arcana-agent-system \
      --repository-id 101 \
      --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      --pull-number 43 \
      --pull-head-sha bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
      --reviewer PavelValentov \
      --now 1050
}

@test "accepts an exact short-lived signed governance witness" {
    manifest="$BATS_TEST_TMPDIR/valid.json"
    comments="$BATS_TEST_TMPDIR/comments.json"
    write_manifest "$manifest"
    sign_comment "$manifest" "$comments"

    run_verify "$comments"

    [ "$status" -eq 0 ] \
      && [[ "$output" == *"SEC0030_GOVERNANCE_WITNESS_PASS"* ]]
}

@test "rejects a witness whose manifest changed after signing" {
    manifest="$BATS_TEST_TMPDIR/tampered.json"
    comments="$BATS_TEST_TMPDIR/comments.json"
    write_manifest "$manifest"
    sign_comment "$manifest" "$comments"
    jq '.subject.sha = "cccccccccccccccccccccccccccccccccccccccc"' "$manifest" > "$BATS_TEST_TMPDIR/changed.json"
    manifest_b64=$(base64 -w 0 "$BATS_TEST_TMPDIR/changed.json")
    jq --arg manifest_b64 "$manifest_b64" '.[0].body |= (fromjson | .manifest_b64 = $manifest_b64 | tojson)' \
      "$comments" > "$BATS_TEST_TMPDIR/tampered-comments.json"

    run_verify "$BATS_TEST_TMPDIR/tampered-comments.json"

    [ "$status" -ne 0 ]
}

@test "rejects an expired signed witness" {
    manifest="$BATS_TEST_TMPDIR/expired.json"
    comments="$BATS_TEST_TMPDIR/comments.json"
    write_manifest "$manifest"
    jq '.expires_at = 1049' "$manifest" > "$BATS_TEST_TMPDIR/expired-signed.json"
    sign_comment "$BATS_TEST_TMPDIR/expired-signed.json" "$comments"

    run_verify "$comments"

    [ "$status" -ne 0 ] \
      && [[ "$output" == *"no valid governance witness"* ]]
}

@test "rejects a signed witness containing a tag-ruleset bypass actor" {
    manifest="$BATS_TEST_TMPDIR/bypass.json"
    comments="$BATS_TEST_TMPDIR/comments.json"
    write_manifest "$manifest"
    jq '.version_tag_ruleset.bypass_actors = [{actor_type:"Team",actor_id:7}]' \
      "$manifest" > "$BATS_TEST_TMPDIR/bypass-signed.json"
    sign_comment "$BATS_TEST_TMPDIR/bypass-signed.json" "$comments"

    run_verify "$comments"

    [ "$status" -ne 0 ]
}

@test "rejects a correctly signed witness posted by the wrong account" {
    manifest="$BATS_TEST_TMPDIR/wrong-author.json"
    comments="$BATS_TEST_TMPDIR/comments.json"
    write_manifest "$manifest"
    sign_comment "$manifest" "$comments" Mallory

    run_verify "$comments"

    [ "$status" -ne 0 ]
}

@test "rejects a signed witness for a different repository" {
    manifest="$BATS_TEST_TMPDIR/wrong-repo.json"
    comments="$BATS_TEST_TMPDIR/comments.json"
    write_manifest "$manifest"
    jq '.repository.full_name = "example/other"' "$manifest" > "$BATS_TEST_TMPDIR/wrong-repo-signed.json"
    sign_comment "$BATS_TEST_TMPDIR/wrong-repo-signed.json" "$comments"

    run_verify "$comments"

    [ "$status" -ne 0 ]
}
