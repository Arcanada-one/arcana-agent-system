# arcana-smoke.sh — mutation matrix (ARAS-0040)

The prod-quality-gate is claimable-met only once its instrument is proven
**falsifiable**: every stage assertion must be shown able to go RED under a
specific injected defect, while the baseline stays GREEN (creative-ARAS-0029
§ "Mutation-test the gate itself" / Failure Mode Table). This file records an
actually-executed mutation run — raw command + a sha256 of the captured TAP
output per mutation (F7: a PASS/RED is auditable, not merely asserted).

- **Repo tip:** `aras-0040-smoke-gate` off `aras-0033 @ 18373b6`.
- **Runner:** `bash dev-tools/smoke/arcana-smoke.sh` (release binary + cargo-test
  driver stages); each mutation applied, the release binary rebuilt where the
  defect is in Rust source, the harness run, then reverted via `git checkout`.
- **Reproducibility:** `baseline` and post-run `restore` hash **identically**
  (`f073776a…`), proving the tree returns byte-for-byte to green. The sha is of
  the full captured stdout (TAP + diagnostics + the `# JUnit:` path line, which
  is `$ARCANA_SMOKE_OUT`-dependent); fix `ARCANA_SMOKE_OUT` to reproduce.

## Baseline (GREEN — the reference)

```
cargo build --release
ARCANA_SMOKE_OUT=$OUT bash dev-tools/smoke/arcana-smoke.sh   # exit 0, not-ok=0
```
`sha256(baseline) = f073776a98f556111c4a297b0eba660a05a7ecb6311cb2cdfd5982334e27a855`
19 rows: 18 `ok` + 1 tri-state `SKIP` (optional live MC leg), 0 `not ok`.

## Negative controls (each drives its stage RED)

| # | Injected defect | File | RED stage(s) | Baseline |
|---|-----------------|------|--------------|----------|
| M1 | `run_whoami` Denied arm returns 0 (revert item 1) | `crates/cli/src/main.rs` | `not ok 7 - S1 whoami-deny exit-2` | GREEN |
| M2 | audit emits an identical hardcoded decision label (Allow == Deny in the log) | `crates/cli/src/bootstrap.rs` | `not ok 6 - S1 whoami-allow audit-Allowed-record`; `not ok 8 - S1 whoami-deny audit-Denied-record` | GREEN |
| M3 | replay fixture returns a degenerate empty `result` (dead-data MC) | `dev-tools/smoke/fixtures/mc-success.json` | `not ok 9 - S2 mc-ping-replay exit-0`; `not ok 10 - S2 mc-ping-replay nonce-bound` | GREEN |
| M4 | corrupt the pinned `UnexpectedStatus` Display string | `crates/core/src/connector.rs` | `not ok 13 - S3 stub-200 pinned-Display` (12 & 14 stay `ok` — per-message discrimination, F5) | GREEN |
| M5 | `CostTracker::check_budget` always `Ok(())` (breaker disabled, F4) | `crates/core/src/cost.rs` | `not ok 16 - S5 cost-breaker maxcost-unit`; `not ok 17 - S5 cost-breaker maxcost-replay-transcript` — **unit accounting test stays GREEN** (`driver_cost_accounting` 1 passed) | GREEN |
| M6 | seed a `mc-deadbeef…` canary into a throwaway build (`std::hint::black_box`) | `crates/cli/src/main.rs` | `not ok 18 - SEC no-secret-in-binary` | GREEN |

### Per-mutation commands + output hashes

**M1** — `run_whoami` no longer returns 2 on Denial.
```
perl -0pi -e 's/if denied {\n  2\n} else {\n  0\n}/0/' crates/cli/src/main.rs   # (whitespace-exact)
cargo build --release && bash dev-tools/smoke/arcana-smoke.sh
```
`sha256 = 22f6177e7e0b8f0aaf0709954ab6e92b263e370996eba38899cc2f25e474fdb1` — RED at S1 deny (exit 2 lost).

**M2** — decision label hardcoded so an allow is indistinguishable from a deny
in the audit log. Post-C4 (ARAS-0033) the decision label is minted in
`Bootstrap::evaluate` (`crates/cli/src/bootstrap.rs`), which feeds
`AuditLog::record_decision`:
```
# replace the `let (decision, layer) = match &outcome {
#     CascadeOutcome::Allowed { .. } => ("Allowed", "cascade"),
#     CascadeOutcome::Denied { layer, .. } => ("Denied", *layer),
# };`
# with `let (decision, layer) = ("Continue", "cascade");` in bootstrap.rs::evaluate
cargo build --release && bash dev-tools/smoke/arcana-smoke.sh
```
RED: no distinct `Allowed` / `Denied` decision records (the same audit-trail
false-green hole the pre-C4 F2 finding named, now guarded at the executor-owned
audit boundary).

**M3** — replay success envelope has `"result":""`.
```
echo '{…,"result":"",…,"status":"success"}' > dev-tools/smoke/fixtures/mc-success.json
bash dev-tools/smoke/arcana-smoke.sh
```
`sha256 = 1b84bc5a409702c94819c56695643e4181110af14b36553e1b94c85aed6e67b1` — RED: item-2 guard exits 2 AND the nonce token is absent.

**M4** — `#[error("unexpected HTTP status {0} (expected 201)")]` → `"unexpected status {0}"`.
```
perl -0pi -e 's/unexpected HTTP status {0} (expected 201)/unexpected status {0}/' crates/core/src/connector.rs
cargo build --release && bash dev-tools/smoke/arcana-smoke.sh
```
`sha256 = 63a35bc3a5bce88b2dbde6611cf625f0a382ea562effc5a5270c9378aa43f306` — only the stub-200 control flips RED (S3 asserts the pinned *message*, not the exit code — F5).

**M5** — breaker disabled; the F4 proof (S5 RED, unit GREEN).
```
# prepend `return Ok(());` to CostTracker::check_budget
bash dev-tools/smoke/arcana-smoke.sh
cargo test -p arcana-core --test driver_cost_accounting -- --exact driver_cost_accounting   # 1 passed
```
`sha256 = 5d7b47d5b06e9b65d18c197af8ba9120fb9562cf656060cff1aaec70df36e6d2` — RED at S5; the counter-only accounting unit test stays GREEN, exactly the "counters tick, breaker dead" regression S5 exists to catch.

**M6** — canary in a throwaway build; proves the SEC arm can FIRE.
```
# add `let _ = std::hint::black_box("mc-deadbeef1234567890");` to fn main
cargo build --release && bash dev-tools/smoke/arcana-smoke.sh
```
`sha256 = 853fa744cac27246623e1023bd3cfb6390cee3cfb9c09b30edcfb6ce7595c9b5` — RED at SEC: `strings | grep -oE 'mc-[0-9a-f]{8,}'` hits `mc-deadbeef1234567890…`.

## Note on the SEC `strings` pattern (F6, corrected during /dr-do)

The creative/plan specified `grep -E 'mc-[a-z0-9]{6,}'`. On this binary that
**false-REDs every honest build** — rustls contributes CMC-OID symbols
(`id-cmc-identityProof`, `id-cmc-revokeRequest`, …) that match. A word-boundary
anchor (`\bmc-…`) removes the false positive but then MISSES the canary:
`rustc` concatenates all `&str` literals into one contiguous rodata blob with
no separators, so `strings` emits them as a single line and any real leaked
token is glued to its neighbours (no boundary to anchor). The shipped pattern
keys on token SHAPE instead — `mc-` + ≥8 lowercase-hex — which is empty on the
honest build (CMC symbols carry non-hex camelCase after `mc-`) yet fires on a
glued `mc-<hex>` token / canary. Both directions proven above (baseline SEC
`ok`; M6 SEC `not ok`). Logged in `datarim/tasks/ARAS-0040-auto-inline-log.md`.

## Restore

```
git checkout -- <each mutated file> ; cargo build --release
bash dev-tools/smoke/arcana-smoke.sh   # exit 0, not-ok=0
```
`sha256(restore) = f073776a98f556111c4a297b0eba660a05a7ecb6311cb2cdfd5982334e27a855`
— **identical to baseline** ⇒ the mutation run left no residue.
