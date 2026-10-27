# DEC-AUP-0167 — Stage delivery: build first on the dev server, verify once per stage

Status: **ADOPTED 2026-10-18 ~14:45Z by operator order** (operator: "Ты сделал предложение по ускорению процесса. Я
поддерживаю. Надо это сделать"). Chair: Claude Root. Supersedes DEC-AUP-0166 (coverage-gap lane, never in effect).
Binding for every session on arcana-devs. Overrides PRODUCT-RESET rules 1, 3 and 7 where they conflict; the rest of
PRODUCT-RESET (no meta-work, 40-line Russian status, links as evidence) stays.

## Why
Per-feature delivery (PR → review → full CI → graph gate → merge to main) serialised all directions behind one shared
runner, strict up-to-date rebuilds and the graph gate's blind spots (workflow/shell/site JS → PAUSED_SAFE). On
2026-10-18 seven approved, CI-green PRs in five directions waited on the gate; a fix to the gate waited on the same gate.

## The order of work
1. **Build on the dev server, no per-feature gate.** Each direction has, per repo it works in, a branch
   `integration/<DIR>` in the private hub `/home/dev/aup/integration/<repo>.git`
   (create: `/home/dev/aup/integration/integ.sh <repo> <DIR>`). The hub is local to arcana-devs, never pushed to the
   product repos, runs no CI. Workers develop on feature branches in their own clones and merge them into
   `integration/<DIR>` (fast-forward/merge only; force and deletion are refused by the hub).
   Per feature, before merging into integration: the author's fast local tests on arcana-devs (minutes, under `nice`),
   gitleaks on the new commits, and one light independent look by the direction's reviewer (no gate, no CAR, no hosted CI).
2. **Stage = a finished, user-visible piece of product** (e.g. "atlas with generator and page", "Prime events visible in
   Control", "Datarim release"). The direction names its current stage and its completion criteria in its status.
3. **Stage check, once, when the stage is ready** (by readiness; at the latest every 48 h or when the stage diff
   exceeds ~60 files — then close what is done as a stage):
   1. merge current `main` into `integration/<DIR>` (merge, not rebase);
   2. end-to-end run of the stage on the dev server stand (build + start + the user path), recorded as evidence;
   3. review of the whole stage split by module across independent reviewers (Luna medium), each on the exact head;
   4. push the stage as branch `stage/<DIR>-<YYYYMMDD>` and open ONE PR to main.
      **Public repos** (datarim, sites, any PUBLIC repo): the stage branch is pushed only after the reviewers' APPROVE
      on the hub head — nothing unreviewed becomes public. Private repos may push first and review on the PR;
   5. full required CI once, graph gate once. Gate items NOT_MEASURED only because the verifier cannot see the entity
      type (workflow/shell/site JS) are covered by the stage's end-to-end evidence and recorded as NOT_MEASURED
      (never as pass); a real finding or failed check blocks the stage;
   6. gitleaks on the outgoing range, merge, deploy through the repo's normal deploy, live check.
4. **Shared repos** (arcanada-universal-program, arcanada-workspace, other multi-direction repos): one shared branch
   `integration/shared` owned by **ARC2**. Other directions push feature branches into the hub and ask ARC2 to merge;
   ARC2 runs the shared stage check.
5. **Already approved open PRs** (e.g. TALO site#278, FOOD site#16/#17 and fi10-atlas#1, I10 fi10-atlas#2/#3, PRIME
   control#182, KC #1612): merge their heads into the direction's `integration/<DIR>` now; they ship with the stage.
   Leave the GitHub PR open with a comment "folded into stage <DIR>, ships with stage PR"; close it when the stage merges.
6. **Muneral**: a task moves to `review` when its work is in integration, to `done` when its stage is merged and live.
7. **Backup**: `/home/dev/aup/integration/backup.sh` copies hub integration branches hourly to the private repo
   Arcanada-one/arcana-devs-backup-20261014 (gitleaks first, HELD on findings). JANITOR runs it in its hourly check.
8. **Stop**: ROOT-CODEX's DEC-0166 lane (Program PR486) and per-feature gate/CAR work for product PRs stop. ARC2's
   verifier PRs (#483/#484/#485) become part of the ARC2 shared stage, no longer a blocker for anyone.
9. **Freeze rule (replaces PRODUCT-RESET 7)**: a direction with no new commits toward its stage in `integration/<DIR>`
   for 4 h is frozen by ROOT-CODEX.

## Unchanged (hard rules)
Supreme Directive; secrets only in config/credentials or .secrets; gitleaks before every push; no force-push, no push to
main, no protection bypass; nothing unreviewed in public repos; production only from main; Publisher-only publishing.

## Evidence gate and reverse_if
Metrics, read by Claude Root every 2-hour check: stages merged to main and live per direction per day; rollbacks.
**reverse_if** within 7 days: more broken/rolled-back production deploys than in the 7 days before 2026-10-18, or a
secret/private material reaches a public repo through a stage — then return to per-feature delivery.
Program record: ARC2 adds this decision to `arcanada-universal-program/governance/decisions/` in its shared stage
(documentation only; the decision is in force from adoption, not from that merge).

## Addendum 2026-10-18 ~15:55Z — who decides sequencing
Ordering of a direction's own tasks inside its approved scope (starting source work ahead of a dependency's acceptance,
with the dependent linkage deferred and the task not closed until the dependency is accepted) is the **direction's own
decision**; cross-direction ordering is ROOT-CODEX's. Record it as one Muneral comment on the task and proceed. Never
route such a question to the operator or wait for the Claude Root. Example: D5A-T5.1 started ahead of T4.5 (78603b81).

## Addendum 2026-10-18 ~16:58Z — pre-existing failures are not stage findings
A gate/CAR FAILED verdict on an entity that is **byte-identical at the stage base (main) and the stage head** and is not in
the stage's change set is pre-existing debt of main, not a finding of the stage. Record it in the receipt as
`PRE_EXISTING_FAILED` (never as pass, never waived), route it once to the entity's owner, and do not block the stage on
it. A FAILED on any changed entity, or on an unchanged entity whose verdict the stage's change could affect (it consumes
changed code/config), still blocks. First case: workspace PR1618, `.github/workflows/paxbt-0168-in-session-executor.yml`
(blob 3c41ea6e both sides; PAXBT is outside the fleet — owner is the operator, managed from the Mac).

## Addendum 2026-10-18 ~18:30Z — Mac-managed projects are outside arcana-devs stage checks (operator correction)
Operator: the trading bot (PAXBT) is developed on the local MacBook and has nothing to do with this server. Its files
in shared repos (e.g. workspace `.github/workflows/paxbt-*`, any `paxbt`/`PAXBT` path; likewise TBT) are **out of scope**
for every arcana-devs stage check: record them in the receipt once as `OUT_OF_SCOPE_MAC_PROJECT` (never pass, never a
finding), do not route them to anyone, do not report them to the operator, and never read or edit them. This replaces the
"route to owner" step of the 16:58Z addendum for such paths; the PRE_EXISTING_FAILED rule stays for fleet-owned entities.

## Addendum 2026-10-18 ~18:25Z — merge criteria for a stage PR (Claude Root correction: gate drift)
At 18:18Z five stage PRs (FOOD#18, TALO#281, PRIME control#184, I10 site#16, workspace#1618) were CLEAN with green
required CI, yet held for "native proofs" of NOT_MEASURED items and verifier/consumer fixes. That is the per-feature gate
spiral this decision removed. A stage PR merges as soon as ALL of these hold on its exact head:
1. required CI green; 2. stage review APPROVE (whole stage, exact head); 3. end-to-end evidence of the stage's user path
recorded; 4. gitleaks clean on the outgoing range; 5. graph gate / CAR has **0 FAILED on changed entities**
(PRE_EXISTING_FAILED and OUT_OF_SCOPE_MAC_PROJECT excluded).
- NOT_MEASURED never blocks and needs **no** native proof, re-derivation or coverage claim: record it as NM, covered by
  item 3. Do not build or wait for verifier/consumer/input-contract fixes (KC, ARC2) as a precondition of another stage;
  those fixes ship in ARC2's own stage.
- A local tool difference (e.g. Node 24 locally vs Node 22 in CI) is settled by the green CI run, not a re-run.
- Then: merge (normal, no bypass), deploy through the repo's normal path, live check, status line "shipped".
ROOT-CODEX applies this today: each listed PR merged by 19:30Z or one named real FAILED/finding that blocks it.
