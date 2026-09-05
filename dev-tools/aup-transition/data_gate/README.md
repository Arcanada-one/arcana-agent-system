# `aup-transition/data_gate` — cutover data gate + authority verifier (PROPOSAL)

Proposal landing of the AUP-MIG-015 `gate0` tooling built in
[`Arcanada-one/arcanada-universal-program`](https://github.com/Arcanada-one/arcanada-universal-program)
(`tools/mig/data_gate/`, contract `contracts/cutover/cutover-readiness-attestation.v1.json`).

**Why this repository.** AUP-E25 § AUP-MIG-015 names `Arcanada-one/arcanada` as the owner repo of the
host wiring. That repository **does not exist in the `Arcanada-one` organisation** (verified
2026-09-05 against the org's 69 repositories). Rather than invent a repository or stall the card, the
proposal lands where the sibling AUP-MIG-014 `fault_drill` proposal already sits — `dev-tools/aup-transition/`
in this repository (see PR #151). If a repository the broker actually owns appears later, moving this
directory there is a rename, nothing more.

**This is a proposal.** Nothing here is wired into anything, nothing is deployed, and the change is not
admin-merged: it goes through this repository's own flow and its reviewers. The program repository
carries the receipts; this copy carries the code.

## What it does

Two verifiers joined only by conjunction:

* the **data** half consumes an acceptance dossier at an exact revision and reads
  active / planned / completed / cancelled, unindexed and conflicts through **three** planes (files at
  the pinned `SourceSetEpoch`, the work-item store, the KB/Scrutator index). `archived` is a row of its
  own and is never folded into `completed`. Raw source values reach a class only through a versioned
  status map, so the tool holds exactly one hand-written table and an unmapped value is a typed refusal;
* the **authority** half reads the current state of a program decision's evidence gate — issuer, action,
  resources/hosts, permitted target generation, expiry (`reverse_if`) and revocation — instead of a human
  approval, and refuses to treat the data signer as the authority issuer;
* a `CutoverReadinessAttestation/v1` with **two** refs is minted only when both halves pass. Anything
  else is a `BlockReceipt/v1` with typed reason codes. **A data PASS is never permission**, and the
  writer epoch is never changed.

Full documentation: [`TOOL.md`](TOOL.md). Contract: [`cutover-readiness-attestation.v1.json`](cutover-readiness-attestation.v1.json).

## Verify this copy

```bash
python3 dev-tools/aup-transition/data_gate/consume_data_gate.py --selftest   # -> "selftest 45/45 PASS"
```

Stdlib only, no network, no repository state touched — the selftest is wholly synthetic (14 fixtures, a
14-mutant battery in which every mutant must be killed, a rule battery in which each oracle rule must
somewhere be the only one that fires, a negative control, a determinism check, and the contract-conformance
assertions). It resolves its contract from a copy beside it, so this landing copy verifies itself.
