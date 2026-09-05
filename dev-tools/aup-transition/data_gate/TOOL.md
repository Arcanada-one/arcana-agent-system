# `tools/mig/data_gate` — AUP-MIG-015 `gate0`: data-gate consumer + cutover authority verifier

Two verifiers that never touch each other's evidence, joined only by conjunction at the very end.
The gate answers one question — *may a production/general cutoff be declared ready?* — and it
answers it with a `CutoverReadinessAttestation/v1` **only** when both halves pass. Anything else is
a `BlockReceipt/v1` with typed reason codes. Contract:
[`contracts/cutover/cutover-readiness-attestation.v1.json`](../../../contracts/cutover/cutover-readiness-attestation.v1.json).

```bash
python3 tools/mig/data_gate/consume_data_gate.py --selftest          # must end "selftest 42/42 PASS"
python3 tools/mig/data_gate/consume_data_gate.py consume             # -> receipts/mig/gate0-<ts>.json + the artifact
python3 tools/mig/data_gate/consume_data_gate.py consume --ws-head <sha>   # override the observed source-set head
```

Read-only, stdlib only. Its only writes are the two receipts under `--out`.

## The data half — three planes, six rows

| row | files | Muneral | index |
|---|---|---|---|
| active / planned / completed / cancelled / **archived** | occurrences read from git objects at the pinned `SourceSetEpoch`, classified through the `HistoricalStatusMap` revision **of record** | the projections the store actually holds (produced under the **batch's** revision) plus its readback | what the KB/Scrutator history namespace acknowledges |
| unindexed | files planned for the namespace | identities read back | acknowledged |
| conflicts | AUP-DAT-007 conflicts over all roots | within-root conflicts HELD at the batch epoch | indexed conflicts |

`archived` is a row of its own and is **never** folded into `completed`: an archive card records that
a card left the board — terminal and unverified (DEC-AUP-0014 rule 3). Folding it into completion is
exactly the silent totalisation I4 forbids, and it is the difference the gate measures today.

Raw source values reach a class **only** through the versioned status map, so the tool holds exactly
one hand-written table (Muneral status → row) and cannot invent a competing mapping of its own. A raw
value with no entry in the map is a typed `UNMAPPED` refusal, never a default. The files plane is read
through the map of record and the store plane through the batch's map, so the gap between two map
revisions is *measured*, not assumed away.

The data half also checks: the dossier is pinned to an exact, resolvable revision and carries its own
verdict; the epoch is git-pinned, is the corpus the dossier measured, and is **still the head of the
source set** (a moved source set invalidates DAT-020/MIG-015 and demands revalidation); the byte copy
is proven; a restore has actually been **drilled** (a backup that was never restored is not a backup);
and every host declared a clean read-through with no source mount or cache.

## The authority half — a decision, not a person

Under DEC-AUP-0010 and DEC-AUP-0012 the `AuthorizationDecision` of AUP-E25 § MIG-015 is replaced by a
program decision with an evidence gate. The authority ref is therefore **decision id + the digests of
its gate receipts**. The verifier reads: issuer; action / resources / hosts / permitted target
generation (from a versioned profile whose every assertion must be found verbatim in the decision or
in a decision it incorporates by reference — an assertion that cannot be found is `NOT_MEASURED` and
blocks, so the profile can never drift away from the decision it claims to read); expiry (each
`reverse_if` condition, one by one); revocation (any later decision superseding it); and the persisted
state machine, which must stand at or beyond `ROLLBACK_DRILLED`. No persisted state means the machine
stands at `FILES_AUTHORITATIVE` and the authority is not in effect.

**The gate mints no authority and never turns a data PASS into permission.** The identity that signs
the data half is compared against the authority issuer; equality blocks
(`AUTHORITY_SIGNER_IS_DATA_SIGNER`). The attestation carries two refs or it is not an attestation.

## Selftest = evidence, not reassurance

`--selftest` is wholly synthetic: it never reads a real receipt. It runs

* **14 fixtures**, including the four failure scenarios the spec names — search finds a document but
  the store lost the transition (`search_finds_but_store_lost_transition`), a canary on a hidden mount
  (`canary_on_hidden_mount`), a data PASS misread as approval (`data_pass_misread_as_approval`), the
  authority expiring before the fence (`authority_expired_before_fence`) — plus a wholly green control
  that must mint a real two-ref attestation, otherwise the whole battery would be vacuous;
* a **mutation battery**: 14 mutants, each disabling exactly one protective rule (a missing plane stops
  blocking, `NOT_MEASURED` collapses into PASS, a stale epoch is ignored, a data PASS mints on its own,
  a revoked or expired authority is accepted, the attestation drops its authority ref, the attestation
  claims a writer-epoch change, …). **Every mutant must be killed by at least one fixture**;
* a **rule battery**: each of the five oracle rules must somewhere be the *only* rule that fires,
  otherwise it is untested and could be deleted without the battery noticing;
* a **negative control** of the battery itself (an inert mutant must be killed by nothing), a
  determinism check, and the mapping-revision test that proves the tool measures the difference
  between status-map revisions rather than normalising it away.

## Not measured here

Whether any imported historical `done` is true (I14: asserted, never verified). The semantics behind
the status values. Any host, service or repository state not already carried by a receipt on program
main — in particular the source-set head is read from the newest `FenceObservationReceipt`, never by a
live fetch of the shared workspace checkout.
