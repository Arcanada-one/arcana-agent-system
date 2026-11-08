# Reading note for change-admission-ARAS-G05-round2-protected-no-dispatch.json

Round 3 added discriminating controls for the two no-dispatch fences
(`fresh_pending`/`held` and `handoff_count`) in
`crates/core/tests/g05_round3_fence_controls.rs`. Round 4 splits ND07 into
phase-accurate controls: pre-rename failure leaves prior Pending; post-rename
directory-sync failure leaves persistence uncertain (Pending or valid
NoDispatch on reopen); successful terminal write confirms NoDispatch only after
directory sync. Those tests remain mock-only; the NOT_MEASURED rows below are
unchanged.

The receipt is the raw `tools/graph/verify.py` draft for the range `b3ac795..<head>`
(ChangeAdmissionReceipt/v1) covering G05 round 2 (protected route + durable
proven-no-dispatch). Its `verified` verdicts state only what the verifiers named
in the receipt measured (fitness rules, CHANGELOG/document references). They do
not speak to live authority, provider effects or cost reservation.

What the tests in this change measured (mock connectors only; synthetic fixtures):

- composition-root `RouteProtection::Protected` refuses before effect when the
  gate or durable intent is absent; legacy `LegacyOutsideGuarantee` keeps the
  pre-G05 positive control; `ExecuteRequest` cannot carry protection;
- fresh Pending refused by the gate before handoff is durably resolved as
  IntentRecord v2 `Disposition::NoDispatch` with `refusal_reason` (exact key /
  identity / generation retained) under the exclusive lock;
- recovered Pending/Unknown never becomes no-dispatch (ND03/ND04); restart after
  durable no-dispatch returns the retained refusal (ND05); late attempt under the
  closed key cannot dispatch (ND06); ND07 pre-rename write failure leaves prior
  Pending; ND07 post-rename directory-sync failure does not dispatch or claim
  terminal success and reopen shows Pending or valid NoDispatch; ND07 successful
  terminal write persists NoDispatch; closed repeat vs new op (ND08); intent file
  does not assert a native budget reservation (ND11); v1 Reconciled + unknown
  version (ND12);
- G07 crash-after-Pending / PR #276 store tests remain green; no second ledger;
  no existing contract digest/canonical/hash line changes. Record schema digest
  is not pinned in-tree; versioning is explicit `RECORD_VERSION` (1) /
  `RECORD_VERSION_NO_DISPATCH` (2).

Verdicts this change cannot carry, each `not_measured`:

| Property | Why not measured | What would measure it |
|----------|------------------|-----------------------|
| Native authority | Driver path has no effect-time authority field; tests use synthetic `CurrentAuthority::Current` | purpose-correct Auth/KC effect-time fence on every dispatch |
| Provider effect | mocks only; no Model Connector or provider was called | funded connector/provider call and charge counts |
| Cost reservation / budget release | intent file never releases or asserts a native reservation (ND11) | connector-side reservation read back / settlement authority |
| Muneral reconcile join | no Muneral attempt/transition was read or written | native attempt record and a reconcile transition |
| ND09 native witness adapter | no authenticated composition-root witness that validates witness scope or refuses model→tool reuse | native witness adapter bound to exact action |
| ND10 real handoff fence | local `between_checks` recheck is not an atomic revocation/effect fence across network scheduling | ordered connector/executor handoff fence with authority |

