# Reading note for change-admission-ARAS-G07D-intent.json

The receipt is the raw `tools/graph/verify.py` draft for the range `9f122d7..<head>` (the `ChangeAdmissionReceipt/v1`
shape merged in PR #272). Its `verified` verdicts state only what the verifiers named in the receipt measured
(fitness rules, CHANGELOG/document references). They do not speak to restart identity, durability or isolation.

What the tests in this change measured (mock connectors only, a real temporary filesystem):

- the order admit -> reconcile retained record -> persist `pending` -> dispatch, on the `arcana-core` call boundary;
- zero dispatch and the original key kept for: restart after an unknown outcome, changed request, conflicting
  attempt/lease/plan/deadline, a held unknown outcome without verified replay, an unwritable store, a corrupt,
  truncated, misfiled, oversized or competing record, a second driver, a parent swap, a symlinked path;
- five mutants of the new code (persist failure ignored, retained record ignored, lock removed, binding conflict
  unchecked, replay flag ignored) each turn at least one of those tests red.

Verdicts this change cannot carry, each `not_measured`:

| Property | Why not measured | What would measure it |
|----------|------------------|-----------------------|
| Native Model Connector intent | mocks only; no connector or provider was called | an isolated connector with a funded test tenant, restart between cut and replay |
| Actual provider effect | same | provider-side call and charge counts read independently |
| Cost reservation / held cost across restart | `CostTracker` is process-local; ARAS has no reservation | connector-side reservation read back after restart (G08) |
| Reconcile join with Muneral | no Muneral attempt/transition was read or written | native attempt record and a reconcile transition |
| Verified connector idempotency | `same_key_replay_verified` is a caller-asserted flag; nothing here verifies the connector | a replay probe against the real connector |
| Native admission of task/lease/plan/deadline | the binding is caller-supplied; ARAS reads no authority; the deadline check uses the local wall clock | a purpose-correct authority read on every operation |
| Durability under power loss / other filesystems | fsync calls are in the source; no fault injection was run | crash-consistency test on the target filesystem |
| CLI wiring | the CLI has no source for the native fields, so it does not enable the record | a native attempt binding in `arcana run` |
