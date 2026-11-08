# Reading note for change-admission-ARAS-G05-final-dispatch.json

The receipt is the raw `tools/graph/verify.py` draft for the range `b3ac795..<head>` (ChangeAdmissionReceipt/v1).
Its `verified` verdicts state only what the verifiers named in the receipt measured
(fitness rules, CHANGELOG/document references). They do not speak to live authority,
provider effects or cost reservation.

What the tests in this change measured (mock connectors only; synthetic authority):

- final effective-dispatch guard at the `arcana-core` model-request and tool-effect
  boundaries (`CoverageComplete`, per-member `PreconditionsDischarged`, current
  authority, durable reservation through the existing G07 intent store);
- zero consequential effects for A-proven/B-unknown, covered-but-undischarged,
  revocation/expiry across an await, and clarification without authority;
- exactly one dispatch under an explicit synthetic authority positive control;
- unresolved prior intent refuses a fresh-key redispatch; after reconcile a later
  valid operation remains possible;
- D01–D08 / PR #276 store tests remain green; no second intent ledger.

Verdicts this change cannot carry, each `not_measured`:

| Property | Why not measured | What would measure it |
|----------|------------------|-----------------------|
| Native authority | Driver path has no effect-time authority field; tests use synthetic `CurrentAuthority::Current` | purpose-correct Auth/KC effect-time fence on every dispatch |
| Provider effect | mocks only; no Model Connector or provider was called | funded connector/provider call and charge counts |
| Cost reservation | `CostTracker` is process-local; ARAS holds no reservation | connector-side reservation read back after restart |
| Muneral reconcile join | no Muneral attempt/transition was read or written | native attempt record and a reconcile transition |

