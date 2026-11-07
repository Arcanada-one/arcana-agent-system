# Reading note for change-admission-ARAS-G07B-restart.json

The receipt is the raw `tools/graph/verify.py` draft for `9f122d7..6f2bd1b` (a new test file and a
CHANGELOG entry; no production code changed). Its three `verified` verdicts state only that
`v-fitness` found no new fitness violation and that five CHANGELOG references resolve. They say
nothing about operation identity across a restart.

Verdicts the receipt cannot carry, each `not_measured`:

| Property | Why not measured | What would measure it |
|----------|------------------|-----------------------|
| Durable attempt / intent / restart lineage | the agent loop / model-call path persists no identity (the `dispatch` audit record holds turn, model and sizes only); no store exists on that path and none was built. The separate `arcana-credential-broker` ledger is durable idempotency state outside this path (see REPORT.md inventory) | a durable intent store written before dispatch, owned by the ARAS/Muneral/connector owners |
| Real Model Connector behaviour | mocks only; no live provider | an isolated connector with a funded test tenant, restart between cut and replay |
| Held cost / reservation across restart | `CostTracker` is process-local | connector-side reservation read back after restart |
| Reconciliation workflow | no reconcile-required state exists across processes | a persisted reconcile state plus an operator or Muneral transition |
| Authoritative deadline across restart | `Instant` is process-local | deadline taken from the native attempt record |

The four new tests pin today's gap (they are green because they assert the unsafe behaviour). The
same assertions written as the safe property were red on 9f122d7.
