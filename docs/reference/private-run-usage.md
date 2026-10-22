# Private run usage export

`arcana_core::usage_export::PrivateRunUsage::from_run(binding, &run_output)`
projects existing local run counters without I/O. CLI library consumers can use
`arcana_cli::usage::private_run_usage(&run_summary, binding)`. Construct correlation
with `RunUsageBinding::new(run_id, source_generation, request_digest, source_revision,
source_evidence_digest, receipt_ref)`;
the digests must be 64 lowercase hexadecimal characters and the source revision
40 lowercase hexadecimal characters. Syntax validation does
not authenticate any of those values. The resulting record is serializable as
`ArasPrivateRunUsage/v1` and has no deserialization or grant-construction API.

Keep the record in the existing private consumer ledger. There is no new CLI
command, HTTP route, public projection, scheduler, reservation store or provider
call. Public aggregate disclosure requires its existing owner's separate policy.
Do not publish raw correlation identifiers, usage rows or provider receipts.

## Meaning of the fields

`localCounters` copies cumulative `RunOutput.cost` counters as decimal strings.
The scope is `RUN_CUMULATIVE`, with coverage restricted to successful connector
responses. This is not per-item or per-attempt accounting. Integer strings retain
values above JavaScript's exact-number range without an additional float cast.
The legacy tracker itself receives f64 USD, rounds to micros, clamps invalid costs
to zero and saturates token input to u32 before aggregation. These limitations
remain; the export does not repair or authenticate those upstream measurements.

All four charge categories (estimate, reservation, observed and billed) remain
`UNKNOWN`, with null amounts. Missing input cost, cached tokens, CPU, RAM, elapsed
wall time, queue delay and network attribution remain null. A zero local counter
does not prove a free call. Connector errors, timeouts, cancellations and refusals
retain `OUTCOME_UNKNOWN` for this export and do not reset partial usage. Successful
local termination is `LOCAL_RUN_FINISHED_UNADMITTED`, not artifact acceptance.
The original terminal reason is retained without raw model text or error detail.

Atomic reservation, billed charge identity and per-attempt usage export are false; authenticated budget cap and physical hard caps are
null. Paid execution is `DENIED`, including through `paid_execution_allowed()`.
The optional legacy `CostBudgetHook` is not a hard financial reservation or physical
resource budget. No adapter field can turn `None` into unlimited paid authority.
Accepted-artifact count, acceptance receipt and cost per accepted artifact are
null because this producer has no authenticated acceptance or reconciled charges.

## Consumer integration boundary

This record is intentionally not `AtlasAttemptUsage/v1`. An Atlas adapter must
retain unknown charge and measurement coverage; it must not distribute a run's
aggregate across attempts or mark local cost as billed. The existing budget owner
must supply authenticated reserve/settle/reconcile evidence, and the physical
executor owner must supply actual enforceable bounds before a paid worker can be
activated. Missing bounds deny effects. Unknown consumed cost requires supported
reconciliation under the same attempt identity before retry. The initial cohort
and concurrency ceilings intersect real owner limits; this library invents none.

The private consumer owns persistence and immutable corrections. This export does
not claim durable reservations, concurrency safety, restart reconciliation,
complete provider billing, runtime installation or knowledge admission.

## CLI HTTP boundary qualification

The private adapter does not call HTTP. Its containing `usage` module also has
the existing read-only `GET /stats/requests/daily` reporting route. The bounded
`usage_canary_*` integration controls in `crates/cli/tests/usage_smoke.rs` run
the real CLI against a loopback fixture: exact stats credential and date window,
one GET without inference bearer credentials, malformed HTTP-200 refusal, and
missing-stats-token refusal with no HTTP request. These measurements establish
local CLI request/response behavior only. They do not authenticate the fixture as
a production connector, prove billing, grant reservation or caps, or measure
installed/live delivery. Canonical source qualification consumes separately
pinned executable, source and observer evidence.

## Bound consumer observation and allocation boundary

Use `PrivateRunUsage::from_bound_run(binding, &expected_binding, &run_output)`
or `arcana_cli::usage::bound_private_run_usage(&summary, binding, &expected_binding)`
when attaching an observation to an existing consumer plan. Every one of the six
fields, including receipt presence, must match before export. Errors disclose no
private field values. The successful record remains `ArasPrivateRunUsage/v1` and
`CALLER_SUPPLIED_UNVERIFIED`: equality does not authenticate a principal, task,
request, executor, source receipt, rights or revocation fence.

The existing consumer owns the allocation policy, persisted stratum-list digest,
`nextStratumIndex` and separate per-item completion cursor. It must pin them in
its versioned plan/request context and retain that context when constructing the
expected binding. A list revision requires a new explicit allocation plan; an old
numeric index cannot be applied to a reordered list. Missing allocation policy
means `PLAN_ONLY/NO_ALLOCATION`. This producer provides no allocation algorithm,
cursor persistence or authenticated plan digest. It neither computes a request
digest from a legacy plan nor resumes v1 plans as v2. Consumer policy limits the
combined occupation/competency cohort to at most 20 targets; related competencies
use only explicitly delegated unconsumed slots after the root cohort.

The consumer's versioned allocation request must retain its actual original demand
input and rank-output digests, target evidence and candidate snapshot, full ordered
cohort digest, policy and stratum-list digests, task/allocation-stream/batch/request
identity, and expected allocation revision/digest. These are proposed consumer
requirements, not fields supplied or authenticated by this wire v1 export. The
consumer must atomically advance its allocation-stream cursor and create the cohort
across batches; a per-batch completion cursor or batch lock does not provide that
serialization. Missing the authenticated resolver or allocation CAS leaves planning
only, with no invented context digest or allocation fairness claim.

Run-cumulative observations must never be divided among items or attempts, treated
as bills, release reserved liability, or make an unknown cost free after a timeout.
The consumer's authenticated task/principal/request/source/operation fence and
writer profile remain with its original authority owner; reserve/settle/reconcile,
billed identity and attempt usage remain with the genuine budget/connector owner.
Physical enforcement remains with the existing executor/Infra owner. These are
upstream requirements, not permissions implemented by this correlation adapter.
