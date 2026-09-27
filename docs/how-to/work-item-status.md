# Read a work item's status

Set `ARCANA_MUNERAL_KEY_FILE` to the protected file holding your Muneral agent
key, then run:

```sh
arcana status --work-item b1227e82-da2b-4fee-aff6-b4ba8c6b01e3
```

The command reads the task row and its dependency readiness from Muneral and
prints one `WorkItemStatusObservation/v1` JSON object. It makes no model calls
and does not change the work item. You can call it from another terminal while
an execution is running. Both reads must be authorized for your agent.

`task_status`, `task_revision` and `task_updated_at` describe the stored row.
`task_observed_at` records when that response was received. A task marked `todo`
can have unsatisfied dependencies: `dependency_readiness.ready` is the separate
server-computed answer. It is not execution permission or a success verdict.
The dependency count can be nonzero even when all dependencies are satisfied.

The two reads are not an atomic snapshot (`consistency: separate_reads`).
Runtime progress is `not_measured` and runtime freshness is `unknown`: a row
update is not a heartbeat, a phase, a progress percentage, or an ETA. The
command has a five-second observation deadline; this is a timeout, not a
latency guarantee.

Exit codes:

- `0`: both reads produced valid, correlated observations. This does not mean
  the task is ready or complete; read the JSON values.
- `3`: the task was read, but dependency readiness is `unknown` with `ready: null`.
- `1`: no observation was emitted. Authentication denial, forbidden access and
  an invisible/missing task have the same `STATUS_NOT_ACCESSIBLE` error.

Access denial on the second read also suppresses the first response. Upstream
error bodies, task titles/descriptions and dependency titles are not printed.
`ARCANA_MUNERAL_URL` can select a local fixture endpoint for testing; normal
operation uses the existing Muneral API root.
