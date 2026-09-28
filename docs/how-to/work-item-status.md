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

## Watch stored completion without interactive input

```sh
arcana status --work-item b1227e82-da2b-4fee-aff6-b4ba8c6b01e3 \
  --watch --timeout-secs 60 --interval-secs 5
```

The watch emits JSONL observations followed by one `WorkItemWatchResult/v1`.
Its predicate is **stored task completion**: dependency readiness alone never
ends the watch. Each poll reuses the same authenticated reads and emits fresh
observation times, even when the task row has not changed. It never reads stdin
or asks a question. It makes no model calls and sends no notifications.

The final result has three outcomes with distinct exit codes and messages:

| Outcome | Exit | Meaning |
|---|---|---|
| `ready` | 0 | `TASK_DONE`: Muneral records `done`; independent acceptance is not measured |
| `not_ready` | 1 | `TASK_CANCELLED`: Muneral records `cancelled` |
| `indeterminate` | 3 | A valid completion observation could not be obtained; read `reason` |

`todo`, `in_progress`, `review` and `blocked` continue polling. `archived`
returns `ARCHIVED_COMPLETION_UNKNOWN`: the current row does not reveal whether
the work was completed before archiving. An unavailable or invalid readiness
response returns `DEPENDENCY_READINESS_UNDETERMINED`, even if the task row says
`done`. Missing or invalid task fields return `STATUS_INVALID_RESPONSE`.

The timeout is required, from 1 to 3600 seconds. The interval defaults to 5
seconds and accepts 1 to 60; interval/timeout options require `--watch`.
Invalid arguments exit 2 before reading Muneral. The monotonic deadline covers
network waits and sleeps, including the first request, and ends with
`WATCH_DEADLINE_EXPIRED`. This always means **indeterminate**, even after a
previous valid observation with false dependency readiness. Each observation
also has a five-second bound (`STATUS_OBSERVATION_TIMEOUT`). These bounds do
not guarantee a service latency or unblock an OS stdout pipe that nobody reads.

Access denial stops polling immediately with `STATUS_NOT_ACCESSIBLE` and
suppresses the entire denied poll. Older printed observations are historical;
the final result supersedes them for this invocation. A broken output stream
exits 3 with `WATCH_OUTPUT_UNAVAILABLE` on stderr if stderr is available.

All watch results retain `independent_acceptance: not_measured`. They do not
check run-evidence attachments, runtime heartbeat, executor idleness, elapsed
idle cost, notification delivery or cancellation fencing. The original
single-observation command and its exit-code meanings remain unchanged.
