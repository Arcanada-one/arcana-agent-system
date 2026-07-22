# Reference: supervisor

`crates/supervisor` (`arcana-supervisor`) supervises OS child processes with
process-group ownership, liveness and deadline watchdogs, bounded restarts, and
concurrency/cost budgets. It depends only on `arcana-core` (audit + cost) and is
fully offline-testable. Rust-only; `unsafe_code = "forbid"` is upheld (safe
`std`/`tokio`/`nix` wrappers, no raw `libc`).

## Security stance

Tier-0: there is **no network listener**. The heartbeat is a line-protocol over
the child's already-owned stdout file descriptor — no socket, bind, or accept.
Lifecycle events are written only through the shared Blake3 `audit.log`; the
supervisor never opens a second audit sink, and only hashes are persisted.

## `Supervisor`

```rust
let supervisor = Supervisor::new(config, audit /* Arc<AuditLog> */, cost /* Arc<CostTracker> */);
let handle = supervisor.spawn(spec).await?;   // ChildHandle
let outcome = handle.wait().await;            // SupervisionOutcome
supervisor.cancel();                          // cooperative shutdown of all children
```

- `new(config, audit, cost)` — construct over a **shared** audit log and cost
  tracker.
- `spawn(spec) -> Result<ChildHandle, SupervisorError>` — blocks until a
  concurrency permit is free, spawns a process-group-owning child, records a
  `spawn` event, and starts the per-child watchdog. If the aggregate-cost budget
  is already exceeded the spawn is refused with `SupervisorError::BudgetExceeded`
  after an `escalate` event.
- `cancel()` / `cancel_token()` — cooperative cancellation; each supervised child
  is force-terminated and its task resolves to `Escalated`.

### `ChildHandle`

- `id() -> u64`, `pid() -> Pid`, `pgid() -> Pid`.
- `last_heartbeat() -> Instant` — non-blocking read of the child's liveness watch
  channel.
- `wait(self) -> SupervisionOutcome` — await the terminal outcome.

## Configuration

```rust
SupervisorConfig {
    correlation_id: String,      // stamped on every audit line
    heartbeat_timeout: Duration, // silence past this ⇒ terminate
    wall_clock: Duration,        // absolute per-child deadline from spawn
    grace: Duration,             // SIGTERM→SIGKILL window
    max_concurrent_children: usize,
    max_cost_usd: Option<f64>,   // None ⇒ no cost cap
    restart: RestartPolicy,
    tick: Duration,              // watch-loop poll interval
}

RestartPolicy { max_restarts: u32, backoff_base: Duration, backoff_cap: Duration, window: Duration }
```

`SupervisorConfig::default()` provides safe defaults (5s heartbeat, 60s
wall-clock, 2s grace, 8 concurrent, no cost cap, 20ms tick).

## Outcomes and lifecycle events

`SupervisionOutcome` is `Completed { child_id }` (clean exit) or
`Escalated { child_id, reason }` (timeout, cancellation, or restart exhaustion).

Audit `kind` tokens (all under `"phase": "supervisor"`): `spawn`,
`heartbeat_timeout`, `wall_clock_timeout`, `restart`, `escalate`, `terminate`.
Each record stores `correlation_id`, `kind`, and `fields_hash` (Blake3, hashes
only — never raw fields).

## Heartbeat line-protocol

The supervisor owns each child's stdout pipe and reads it in an **independent**
async task per child. Recognised, prefix-matched lines republish liveness:

- `READY` — the child has started.
- `HEARTBEAT <seq>` — the child is alive.
- `STATUS <...>` — a status line (also counts as liveness).

Because the readers are independent tasks, a frozen (`SIGSTOP`'d) child — whose
pipe never yields a line — cannot starve the servicing of its siblings.

## Terminate sequence

`terminate_group(pgid, grace, child, audit, correlation_id)` sends `SIGTERM` to
the **whole process group**, waits up to `grace` for the direct child to exit,
and — if it is still alive — sends the un-blockable `SIGKILL`. The direct child
is always reaped afterwards (a zombie still answers `kill(pid, 0)`, so reaping is
required for an `ESRCH` liveness probe to be meaningful). `ESRCH` from a signal
(the group already exited) is benign and ignored.

## `heartbeat-child` test fixture

`src/bin/heartbeat-child.rs` is an offline fixture (no network, no ecosystem
services) used by the chaos/watchdog tests. It emits the heartbeat protocol,
**flushing** each line (a piped stdout is block-buffered), and tolerates a closed
reader pipe so terminability is exercised via signals only. Flags: `--interval`,
`--heartbeats`, `--exit-code`, `--stop-heartbeat-after`, `--ignore-term` (blocks
`SIGTERM` via safe `sigprocmask`, never an `unsafe` disposition install), and
`--spawn-grandchild` (forks a second, silent `heartbeat-child --ignore-term` into
the same process group; it survives `SIGTERM` and the parent's `kill_on_drop`, so
only the explicit group `SIGKILL` reaches it — the discriminator behind the
V-AC-2 and V-AC-9 group-`ESRCH` assertions).
