# Reference: architecture

> Bootstrap stub. Replaces narrative once the upcoming PRD ratifies the system map.

## High-level layout

```
crates/cli       Binary `arcana` — args, REPL loop, slash dispatcher, terminal UI.
crates/core      Library — agent loop, tool dispatcher, context manager, hooks, permissions.
crates/supervisor Library — process-group-owning child supervisor: heartbeat/timeout watchdog, restart/escalation, concurrency + cost budgets.
crates/connectors (planned) — Auth Arcana, Model Connector, Vault, Scrutator, LTM, Ops Bot, Coworker.
crates/tools      (planned) — Read, Edit, Write, Bash, Grep, WebFetch.
crates/mcp        Adapter — exposes the capability core as an MCP server (`arcana mcp serve`).
```

## H-MCP-seam (`crates/mcp`)

A **pure adapter** (no new permission/tool/hook/audit logic) that answers MCP
`tools/list` / `tools/call` over a Tier-1 loopback transport (stdio, or an
optional `--bind` loopback HTTP listener). Its response envelope extends vanilla
MCP with `structured_content.arcana.effective_args` (the post-`ReplaceInput`
input the tool executed on) and an `interaction_required` suspend/resume channel
for `Defer` decisions (`oneshot` + `Mutex<HashMap>` in-process — no broker).
`crates/cli` depends on `crates/mcp` for the `mcp serve` entrypoint; the
dependency edge is one-way. See [`mcp-server.md`](mcp-server.md).

The seam's only touch to `crates/core` is a read-only field,
`CapabilityOutput.effective_input`: the cascade's already-audited
`transformed_input`, surfaced (not recomputed) so the adapter can report
`effective_args` without re-running the cascade or double-auditing.

## Architectural references

Reference-only — patterns and contracts, never copy. The implementation draws on prior-art coding-agent architectures (state-machine agent loops, typed tool dispatch with permission gates, MCP-compatible tool surfaces).

## Rust adaptation notes (Phase 1 input)

1. **Agent loop** — state machine driven by `tokio` runtime; one task per LLM call; tools dispatched via `tower::Service`-like trait.
2. **Tool calling** — typed traits per tool family; serde-defined params/results; permission gate runs *before* dispatch.
3. **Context window** — manual budget accounting (no JS-style runtime introspection); explicit `Compactor` trait for context pruning.
4. **Hooks** — config-driven shell exec via `tokio::process::Command`; envelope: env vars + stdin JSON.
5. **MCP** — JSON-RPC over stdio/HTTP via `serde_json` + `tokio::io`. Optional crate `rmcp` if maturity acceptable; otherwise hand-rolled.

## Data flow (target Phase 2)

```
user input → REPL → core::agent_loop
                       │
                       ├─ context::pack()
                       ├─ connectors::model_connector::call() (preferred) or direct provider
                       └─ capability executor
                            (registry → cascade → hooks → final schema check
                             → decision audit → move-only invocation → tool
                             → terminal audit)
                       │
                       ↓
                    terminal UI render
```

## Capability execution trust boundary

`CapabilityExecutor` is the only execution authority. It consumes a mutable
`ToolDispatcher` at construction, freezing the registry, and owns the
permission cascade, non-audit hooks, and mandatory synchronous audit sink.
There is no public dispatcher lookup or raw-value execution function.
`Tool::execute` requires a private-field, non-`Clone` `ToolInvocation`; only the
executor can construct one, and it moves the invocation directly into the
registered implementation.

An attempt validates the raw payload, walks the cascade, then runs the
executor-owned pre-tool hooks as a **veto/side-effect gate only** — the cascade
is the sole input-transform authority, so those hooks cannot change the executed
value (their outcome type carries no input; a post-cascade transform is a
compile error). It then validates the cascade-authorized payload again
immediately before writing the allow decision and invoking the tool. Empty or
all-`Defer` cascades deny (fail-closed).
The audit format is version 2: one `decision` and one terminal `result` record
share an `invocation_id`; records carry hashes, never raw input/output or error
text. A decision-write failure executes zero tools. A result-write failure is
fatal and latches the executor closed for all later attempts. Because the audit
sink is not a `ToolHook`, callers cannot double-bridge the audit authority.

Filesystem tools (`Read`, `Write`, `Edit`) additionally route their `path`
argument through `crates/tools/src/path_guard.rs::check()` before any I/O — a
tool-internal seam against path traversal (CWE-22). The guard canonicalizes the
input and matches it against the active `ToolRuleSet` deny/allow paths. Matches
block the call with `ToolError::PermissionDenied`.

`Tool::default()` ships a permissive rule set so existing call sites are not regressed. Production rule loading — wiring a real `ToolRuleSet` derived from `permissions.toml` into the tool constructors — is the next step on the permission stack and lands in a follow-up CLI bootstrap task.

## Supervisor (`crates/supervisor`)

Supervises OS children — the mechanism by which the runtime keeps long-running
work terminable (Supreme Directive law 4). Full API in
`docs/reference/supervisor.md`. Summary:

- **Process-group ownership** at spawn (`process_group(0)` — safe std/tokio API):
  each child leads its own group, so a forked grandchild cannot escape shutdown.
- **Terminate sequence** — `SIGTERM` → grace → `SIGKILL` to the whole group
  (`nix::killpg`), then reap the direct child. `SIGKILL` is un-blockable, so a
  child that blocks/ignores `SIGTERM` is still killed.
- **Heartbeat watchdog** — a stdout line-protocol (`READY` / `HEARTBEAT <seq>` /
  `STATUS`) republishes liveness; a silent child past `heartbeat_timeout` is
  terminated. Per-child readers are **independent async tasks**, so a frozen
  (`SIGSTOP`'d) child never starves its siblings.
- **Wall-clock deadline** bounds runaway work independently of liveness.
- **Budgets** — a `Semaphore` caps concurrency; the reused
  `core::cost::CostTracker::check_budget` caps aggregate cost.
- **Restart/escalation** — a bounded `RestartPolicy` restarts a crash-looping
  child, then returns terminal `Escalated` (a signal + an audit event, never an
  autonomous hard-gated action).
- **Audit** — every lifecycle event routes through the additive
  `core::hooks::audit::AuditLog::record_event` seam into the **same** Blake3
  `audit.log`; only hashes are stored (`fields_hash`), never raw fields. No
  second audit sink; Tier-0 (no network listener).

## Ecosystem boundaries (mandates apply)

- All identity through Auth Arcana (per the Arcanada Auth Arcana Mandate).
- All LLM calls through Model Connector unless a documented Risk waives it.
- All secrets via Vault scoped service-account (Operational Resilience Mandate).
- All self-heal events → Ops Bot.

A detailed product requirements document is tracked in internal workflow and lands in upcoming releases.
