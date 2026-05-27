# Reference: architecture

> Bootstrap stub. Replaces narrative once the upcoming PRD ratifies the system map.

## High-level layout

```
crates/cli       Binary `arcana` — args, REPL loop, slash dispatcher, terminal UI.
crates/core      Library — agent loop, tool dispatcher, context manager, hooks, permissions.
crates/connectors (planned) — Auth Arcana, Model Connector, Vault, Scrutator, LTM, Ops Bot, Coworker.
crates/tools      (planned) — Read, Edit, Write, Bash, Grep, WebFetch.
```

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
                       ├─ tool dispatcher (permission gate → tool exec → result envelope)
                       └─ hooks (pre/post)
                       │
                       ↓
                    terminal UI render
```

## Permission layer

The cascade `Schema → HookBridge → Rule → Interactive` runs ahead of every tool dispatch (see `crates/core/src/permission/`). Filesystem tools (`Read`, `Write`, `Edit`) additionally route their `path` argument through `crates/tools/src/path_guard.rs::check()` before any I/O — a tool-internal seam against path traversal (CWE-22). The guard canonicalizes the input (resolving `..`, `.`, symlinks) and matches the canonical `PathBuf` against the active `ToolRuleSet`'s `deny_paths` and `allow_paths`. Matches block the call with `ToolError::PermissionDenied`.

`Tool::default()` ships a permissive rule set so existing call sites are not regressed. Production rule loading — wiring a real `ToolRuleSet` derived from `permissions.toml` into the tool constructors — is the next step on the permission stack and lands in a follow-up CLI bootstrap task.

## Ecosystem boundaries (mandates apply)

- All identity through Auth Arcana (per the Arcanada Auth Arcana Mandate).
- All LLM calls through Model Connector unless a documented Risk waives it.
- All secrets via Vault scoped service-account (Operational Resilience Mandate).
- All self-heal events → Ops Bot.

A detailed product requirements document is tracked in internal workflow and lands in upcoming releases.
