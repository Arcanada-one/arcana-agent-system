# Reference: MCP server (`arcana mcp serve`)

Information-oriented reference for the H-MCP-seam: the arcana capability core
exposed as a Model Context Protocol server. The `crates/mcp` crate is a **pure
adapter** over the existing `ToolDispatcher` + `PermissionCascade` +
`CapabilityExecutor` (with hooks and the mandatory audit log). It adds no
permission, tool, hook, or audit logic.

## Command surface

```
arcana mcp serve            # stdio transport (no socket)
arcana mcp serve --bind ADDR  # loopback HTTP transport (Tier-1)
```

- **stdio** (default) — the server speaks JSON-RPC over stdin/stdout. No socket
  is opened; nothing is reachable off-host.
- **`--bind ADDR`** — a loopback HTTP listener. `ADDR` **must** be a loopback
  socket address (`127.0.0.0/8` or `::1`). Any non-loopback address — including
  a Tailscale mesh IP — is refused **before** the listener is created (see
  [Bind guard](#bind-guard)). The loopback HTTP path requires the default
  `http` build feature.

## Transports and tiers

This server is **Tier-1 (loopback)**, strictly below the Tier-2 mesh tier that
`dev-tools/network-exposure-check.sh` governs. It is deliberately **not** listed
in the mesh-exposure descriptor: a loopback entry would fail that gate's
mesh-IP rule. The crate's own bind guard is stricter than the mesh script — it
refuses even a mesh IP — so the server can never escalate to a tier that would
require a descriptor entry.

## The extended envelope

Vanilla MCP `CallToolResult` cannot express two facts the capability core
produces. Both ride vanilla-compatible extension points, so a plain MCP client
still parses `content` while an arcana-aware client reads the extension.

### `structured_content.arcana`

```jsonc
{
  "arcana": {
    "status": "completed" | "interaction_required" | "denied",
    "effective_args": { /* the post-ReplaceInput input the tool executed on */ } | null,
    "interaction_required": {
      "token": "<uuid v4>",
      "tool": "<tool name>",
      "prompt": "<human prompt>",
      "pending_input": { /* current pre-resolution input */ }
    } | null
  }
}
```

- **`effective_args`** — the cascade-authorized input the tool actually
  executed on. When a `ReplaceInput` rule fired, `effective_args` differs from
  the caller's `input`. Present (`Some`) on `completed`; `null` otherwise.
- **`interaction_required`** — present only on `interaction_required`; carries
  the resume token.

### `_meta` fast-flags

```jsonc
{ "arcana.status": "...", "arcana.interaction_token": "..." }
```

Routing hints for a caller that does not want to parse `structured_content`.
`arcana.interaction_token` is present only when a call suspended.

### `is_error`

`null` for `completed` and `interaction_required` (a suspension is a valid
state, not an error); `true` for `denied`.

## Suspend / resume (`Defer` decisions)

When the permission cascade reaches a `Defer` at its terminal layer, the
adapter suspends the call instead of resolving it against a terminal prompt:

1. `tools/call` returns `status: "interaction_required"` with a server-minted
   uuid v4 `token`. The underlying capability call is parked in-process.
2. The caller resolves it with the `arcana.resume` control tool:

   ```jsonc
   // arcana.resume arguments
   { "token": "<token>", "resolution": "allow" }
   { "token": "<token>", "resolution": "deny" }
   { "token": "<token>", "resolution": { "replace_input": { /* new args */ } } }
   ```

3. `arcana.resume` returns the final envelope: `completed` (carrying the real
   `effective_args`) on `allow` / `replace_input`, or `denied` on `deny`.

`arcana.resume` is a control tool: it is **never** listed by `tools/list`
(which returns exactly the capability-core tool set). An unknown or expired
token resolves to a `denied` envelope.

### State model

Suspend/resume is **in-process tokio only** — `oneshot` channels plus a
per-process `Mutex<HashMap<token, pending>>`. There is **no queue and no
broker**. A suspended call is a parked async task keyed by its token; it dies
with the process (Tier-1, single operator, non-durable by design). The resolved
dependency tree contains no Kafka / AMQP / broker crate.

## Security

- Every `tools/call` routes through the **unchanged** `PermissionCascade` +
  `CapabilityExecutor`: Schema → Rule → terminal SuspendLayer, with the single
  Blake3 audit line per attempt. MCP tools stay deny-by-default.
- `effective_args` exposes only the value already written to the audit log — no
  new disclosure.
- `--bind` refuses any non-loopback address before binding; the HTTP transport
  additionally restricts the `Host` header to loopback (anti DNS-rebinding).

## The single core touch

The adapter reads the cascade's transformed input via a read-only field added
to the core: `CapabilityOutput.effective_input` (populated from the
post-`ReplaceInput` prepared input in `CapabilityExecutor::invoke`). No other
core behaviour changes — the value already flowed through execution and was
audited; the field only surfaces it to an out-of-crate adapter.

## See also

- [`architecture.md`](architecture.md) — component map.
- [`cli-exit-codes.md`](cli-exit-codes.md) — `arcana mcp serve` exit codes.
- [`permissions-toml.md`](permissions-toml.md) — the rule layer the cascade reuses.
