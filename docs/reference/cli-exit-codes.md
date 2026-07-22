# CLI exit codes & connector environment

Information-oriented reference for the `arcana` subcommand exit-code namespace
and the Model-Connector environment overrides.

## Exit-code namespace

`arcana` subcommands use the following outcome namespace so an automated caller
(CI, the smoke gate) can tell a dead capability from an infrastructure error.
Not every subcommand emits every code:

| Code | Meaning | Examples |
|------|---------|----------|
| `0` | Success — the capability ran and produced a positive result. | `whoami` cascade Allowed with a non-empty audit record; `mc-ping` returned a non-empty `result`; `kb-read` completed exactly one authenticated search with nonzero hits and cited a returned `source_path`. |
| `1` | Operational / infrastructure error, or a fail-closed `kb-read` grounding failure. | bootstrap failure; async-runtime start failure; connector transport error (DNS/TLS/connect/timeout); the advertised audit-log path is missing or empty; `kb-read` credential, audit, search-count, hit, or citation failure. |
| `2` | Capability-assertion failed — the probe ran, but the capability is dead. | `whoami` cascade **Denied**; `mc-ping` got a degenerate `201 {"status":"success","result":""}` (empty result). |

Rationale: control-plane green (exit 0) while the data plane is dead is the
dominant false-green failure mode. A blanket `0` on any `Ok(response)` or on a
denied cascade hides a broken capability behind a passing check. Splitting
"the probe could not run" (`1`) from "the probe ran and the capability is dead"
(`2`) lets a harness record `SKIP(env:unreachable)` for a transport error while
still failing hard on a degenerate result.

### `mc-ping` error discrimination

`mc-ping` maps **every** `ConnectorError` to a single non-zero code — the exit
code cannot tell *which* contract failed. Assert on the stderr `Display`
message instead:

| Condition | stderr substring |
|-----------|------------------|
| `ARCANA_MC_TOKEN` unset/empty | `missing API key (set ARCANA_MC_TOKEN)` |
| upstream HTTP 200 (only 201 is success) | `unexpected HTTP status 200 (expected 201)` |
| `201 {"status":"error"}` | `upstream logical error [<kind>]: <message>` |
| transport failure | `transport error: <detail>` (→ treat as unreachable) |

### `mcp serve` exit codes

`arcana mcp serve` uses the same namespace:

| Code | Condition |
|------|-----------|
| `0` | The server ran (stdio or loopback HTTP) and shut down cleanly after the peer disconnected. |
| `1` | Operational failure: async-runtime start, server assembly (audit dir / `permissions.toml`), or transport error. |
| `2` | `--bind` rejected: the requested address is not loopback (Tier-1 loopback only). Emitted by the bind guard **before** any listener is created. |

The loopback HTTP transport (`--bind`) requires the default `http` build
feature; a build with `--no-default-features` serves stdio only and returns `1`
with a clear message if `--bind` is requested.

## Connector environment overrides

| Variable | Purpose | Default |
|----------|---------|---------|
| `ARCANA_MC_TOKEN` | Bearer token for the Model Connector. Unset/empty → exit path with the `missing API key` message. | *(required)* |
| `ARCANA_MC_BASE_URL` | Diagnostic override accepted only by hidden `mc-ping`, including a loopback replay fixture (`http://127.0.0.1:PORT`). Production `kb-read` rejects every override except the exact canonical endpoint. | `https://connector.arcanada.ai` |

`ARCANA_MC_BASE_URL` lets the smoke gate exercise hidden `mc-ping` against a
recorded fixture server without a live mesh. It is not an agent-loop replay
surface: `kb-read` accepts only `https://connector.arcanada.ai`. See
[`../../dev-tools/smoke/`](../../dev-tools/smoke/).
