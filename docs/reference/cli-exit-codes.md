# CLI exit codes & connector environment

Information-oriented reference for the `arcana` subcommand exit-code namespace
and the Model-Connector environment overrides.

## Exit-code namespace

`arcana` subcommands distinguish three outcome classes so an automated caller
(CI, the smoke gate) can tell a dead capability from an infrastructure error:

| Code | Meaning | Examples |
|------|---------|----------|
| `0` | Success — the capability ran and produced a positive result. | `whoami` cascade Allowed with a non-empty audit record; `mc-ping` returned a non-empty `result`. |
| `1` | Operational / infrastructure error — the probe could not run. | bootstrap failure; async-runtime start failure; connector transport error (DNS/TLS/connect/timeout); the advertised audit-log path is missing or empty. |
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

## Connector environment overrides

| Variable | Purpose | Default |
|----------|---------|---------|
| `ARCANA_MC_TOKEN` | Bearer token for the Model Connector. Unset/empty → exit path with the `missing API key` message. | *(required)* |
| `ARCANA_MC_BASE_URL` | Override the connector base URL. Set to a non-empty value to point the probe at a non-default deployment or a loopback replay fixture (`http://127.0.0.1:PORT`). An `http://` override disables HTTPS-only enforcement; the default stays HTTPS-only. | `https://connector.arcanada.one` |

`ARCANA_MC_BASE_URL` is what lets the smoke gate exercise `mc-ping` against a
recorded fixture server without a live mesh — see
[`../../dev-tools/smoke/`](../../dev-tools/smoke/).
