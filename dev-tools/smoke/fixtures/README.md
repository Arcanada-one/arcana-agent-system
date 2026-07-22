# arcana-smoke record/replay fixtures

Canned Model-Connector response envelopes served by
`../mc_replay_server.py` on `127.0.0.1:0` (ephemeral loopback, torn down per
run) so the smoke gate's S2/S3 stages never hard-depend on the live mesh.

| File | Served as | Drives |
|---|---|---|
| `mc-success.json` | HTTP **201** | S2 nonce-bound success (`result` `ARCANA-__NONCE__` is regenerated per run) and the S3 stub-200 negative control (same body, served with HTTP **200** → `UnexpectedStatus(200)`) |
| `mc-error.json` | HTTP **201** with `"status":"error"` | S3 logical-error negative control → `ConnectorError::Logical` |

**Provenance:** hand-authored from the pinned `ConnectorResponse` /
`LogicalError` schema in `crates/core/src/connector.rs` (captured on branch
base `aras-0033 @ 18373b6`), not from documentation. The camelCase wire names
(`inputTokens`/`outputTokens`/`totalTokens`/`costUsd`/`latencyMs`) mirror the
`#[serde(rename = …)]` derives. When the live MC is reachable from DEVS with a
real token, S2 additionally runs a live leg (`ARCANA_MC_LIVE=1`); otherwise the
live leg is tri-stated `SKIP`, never counted as a pass.
