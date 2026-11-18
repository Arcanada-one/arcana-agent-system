# Run a work item under its KC2 contract

How to execute a Muneral work item that carries a KC2 contract digest — the
`arcana run --work-item` path.

Use this when a task was dispatched through Muneral and the operator needs to
carry it out exactly as the contract defines, with a readiness receipt that
proves the binding was checked before the first model call.

## Prerequisites

| Variable / file | Purpose |
|-----------------|---------|
| `ARCANA_MC_TOKEN` | Model Connector API key. The run will refuse to start if absent. |
| `ARCANA_MUNERAL_KEY_FILE` | Path to the file holding the agent's `mun_sk_` secret key (mode `0600`). Read once at startup; never inherited from the command line or plain env. |
| `arcana` binary | Installed via `cargo install arcana` or from a release archive. |

## Run the work item

```bash
arcana run --cwd /path/to/checkout --work-item <work-item-id>
```

`--cwd` is the working directory — the repository checkout the agent may modify.
`--work-item` identifies the Muneral work item. The task text and the contract
digest come from the work item itself, not from `--prompt`.

### Example

```bash
arcana run \
  --cwd /home/runner/arcana-agent-system \
  --work-item d931525f-c134-4c6b-85e1-9cdf94e8ab8b
```

### Extra options

Most flags documented in [`run-one-task-unattended.md`](run-one-task-unattended.md)
also apply here — `--max-turns`, `--model`, `--request-timeout`, etc.

Two flags are specific to the contract-bound path:

| Flag | Meaning |
|------|---------|
| `--contract-file <PATH>` | Read the contract document from a local file instead of fetching it from Argana. The file is re-hashed and must match the digest — otherwise the run is refused before any model call. The receipt records `contract.source: "file"`. |
| `--ground-truth <PATH>` | Quote this file into the work item's brief as ground truth. Repeatable. Pass a file from the repository that contains the actual commands the task expects — `arcana run --help`, an existing how-to, etc. |

## What happens on success

1. The run fetches the work item from Muneral, reads its `contractDigest`, and
downloads the contract (or reads it from `--contract-file`).
2. The contract bytes are re-hashed. If the digest matches, the run proceeds.
3. The agent executes the task inside `--cwd`.
4. On completion the last line of stdout is the machine-readable done-marker:

```
ARCANA_RUN_DONE {"completed":true,"reason":"Completed","turns":3,"tool_calls":2,"cost_usd_micros":59,"workspace":"/path/to/checkout","error":null}
```

5. A readiness receipt is written to `receipts/ReadinessReceipt-<work-item-id>.json`.
The run **never** changes the work item's status — this is an execution, not a
transition.

Exit code `0`: the run completed and executed at least one tool call.

## Refusal: no `contractDigest`

If the work item has no `contractDigest` field, the run refuses **before any
model call** — no tokens are spent, no money leaves the account.

```
arcana run: CONTRACT_MISSING: work item <id> has no contractDigest
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_MISSING","code":"CONTRACT_MISSING","error":"work item <id> has no contractDigest"}
```

Exit code `1`. The done-marker is printed so a runner never waits for a line
that will not arrive.

## Refusal: contract digest mismatch

If the fetched (or file-provided) contract bytes do not hash to the digest in
the work item, the run refuses before any model call:

```
arcana run: CONTRACT_DIGEST_MISMATCH: contract bytes for digest <expected> hash to <actual>
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_DIGEST_MISMATCH","code":"CONTRACT_DIGEST_MISMATCH","error":"contract bytes for digest <expected> hash to <actual>"}
```

Exit code `1`. The receipt records the mismatch as well.

## Why refusal happens before any model call

The contract binding is validated in the client, before the first dispatch to
the Model Connector. Neither `--contract-file` nor the live Argana endpoint
triggers a model turn — the work item is read, the contract is fetched or
loaded, the digest is verified, and only then does the loop open its first
connector request. A refused run costs only the time to check a local file or
a single HTTP request to Muneral + Argana; no model inference is paid for.

## See also

- [`run-one-task-unattended.md`](run-one-task-unattended.md) — the prompt-based
  `arcana run` command.
- [`install.md`](install.md) — how to get the `arcana` binary.
