# Run a work item under its KC2 contract

A *work item* is a structured, traceable assignment that carries its own
task text and is bound to a *KC2 contract* — the set of constraints,
capabilities and governance rules that define how the agent may execute
it. The agent honours the contract by refusing any tool the contract
does not list, before it spends anything on a model call.

A work item is dispatched with `arcana run` using the `--work-item` flag
and never the `--prompt` or `--prompt-stdin` flags, which conflict with
it.

## Prerequisites

- An `arcana` binary on your `$PATH` (build or install).
- A **Muneral work item** whose JSON record includes a
  `contractDigest` — a SHA-256 hex string naming the contract that
  governs it; see "Refusals" below for what happens otherwise.
- The **agent key** for the Muneral realm, at a path you can name with
  `ARCANA_MUNERAL_KEY_FILE`.
- A **model connector token** in `ARCANA_MC_TOKEN`. Without it the
  model call fails at dispatch time.

## Steps

### 1. Point `ARCANA_MUNERAL_KEY_FILE` at the agent key

The key file holds the agent's `mun_sk_` key as one line of text, mode
0600. It is read from the file and never from a command line. Export the
path:

```bash
export ARCANA_MUNERAL_KEY_FILE="$HOME/.config/arcana/muneral-agent-key.pem"
```

### 2. Set the environment (recommended)

Pin the model and provide the connector token:

```bash
export ARCANA_MODEL="deepseek-v4-flash"
export ARCANA_MC_TOKEN="<your-model-connector-token>"
```

The model can also be set with `--model` (highest authority), then the
`ARCANA_MODEL` environment variable, then `arcana models use`, then the
tiered dispatch policy. The run prints on startup which source answered.

The timeout per turn can be adjusted with `ARCANA_MC_TIMEOUT_SECS` or
`--request-timeout` (default 120 s, range 5–600).

### 3. Create a disposable working directory

The `--cwd` directory is the agent's working root; any tool call that
references a path outside it is refused. Create a clean one:

```bash
mkdir -p /tmp/work-item-run
git clone <repository-url> /tmp/work-item-run
```

Or use a git worktree:

```bash
git worktree add --detach /tmp/work-item-run HEAD
```

### 4. Dispatch the work item

```bash
arcana run \
  --cwd /tmp/work-item-run \
  --work-item "d931525f-c134-4c6b-85e1-9cdf94e8ab8b"
```

The agent will:

1.  Fetch the work item from Muneral.
2.  Extract its `contractDigest`.
3.  Fetch the contract by that digest, or verify a local file given
    with `--contract-file`.
4.  Enforce the contract's tool allowlist for every turn.
5.  Write a receipt to `receipts/ReadinessReceipt-<id>.json`.
6.  Never change the work item's status.

The last line of stdout is always `ARCANA_RUN_DONE` with a JSON payload
containing the outcome.

### 5. Inspect the receipt

```bash
cat receipts/ReadinessReceipt-d931525f-c134-4c6b-85e1-9cdf94e8ab8b.json
```

The receipt records the contract digest, model source, tool list, and
run outcome.

## Refusals

Two refusal scenarios happen **before the first model call**, so they
never incur a billable inference:

### Missing contract digest (`CONTRACT_MISSING`)

If the work item has no `contractDigest` field, the agent refuses
immediately. No receipt is written; the exit code is 1:

```text
arcana run: CONTRACT_MISSING: work item d931525f-c134-4c6b-85e1-9cdf94e8ab8b has no contractDigest
ARCANA_RUN_DONE {"code":"CONTRACT_MISSING","completed":false,"error":"work item d931525f-c134-4c6b-85e1-9cdf94e8ab8b has no contractDigest","reason":"CONTRACT_MISSING"}
```

**Why before the first model call.** The agent must know *which* contract
governs the work before it can enforce any permission rule — the tool
allowlist, the capability envelope, the governance constraints. Without
a `contractDigest` there is no secure way to load a contract, so the
refusal is the first action after parsing the flags. The first token on
stderr is `CONTRACT_MISSING`, so a script can branch on it without
parsing the sentence.

### Contract digest mismatch (`CONTRACT_DIGEST_MISMATCH`)

If the work item names a `contractDigest` but the fetched (or locally
provided) contract's byte-level hash does not match it, the agent
refuses immediately. The exit code is 1:

```text
arcana run: CONTRACT_DIGEST_MISMATCH: contract digest sha256:abc123... does not match work item's contractDigest
ARCANA_RUN_DONE {"code":"CONTRACT_DIGEST_MISMATCH","completed":false,"error":"contract digest sha256:abc123... does not match work item's contractDigest","reason":"CONTRACT_DIGEST_MISMATCH"}
```

**Why before the first model call.** This is the last line of defence
before the capability and governance layers are built: if the contract's
integrity cannot be verified, no permission rule can be trusted. The
boundary is enforced before any tool is made available to the agent,
and therefore before any paid inference.

## Other dispatch options

### `--contract-file` — offline contract

For development and CI scenarios where the contract service is not
reachable, pass a local file:

```bash
arcana run \
  --cwd /tmp/work-item-run \
  --work-item "d931525f-c134-4c6b-85e1-9cdf94e8ab8b" \
  --contract-file ./contract.json
```

This flag **requires `--work-item`** — it cannot be used with a
free-form prompt. The tool re-hashes the file and rejects it if the
hash does not match the work item's `contractDigest`: a local file
cannot be used to run under a digest it does not hash to. The receipt
records `"contract.source": "file"`, which is *not* the same verdict
as a binding checked against the live endpoint.

### `--ground-truth` — authoritative reference files

For tasks whose answer names commands, flags or environment variables,
quote the defining file as ground truth:

```bash
arcana run \
  --cwd /tmp/work-item-run \
  --work-item "d931525f-c134-4c6b-85e1-9cdf94e8ab8b" \
  --ground-truth path/to/help-output.txt \
  --ground-truth path/to/flag-definitions.rs
```

This flag **requires `--work-item`** — repeat it for multiple files.
The file's SHA-256 is recorded in the receipt. An unreadable or empty
file refuses the run before the first model call.

## All flags for `arcana run`

| Flag | Purpose |
|------|---------|
| `--cwd <PATH>` | Working directory root; every tool is rooted here (required) |
| `--work-item <ID>` | Muneral work item ID (conflicts with `--prompt`, `--prompt-stdin`) |
| `--contract-file <PATH>` | Local contract file (requires `--work-item`) |
| `--ground-truth <PATH>` | Repository file quoted as authority (requires `--work-item`, repeatable) |
| `--prompt <TEXT>` | Free-form task (conflicts with `--work-item`, `--prompt-stdin`) |
| `--prompt-stdin` | Read task from stdin (conflicts with `--work-item`, `--prompt`) |
| `--max-turns <N>` | Connector-attempt cap (default 24) |
| `--max-cost-usd <N>` | Spend cap in USD |
| `--model <ID>` | Pin a model id (highest authority in order: flag > `ARCANA_MODEL` > `arcana models use` > tiered policy) |
| `--request-timeout <SEC>` | Model turn timeout, 5–600 (default 120; also `ARCANA_MC_TIMEOUT_SECS`) |
| `--context-budget <UNITS>` | Transcript ceiling in UTF-16 code units (default 90000, max 100000) |
| `--tool-result-budget <UNITS>` | Ceiling on one tool result in UTF-16 code units (default 8000, min 240) |
| `--save-transcript <PATH>` | Append every dispatch request to this file (appended per dispatch) |
| `--read-only` | Declare the task will not change any file (without it a clean tree produces `NoEffect`) |

## See also

- [Run one task unattended](run-one-task-unattended.md)
- [Credential incident recovery](credential-incident-recovery.md)
- `arcana run --help` for the full flag reference
