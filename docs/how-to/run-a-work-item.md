# How to run a work item under its KC2 contract

This guide shows how an operator executes a single Muneral work item using its
KC2 contract. Every command below is real: nothing is simulated or described.

## Prerequisites

- `arcana` built and installed (see [install.md](install.md)).
- A file that holds the agent key. Its path is exported in `ARCANA_MUNERAL_KEY_FILE`.
- `ARCANA_MC_TOKEN` set to a live Model Connector token — the run costs money.
- A working directory, e.g. a disposable checkout or `git worktree`, where the
  agent will operate. Every tool call the agent makes is confined to this
  directory.

## Run a work item by its ID

```bash
export ARCANA_MC_TOKEN="mc_live_..."          # from your secrets store
export ARCANA_MUNERAL_KEY_FILE="$HOME/.config/arcana/muneral-key"

arcana run \
  --cwd /path/to/disposable-checkout \
  --work-item "d931525f-c134-4c6b-85e1-9cdf94e8ab8b"
```

The `--work-item` flag tells `arcana` to:
1. Load the work item from Muneral. The item carries a `contractDigest` that
   names the KC2 contract it must run under.
2. Fetch or load the contract document, hash it, verify it matches the digest.
3. Extract the task goal from the work item (the `--prompt` flag is ignored
   when `--work-item` is present).
4. Run the agent loop: dispatch → tools → permissions → audit, writing
   `receipts/ReadinessReceipt-<id>.json` into the working directory.

The last line of stdout is always:

```
ARCANA_RUN_DONE <json>
```

## What happens when the work item has no contract

If the work item does not carry a `contractDigest` field at all, `arcana`
refuses the run *before the first model call*:

```
$ arcana run --cwd /tmp/repo --work-item "some-id-without-digest"
Error: CONTRACT_MISSING: the work item has no contractDigest field
```

No tokens are spent, no receipt is written, and the exit code is non-zero.
The check happens before any HTTP request to the Model Connector.

## What happens when the contract digest does not match

If the work item names a `contractDigest` but the fetched contract document
does *not* hash to that digest, `arcana` refuses the run *before the first
model call*:

```
$ arcana run --cwd /tmp/repo --work-item "some-id-with-bad-digest"
Error: CONTRACT_DIGEST_MISMATCH: the contract file does not hash to the digest
       declared in the work item
```

Again, no tokens are spent and no receipt is written. This is the only
integrity gate between what the work item claims its contract is and what the
contract actually contains.

## Using a local contract file

For the period in which the live contract service (`GET /v1/contract/{digest}`)
is not deployed, you can supply the contract from a file:

```bash
arcana run \
  --cwd /path/to/disposable-checkout \
  --work-item "d931525f-c134-4c6b-85e1-9cdf94e8ab8b" \
  --contract-file /path/to/contract.json
```

The file is re-hashed exactly like the service response: it cannot be used to
run under a digest it does not hash to. The receipt records
`contract.source: "file"`, which is *not* the same verdict as a binding
checked against the live endpoint.

## What the receipt looks like

The run writes `receipts/ReadinessReceipt-<id>.json` inside the working
directory. The file is *never committed* — `.gitignore` already carries the
rule — and belongs in a pull request body or as an attachment, not in the
repository tree. Committing it turns the admission gate's verdict into
`not_measured` and pauses the change it was meant to support.

## Common pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| `ARCANA_MUNERAL_KEY_FILE` not set | `arcana` cannot read the agent key | `export ARCANA_MUNERAL_KEY_FILE=...` before the command |
| `ARCANA_MC_TOKEN` not set | run fails before dispatch | `export ARCANA_MC_TOKEN=...` with a live token |
| Working tree is unchanged after the run | `NoEffect` exit code 1 | The model made no tool calls. Add `--read-only` if the task genuinely reads only, or check that the task is actionable |
| Receipt committed to the repository | Admission gate returns `PAUSED_SAFE` | Remove the receipt from the commit: it is evidence of the run, not part of the change |
| Work item without a `contractDigest` | `CONTRACT_MISSING` error | Ask the work item dispatcher to add one |
