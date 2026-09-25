# How-to: run a work item under its KC2 contract

Drive one Muneral work item to completion, bound by the KC2 contract its
`contractDigest` names. The task text comes from the work item and the
contract, not from `--prompt`. The run writes a readiness receipt to
`receipts/ReadinessReceipt-<id>.json` and never changes the work item's own
status.

## Prerequisites

- The `arcana` binary installed (see [`install.md`](install.md)).
- `ARCANA_MC_TOKEN` set to a Model Connector API key.
- `ARCANA_MUNERAL_KEY_FILE` set to a file holding the agent's `mun_sk_` key
  (mode 0600, one line, the trailing newline is trimmed automatically).
- The work item ID you want to execute.

Both environment variables are required and checked before the first model call.

## Steps

1. **Choose a working directory.**  Every tool the agent runs is rooted
   inside this directory; paths outside are refused.  A disposable checkout or
   a `git worktree` is the intended target.

   ```bash
   export CWD=/path/to/a/clean/checkout
   ```

2. **Run the work item.**

   ```bash
   arcana run --cwd "$CWD" --work-item "<work-item-id>"
   ```

   Replace `<work-item-id>` with the actual Muneral work item ID (a UUID, e.g.
   `d931525f-c134-4c6b-85e1-9cdf94e8ab8b`).  The command reads the agent key
   from the file named by `ARCANA_MUNERAL_KEY_FILE`, fetches the work item from
   Muneral (`https://api.muneral.com/api/v1` unless `ARCANA_MUNERAL_URL`
   overrides it), re-hashes the contract document named by the work item's
   `contractDigest`, and runs the task under that binding.

3. **Read the result.**  Every run — success or refusal — prints the
   done-marker as its last line of stdout:

   ```
   ARCANA_RUN_DONE {"completed":true,"reason":"Completed","turns":3,"tool_calls":2,"cost_usd_micros":59,"workspace":"/path/to/worktree","error":null}
   ```

   A runner can always find this line and never has to infer whether the run
   finished.  On success the receipt file is created at
   `receipts/ReadinessReceipt-<work-item-id>.json` inside the working directory.

## What happens on refusal

### Work item without `contractDigest`

If the work item carries no `contractDigest` field, the run refuses before the
first model call and prints:

```text
arcana run: CONTRACT_MISSING: the work item carries no contractDigest, so nothing says what this run may do; refused before the first model call
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_MISSING","code":"CONTRACT_MISSING","error":"the work item carries no contractDigest, so nothing says what this run may do; refused before the first model call"}
```

The code `CONTRACT_MISSING` is the first token on stderr, repeated in the
done-marker JSON, so a runner can branch on it without parsing a sentence.
No model cost is incurred — the check happens before any connector dispatch.

### Digest mismatch

If the contract document the source returns does not hash to the digest the
work item names, the run refuses before the first model call with:

```text
arcana run: CONTRACT_DIGEST_MISMATCH: the document returned for sha256:abc123... hashes to sha256:def456... over its canonical.bytes_b64 — the contract is not the one the work item names
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_DIGEST_MISMATCH","code":"CONTRACT_DIGEST_MISMATCH","error":"the document returned for sha256:abc123... hashes to sha256:def456... over its canonical.bytes_b64 — the contract is not the one the work item names"}
```

The message states the expected digest, the computed digest, and over which
preimage (`canonical.bytes_b64`, `canonical_bytes`, or `projection`) the
computation ran.  This makes it possible to debug a stale or mis-linked
contract without needing the contract body.  Again, no model call has been made
at this point: the digest check is pure local arithmetic.

## Notes

- **The agent key must be in a file.**  The value of `ARCANA_MUNERAL_KEY_FILE`
  points at a file whose first line is the `mun_sk_` secret.  Passing the key
  on the command line or through a plain environment variable is never
  accepted: every error path is built from the response, not from the request,
  so the key never appears in logs or error messages.

- **Optional: pin a model.**  Pass `--model <id>` or set `ARCANA_MODEL`.
  The run prints which source answered before spending anything, and a
  contract-bound run records it in the receipt as `mc_usage.model_source`.
  The value `tier` selects the tiered dispatch policy.

- **Optional: check a contract from a local file.**  The `--contract-file
  <PATH>` flag reads the contract document from a local file instead of from
  Argana.  The file is re-hashed exactly like the service's answer, so it
  cannot be used to run under a digest it does not hash to — and the receipt
  records `contract.source: "file"`, which is NOT the same verdict as a
  binding checked against the live endpoint.

- **Other refusal codes** (`CONTRACT_DIGEST_MALFORMED`, `CONTRACT_NOT_FOUND`,
  `CONTRACT_UNVERIFIABLE`, `CONTRACT_SOURCE_UNAVAILABLE`) follow the same
  pattern: the code on stderr, the detail on the same line, and the machine-
  readable marker on stdout.  All happen before the first model call.
