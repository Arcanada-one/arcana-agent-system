# How to run a work item under a KC2 contract

**Applies to:** `arcana-agent-system`  
**Documentation type:** How-to (Diataxis)

This page walks an operator through launching a work item under a KC2 contract using the `aras` CLI. All failures shown here happen **before any billable model call**.

## Prerequisites

- `aras` binary in `$PATH`
- A KC2 contract file (JSON) with field `contractDigest` at the top level
- Access to the `arcana-agent-system` repository (local clone)

## 1. Prepare the contract file

Save the KC2 contract as `contract.json`. The file must contain a top-level `contractDigest` field whose value is the SHA-256 hash of the canonical JSON (json-c14n-pilot).

Minimal structure:

```json
{
  "contractDigest": "sha256:d1afc442572f70ea5d0d8ee7fe6490443bf4659fff99635ea0bf5cbcdb0762ab",
  "body": {
    "verdict": "T",
    "closure_manifest": { ... },
    ...
  }
}
```

## 2. Run the work item

Basic command:

```bash
aras run --contract contract.json
```

With a specific work item ID:

```bash
aras run --contract contract.json --item d931525f-c134-4c6b-85e1-9cdf94e8ab8b
```

For a fully local run (no external runner):

```bash
KC2_CONTRACT=contract.json \
  KC2_SNAPSHOT=sha256:192e2ce29dd00cf19dd682d948d6bd09f2fa8cc468ca44d2e6f1b2ff7abb563b \
  aras run
```

### What happens on success

1. `aras` computes the SHA-256 of the contract file and compares it to `contractDigest`.  
2. If they match, it loads the assertion projections listed in `body.projection`.  
3. The pipeline matching those assertions runs (`execute-writing-pipeline`, etc.).  
4. The final verdict is printed (must match `body.verdict`).

Example output:

```
✓ Contract digest verified: sha256:d1afc...
✓ Assertions loaded: 24 sources
✓ Work item d931525f-c134-4c6b-85e1-9cdf94e8ab8b
  → Verdict: T
```

## 3. Failures (before any billable model call)

All checks below are synchronous and happen before any LLM call.

### 3.1 Missing `contractDigest`

```
✘ contract.json: missing required field "contractDigest"
  → Cannot confirm contract integrity without a digest.
  → Run rejected. No model call was made.
```

**Why:** Without `contractDigest` the runner cannot determine which contract was supplied, so it cannot guarantee that the expected assertions are executed. The check is at argument-parsing level — no network, model, or database needed.

### 3.2 Digest mismatch

If the file content does not match its `contractDigest`:

```bash
$ sha256sum contract.json
sha256:abcdef...123456  contract.json
```

But `contractDigest` is `sha256:d1afc442572f70ea5d0d8ee7fe6490443bf4659fff99635ea0bf5cbcdb0762ab`.

`aras` prints:

```
✘ Contract digest mismatch:
    expected: sha256:d1afc442572f70ea5d0d8ee7fe6490443bf4659fff99635ea0bf5cbcdb0762ab
    actual:   sha256:abcdef...123456
  → The contract file was modified after signing or is corrupt.
  → Run stopped. No model costs incurred.
```

**Why:** Contract integrity is a prerequisite for trusted replay (see `identity-validated-before-secrets` in `datarim-constraint-trusted-replay@r1`). Digest verification is a local read+hash operation — it requires no external service.

### 3.3 Failure chain

```
User → aras run --contract contract.json
        │
        ├─ [1] File exists?           — no → open error
        ├─ [2] Valid JSON?            — no → parse error
        ├─ [3] Has contractDigest?    — no → FAIL (3.1)
        ├─ [4] Digest matches?        — no → FAIL (3.2)
        ├─ [5] Verdict in body?       — no → structure error
        │
        └──→ Pipeline start (only after step 4)
```

Steps 1–4 involve no billable model calls.

## 4. Full session example

```bash
# Successful run
$ aras run --contract ./contract.json --item d931525f-c134-4c6b-85e1-9cdf94e8ab8b
✓ Contract digest matches: sha256:d1afc442572f70ea5d0d8ee7fe6490443bf4659fff99635ea0bf5cbcdb0762ab
✓ Snapshot verified: sha256:192e2ce29dd00cf19dd682d948d6bd09f2fa8cc468ca44d2e6f1b2ff7abb563b
✓ Projection sources: 24
✓ Work item completed. Verdict: T

# Failure — no contractDigest
$ aras run --contract no-digest.json
✘ no-digest.json: missing required field "contractDigest"

# Failure — digest mismatch
$ aras run --contract tampered.json
✘ Contract digest mismatch:
    expected: sha256:d1afc442572f70ea5d0d8ee7fe6490443bf4659fff99635ea0bf5cbcdb0762ab
    actual:   sha256:aaaa...
```

## 5. Notes

- `contractDigest` is the SHA-256 of the **canonicalised** JSON (`json-c14n-pilot`). Do not use raw `sha256sum` if the file was reformatted.
- After digest check, the runner also verifies `body.closure_manifest.snapshot_digest` against the provided `KC2_SNAPSHOT` if set.
- This page covers only launching a work item. Creating and signing a contract is a separate procedure.

---

*Last updated: 2025-04-15*
