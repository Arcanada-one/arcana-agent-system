# The two refusal blocks PR #222's page carried, with both details taken from the program

## Refusal: no `contractDigest`

```
arcana run: CONTRACT_MISSING: the work item carries no contractDigest, so nothing says what this run may do; refused before the first model call
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_MISSING","code":"CONTRACT_MISSING","error":"the work item carries no contractDigest, so nothing says what this run may do; refused before the first model call"}
```

## Refusal: contract digest mismatch

```
arcana run: CONTRACT_DIGEST_MISMATCH: the document returned for <expected> hashes to <computed> over its canonical.bytes_b64 — the contract is not the one the work item names
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_DIGEST_MISMATCH","code":"CONTRACT_DIGEST_MISMATCH","error":"the document returned for <expected> hashes to <computed> over its canonical.bytes_b64 — the contract is not the one the work item names"}
```
