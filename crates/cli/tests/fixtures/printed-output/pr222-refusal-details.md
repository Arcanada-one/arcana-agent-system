# The two refusal blocks PR #222's page carried, verbatim

## Refusal: no `contractDigest`

```
arcana run: CONTRACT_MISSING: work item <id> has no contractDigest
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_MISSING","code":"CONTRACT_MISSING","error":"work item <id> has no contractDigest"}
```

## Refusal: contract digest mismatch

```
arcana run: CONTRACT_DIGEST_MISMATCH: contract bytes for digest <expected> hash to <actual>
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_DIGEST_MISMATCH","code":"CONTRACT_DIGEST_MISMATCH","error":"contract bytes for digest <expected> hash to <actual>"}
```
