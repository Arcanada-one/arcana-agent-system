<!-- The printed output of A2-292's first live page (`docs/how-to/run-a-work-item.md`,
     work item d931525f, run 1), quoted verbatim. Every command on that page parsed
     with the real clap definition; these lines are what no check was looking at.
     The last two blocks are the same defect in the two shapes it also takes: a code
     no build has, and a done-marker field no writer emits. -->

# How to run a work item (A2-292 run 1, withheld)

The last line of stdout is always:

```
ARCANA_RUN_DONE <json>
```

## What happens when the work item has no contract

```
$ arcana run --cwd /tmp/repo --work-item "some-id-without-digest"
Error: CONTRACT_MISSING: the work item has no contractDigest field
```

## What happens when the contract digest does not match

```
$ arcana run --cwd /tmp/repo --work-item "some-id-with-bad-digest"
Error: CONTRACT_DIGEST_MISMATCH: the contract file does not hash to the digest
       declared in the work item
```

## What happens when the contract has expired

```
arcana run: CONTRACT_EXPIRED: the contract is past its validity window
```

## The done-marker of a refusal

```
ARCANA_RUN_DONE {"completed":false,"reason":"CONTRACT_MISSING","exit_code":1}
```
