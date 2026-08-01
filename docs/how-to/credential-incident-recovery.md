# How to recover from a provider-credential exposure

This is the runbook for the case where a provider API credential has reached an
agent's environment and been emitted into terminal output or durable
transcripts. It is written from a real incident; the ordering is not arbitrary.

## The two rules that matter most

**A balance failure is not a revocation.** If the provider returns `402
Insufficient Balance` on a billable call but `200` on a metadata call, the
credential still authenticates. Its authority returns the moment anyone funds
the account — which does not require holding the key. Never record an exhausted
balance as invalidation.

**Deleting a local copy is not a retraction.** Redacting transcripts reduces the
number of places the value sits. It does nothing to the credential's validity.
Only the provider authority can do that.

## Order of operations

Copy cleanup and rotation are sequenced deliberately.

1. **Stop credentialed execution.** Do not restart a credential-bearing
   executor until step 4 is authoritative.
2. **Inventory copies.** Paths and counts only — never content. Classify each
   copy as *inert* (transcripts, shell snapshots, file history) or
   *distribution* (shell rc, env files, secret stores).
3. **Redact inert copies now.** They serve no consumer, so removing them cannot
   break anything. Do this immediately; every hour they persist is exposure.
4. **Rotate at the provider.** Create the replacement, then invalidate the old
   credential, then prove the old one is rejected and the new one works — with
   status codes only.
5. **Distribute the replacement through the canonical secret store**, never back
   into shell rc or env files.
6. **Only then remove the distribution copies**, and restart every dependent
   process.

Step 6 comes last because removing the distribution path before a replacement
exists leaves the host with no credential path at all and no way to restore one.
Step 3 does not have that problem, which is why it does not wait.

Do not create a dummy value at the production destination merely to make the
path “exist.” A placeholder creates a real secret version, can make consumers
mistake path existence for credential readiness, and pollutes the audit/version
history. It is safe to pre-stage policy or metadata only when data reads still
report absent. The first data version at the destination must be the actual
console-issued replacement, written with the store's create-only/CAS guard.

## Inventorying copies without leaking them

Read the credential from the process environment inside your script — never pass
it as an argument, or it appears in `/proc/<pid>/cmdline` and in shell history.
Emit paths and counts, never matched content.

```python
secret = os.environ.get("PROVIDER_API_KEY", "")
if len(secret) < 12:
    sys.exit(2)              # fail closed rather than match everything
needle = secret.encode()
# ... count occurrences per file; print path and count only
```

Agent transcript stores dominate the count in practice. No `.gitignore`
protects them, and they are exactly the surface the execution boundary exists to
close. Expect the count to *grow* while the credential remains in the shell
environment — each new agent session writes more copies. That growth is the
signal that step 6 is genuinely necessary, not optional cleanup.

## Proving revocation without printing anything

Use a metadata endpoint and compare status codes against a deliberately invalid
control:

| Probe | Before rotation | After rotation |
|---|---|---|
| Old credential, metadata endpoint | `200` | `401` |
| Invalid control credential | `401` | `401` |
| Replacement, through the broker | n/a | `200` |

The invalid control matters: without it, a `401` could equally mean the endpoint
moved. Never log the request headers.

## When the provider has no key-management API

Some providers offer only console-based key management, and account-scoped keys
with no per-key scope, spend cap, or expiry. Two consequences:

- Rotation cannot be automated. Say so in the runbook rather than implying
  parity with providers that support it — under incident pressure, the
  difference will be forgotten.
- Least privilege cannot be enforced upstream, so it must be enforced at your
  own boundary: the broker constrains provider, model, operation, quota and
  expiry on top of an unscoped upstream key. This constrains what the *agent*
  can request. It does not constrain what a *key holder* can do, and that
  residual risk should be written down and accepted explicitly.

See `docs/explanation/provider-capability-gap-deepseek.md` for a worked example.

## Auditing an unrelated token caught in the blast radius

Audit by **accessor**, never by token value. Enumerate live accessors and
account for each one: display name, policies, TTL. Confirm no derived or child
authority survives, no lease references the incident, and no long-TTL token has
wrong-host capability. A revoked token simply does not appear.

Two failure modes that look like an outage but are not:

- The secret store may be reachable from one host and not another. Probe from
  the host the store actually trusts.
- A store speaking plain HTTP behind `VAULT_ADDR=https://…` returns *"server
  gave HTTP response to HTTPS client"*, which reads like a service failure and
  is a scheme mismatch.

Both cost real time in this incident. Check them before concluding an audit is
blocked.

## The root cause is usually distribution, not disclosure

Ask where the credential lived. If it was distributed by shell rc and env files
rather than through the secret store, then it had no accessor, no lease, no TTL
and no revocation path — which is *why* the exposure was unbounded, not merely
how it happened.

Re-issuing the replacement into the same place reproduces the incident with a
new value. The replacement must land in the secret store first.

## Verifying the sweep actually ran

A secret-scanning script that fails to start reports "no findings" — which is
indistinguishable from success. In this incident a sweep had been silently dead
on one platform for an unknown period because it used a bash 4 feature under
bash 3.2, exiting before scanning anything.

Make the tool distinguish *clean* from *never ran*, and fail closed on the
latter.
