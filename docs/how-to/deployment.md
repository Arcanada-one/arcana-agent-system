# How-to: deploy a broker generation

The release workflow builds `linux-x86_64` and `macos-arm64` packages, runs the
locked workspace tests on each hosted platform, produces SBOMs and checksums,
and signs and attests every published artifact. A tag publishes only when it is
the exact current `main` commit, every app-bound protected check is successful,
and exactly one merged pull request into `main` produced that commit. The
protected release environment still admits `v*` tags only. Immediately before
publication the workflow re-reads both `main` and the recursively dereferenced
tag and requires both to resolve to the release SHA.

Follow [install.md](install.md) to verify a downloaded package before using its
contents. Never deploy an archive that has only passed a checksum.

## Control downgrade, 2026-09-02

The release path no longer requires a human signature. Three checks were
removed from the `preflight` job and one from the release environment:

- the APPROVED review from `vars.SEC0030_RELEASE_REVIEWER` on the merged PR
  head SHA;
- the assertion that this reviewer appears in `.github/CODEOWNERS`;
- the Ed25519 governance-witness manifest, captured on an operator host and
  verified by `dev-tools/sec0030-governance-witness-verify.sh`;
- the `required_reviewers` rule on the `sec0030-protected-release`
  environment, which held publication for a manual approval in the GitHub UI.

**Why.** The gate was introduced by PR #43 on 2026-08-11 and merged with zero
approvals by the `Arcanada` service account. No vendor, contract, or external
policy required it. Measured against the repository as it stands, the gate was
also unsatisfiable by anyone: `main` carries no
`required_pull_request_reviews` block, so the exact-head approval it demanded
could not be produced through the normal merge path. The operator, who was the
sole configured reviewer, directed on 2026-09-02 that work the agent can do
alone should not wait on their signature.

**What this costs.** Release no longer carries independent human attestation.
A compromised or mistaken agent with merge rights on `main` can now reach
publication unaided. This is a real reduction in control, recorded here rather
than dropped silently.

**What still holds.** Publication remains gated on machine-checkable facts:
the tagged SHA must be the tip of `origin/main`; the tag version, the workspace
`Cargo.toml` version, and the CHANGELOG heading must agree; all six protected
checks must be `completed`/`success` on that exact SHA and produced by app id
15368; and exactly one closed, merged PR into `main` must have that SHA as its
`merge_commit_sha`. The release environment still accepts `v*` tags only, with
`can_admins_bypass` false. Branch protection on `main` is unchanged:
`enforce_admins`, linear history, no force-pushes, no deletions, six required
contexts. Signing, SBOM, and provenance attestation are untouched.

Restoring the requirement means re-adding the removed steps and a
`required_reviewers` rule, and, for the review check to be satisfiable at all,
adding `required_pull_request_reviews` to `main`. The witness tooling
(`dev-tools/sec0030-governance-witness-*.sh`, `.github/sec0030-governance-witness.pub`)
is left in the repository for that purpose. The signing key remains in its
operator-private Vault locator; nothing consumes it now, and it can be
destroyed once the decision is settled.

[github-rulesets]: https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset

## Stage disabled

Do not pass the root lifecycle helper a path from a user-writable checkout.
Create a root-only staging directory, download the release there as root, rerun
the checksum, identity-bound cosign, and GitHub-attestation verification from
[install.md](install.md), then extract there. Every source component must be
root-owned, non-symlink, free of extended ACLs, and not group/world writable;
the helper enforces that contract from `/` to the source file.

Run the packaged helper with absolute paths from that verified root-only staging
directory and an immutable generation name:

```bash
sudo /var/lib/arcana-broker-stage/$GENERATION/packaging/broker-lifecycle.sh \
  install "$GENERATION" \
  "/var/lib/arcana-broker-stage/$GENERATION/bin/arcana-credential-broker" \
  "/var/lib/arcana-broker-stage/$GENERATION/packaging/policy/capability-policy.example.toml"
```

Installation disables activation first, stores binary and policy in a
root-owned immutable generation archive, installs the platform service assets,
and leaves the generation pending. Repeating the same generation repairs an
interrupted service-asset install; a different binary or policy under the same
name is refused. Generation selection and rollback snapshots live in a separate
root-only control directory. Broker-owned runtime state is moved there without
following source symlinks before it is validated, so privileged lifecycle code
never copies from a broker-writable pathname. A separate root-owned state-
generation marker lets rollback restore the correct durable quota/idempotency
ledger even when a switch fails before the binary generation token changes.

## Activation gate

Do not run `activate` until all of these are proven on the target host:

- the replacement provider credential exists in the canonical secret store and
  the retained shell/env copies have been removed only after console rotation;
- the platform-native peer-attestation and hostile-descendant containment
  backend has passed its live escape tests;
- the installed service identity, exact executable digest, state paths, and
  permissioned local socket pass `broker-lifecycle.sh verify`;
- rollback has been rehearsed with the same signed artifacts.

Credentialed startup deliberately remains disabled when these gates are absent.
Hosted platform-contract tests are packaging evidence, not production proof.

## Activate, verify, and roll back

Run the installed helper, exactly as for `install` above — an absolute path
inside the verified staging root, never the relative path into a checkout:

```bash
BROKER=/var/lib/arcana-broker-stage/$GENERATION/packaging/broker-lifecycle.sh
sudo "$BROKER" activate
sudo "$BROKER" verify
sudo "$BROKER" rollback "$PREVIOUS_GENERATION"
```

An activation or rollback verification failure ends with both the service and
activation endpoint disabled. `ARCANA_ROOT` is accepted only in explicit
`SERVICE_MODE=rehearsal`; it cannot redirect production service-manager writes.
