# How-to: deploy a broker generation

The release workflow builds `linux-x86_64` and `macos-arm64` packages, runs the
locked workspace tests on each hosted platform, produces SBOMs and checksums,
and signs and attests every published artifact. A tag publishes only when it is
the exact current `main` commit, every app-bound protected check is successful,
the active tag ruleset has no bypass actor, branch protection requires a fresh
code-owner approval with no bypass, the merged PR has an exact-head approval
from the configured independent code owner, and the protected release
environment receives its separate independent review.

Follow [install.md](install.md) to verify a downloaded package before using its
contents. Never deploy an archive that has only passed a checksum.

## Capture the governance witness

Decision, 2026-08-02: the tag-triggered release path does not carry a GitHub
governance credential. Reading hidden ruleset bypass actors requires a
mutation-capable Administration token. Giving that long-lived authority to a
tag workflow would let a compromised release job rewrite the governance it is
supposed to verify. Public `updated_at` metadata was also rejected as a drift
anchor: a live add/remove bypass-actor negative control did not change it.

Instead, a trusted operator host performs the privileged read immediately
before creating the version tag. The capture helper requires:

- the `Arcanada` machine account's GitHub credential on a private file
  descriptor, never in argv or the environment;
- the SEC-0030 Ed25519 signing key on a second private file descriptor;
- the exact merge SHA, merged PR number, repository, and independent reviewer.

`dev-tools/sec0030-governance-witness-capture.sh` verifies that the GitHub
identity has admin visibility, reads branch protection, the complete active tag
ruleset including hidden bypass actors, and the protected environment, then
signs a 120-second exact-SHA manifest. It posts only the manifest and signature
as a machine-account PR comment. The release workflow has `checks`, `contents`,
`issues`, and `pull-requests` read access, verifies the signature against
`.github/sec0030-governance-witness.pub`, and rejects an expired, altered,
wrong-author, wrong-repository, wrong-SHA, or bypass-bearing witness.

The private signing key is stored only at Vault KV v2 path
`arcanada/shared/tokens/sec0030-governance-witness`, with CAS required. Version
1 was created on 2026-08-02, is limited by contract to signing these 120-second
governance manifests, and must rotate by 2026-10-31 or immediately after any
suspected disclosure. Rotation is a code-reviewed public-key change followed
by revocation of the old Vault version. The signing key cannot mutate GitHub;
the GitHub credential never enters Actions. An absent or invalid witness stops
release before build or publication.

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

```bash
sudo packaging/broker-lifecycle.sh activate
sudo packaging/broker-lifecycle.sh verify
sudo packaging/broker-lifecycle.sh rollback "$PREVIOUS_GENERATION"
```

An activation or rollback verification failure ends with both the service and
activation endpoint disabled. `ARCANA_ROOT` is accepted only in explicit
`SERVICE_MODE=rehearsal`; it cannot redirect production service-manager writes.
