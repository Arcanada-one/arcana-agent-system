# arcana v0.1.0 — release-verify recipe (producer side)

Scratch operator note (NOT committed). Matches the consumer-side `release-verify`
skill so `cosign verify-blob` + `gh attestation verify` round-trip.

cosign is NOT installed in the prep environment — **nothing was signed here.**
Below are the exact commands for the operator to run at the publish gate.

## Computed integrity (this build)

- Binary: `target/release/arcana`  (13.2 MB, release profile, LTO thin, stripped)
- Embedded git SHA: `06ca07c` (== origin/main HEAD at build time)

```
sha256:  cee4fb31f71742ca184f64a49167e2dc13033cb8a416b2e38f99c3525bea5b3e  arcana
```

> Note: `cargo install` consumers build the binary locally, so their bytes will
> differ from this one. Sign + attest the exact binary artifact you ATTACH to
> the GitHub Release (per-target, e.g. `arcana-v0.1.0-x86_64-unknown-linux-gnu`).

## Preferred path — sign in CI via a `release.yml` (keyless OIDC)

`arcana-agent-system` has **no `release.yml` yet** (only `ci.yml`). The consumer
recipe binds the cosign certificate-identity to
`…/.github/workflows/release.yml@refs/tags/v0.1.0`. To make the consumer
`release-verify` recipe round-trip verbatim, add a keyless release workflow that,
on the `v0.1.0` tag:

1. builds the per-target `arcana` binary,
2. `sha256sum arcana-<target> > arcana-<target>.sha256`,
3. keyless `cosign sign-blob` (OIDC = GitHub Actions token):

```bash
cosign sign-blob --yes \
  --bundle "arcana-v0.1.0-<target>.cosign.bundle" \
  "arcana-v0.1.0-<target>"
```

4. build-provenance attestation (this is what `gh attestation verify` checks):

```yaml
- uses: actions/attest-build-provenance@v1
  with:
    subject-path: "arcana-v0.1.0-<target>"
```

5. upload binary + `.sha256` + `.cosign.bundle` to the release.

## Fallback — sign locally (keyless, operator OIDC identity)

If signing by hand instead of via `release.yml`, the certificate-identity will be
the operator's own OIDC subject (e.g. GitHub/Google email), NOT the workflow
identity — so the consumer must pass the matching `--certificate-identity` /
`--certificate-oidc-issuer`. Prefer the CI path above for a clean round-trip.

```bash
BIN=target/release/arcana
sha256sum "$BIN" | sed 's# .*/# #' > arcana-v0.1.0-linux-x86_64.sha256
cosign sign-blob --yes \
  --bundle arcana-v0.1.0-linux-x86_64.cosign.bundle \
  "$BIN"
```

## Consumer round-trip (from the release-verify skill, adapted)

```bash
TAG=v0.1.0
gh release download "$TAG" --repo Arcanada-one/arcana-agent-system
sha256sum -c "arcana-${TAG}-<target>.sha256"
cosign verify-blob \
  --bundle "arcana-${TAG}-<target>.cosign.bundle" \
  --certificate-identity "https://github.com/Arcanada-one/arcana-agent-system/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "arcana-${TAG}-<target>"
gh attestation verify "arcana-${TAG}-<target>" --repo Arcanada-one/arcana-agent-system
```

Any non-zero exit → untrusted, do not install.
