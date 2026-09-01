# How-to: install

## Binary-name collision probe

Before publishing to crates.io or a Homebrew tap, run the collision probe
against every candidate name:

```bash
dev-tools/check-binary-name.sh <candidate> [<candidate> ...]
```

It checks crates.io, Homebrew core (`formulae.brew.sh`), and the local
`apt-cache` index; exit 0 means every candidate is free everywhere it could
be checked, exit 1 means at least one collides. See
`dev-tools/tests/check-binary-name.bats` for the test suite (runs against a
local fixture server, no live-network dependency).

Latest probe run (crate/package-name candidates):

| Candidate | crates.io | Homebrew |
|---|---|---|
| `arcana` | **taken** | free |
| `arcana-cli` | **taken** | free |
| `arcana-agent` (current `crates/cli` package name) | free | free |

Both single-word ergonomic names from the original fallback list
(`arcana` default, `arcana-cli` per OQ-4) are already occupied on
crates.io. The `crates/cli` package is named `arcana-agent`, renamed from
`arcana-agent-system` before the first publish: a crates.io name is reserved
by the first successful upload and cannot be given back, so the long name
would have been burned permanently on a crate whose binary is called
`arcana`. The command is unchanged — `[[bin]] name = "arcana"`.

Note the two names that legitimately differ. The **repository** is still
`Arcanada-one/arcana-agent-system`, so every URL and clone path below keeps
that spelling; only the **package** was renamed.

## Install a verified GitHub release

No release is trusted merely because it appears on the Releases page.
The release workflow publishes platform archives, SBOMs, SHA-256 files, keyless
Sigstore bundles, and GitHub build-provenance attestations. Verify all three
layers before extracting anything.

Prerequisites: `gh` 2.40 or newer, `cosign` 3.0 or newer, and `sha256sum`.

```bash
TAG=v0.2.0                 # exact release tag
PLATFORM=linux-x86_64      # or macos-arm64
REPOSITORY=Arcanada-one/arcana-agent-system
mkdir "arcana-${TAG}-${PLATFORM}"
cd "arcana-${TAG}-${PLATFORM}"
gh release download "$TAG" --repo "$REPOSITORY" --pattern "*${PLATFORM}*"

for checksum in *.sha256; do
  sha256sum -c "$checksum"
done

for artifact in *.tar.gz *.cdx.json *.sha256; do
  cosign verify-blob \
    --bundle "${artifact}.cosign.bundle" \
    --certificate-identity "https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/tags/${TAG}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$artifact"
  gh attestation verify "$artifact" --repo "$REPOSITORY"
done
```

Every command above must exit zero. A checksum without the identity-bound
cosign verification is insufficient because an attacker could replace both
the archive and checksum. Any signature or attestation failure makes the
release untrusted: do not extract or install it.

Archives are named `arcana-<TAG>-<PLATFORM>.tar.gz` and each contains
`bin/arcana`, `bin/arcana-credential-broker`, and the platform packaging files.
The `v0.1.0` release predates this layout: it published a single bare
`arcana-v0.1.0-x86_64-unknown-linux-gnu` binary with a detached signature and
no archive or SBOM, so the loop above does not apply to it. Use `v0.2.0` or
later.

After verification, extract the platform archive and inspect the included
packaging files. Credentialed broker activation remains a separate deployment
gate; installation must not provision, print, or copy a provider credential.

## Developer install from a reviewed checkout

The crates.io package is not published, and publishing is currently blocked:
the workspace crates depend on one another by path with no version requirement,
which `cargo publish` rejects outright. Publishing would first require version
requirements on every internal dependency and then publishing all nine crates
in dependency order. For development, check out a reviewed commit and build
from source:

```bash
git clone https://github.com/Arcanada-one/arcana-agent-system.git
cd arcana-agent-system
cargo install --locked --path crates/cli
```

This installs the `arcana` binary declared by `crates/cli/Cargo.toml`. It does
not install or activate the separately packaged credential broker.

A Homebrew tap is not yet created. The collision results above are historical
probe evidence, not a current reservation of either name.
