# arcana

`arcana` (Arcanada Agent System) is an interactive CLI agent written in Rust — a
single static binary that integrates with the Arcanada service mesh. It ships the
agent capability core as a Rust workspace: an agent loop with cost-tiered
multi-model dispatch, a layered permission cascade backed by a durable audit log,
a terminable cost-budget supervisor, a built-in tool standard with an MCP
loopback adapter, and an evolutionary skills engine (a template → instance
maturity ladder with a trust-fenced `SkillPin` interpreter) grounded by the
Scrutator KB.

## Status

Current release: `0.2.0`. The capability core and its supporting subsystems
ship alongside the interactive session (`arcana` with no subcommand),
`arcana login`, model selection, spend reporting, and a separately packaged
credential broker (see the [CHANGELOG](CHANGELOG.md) and
[Known limitations](#known-limitations)).

### Stability (0.x)

`0.x` release — **the API may change between minor versions** ([SemVer](https://semver.org/spec/v2.0.0.html)
permits breaking changes in `0.x` minors):

- **Provisional (may change in any minor):** the skills schema
  (`SkillPlan` / `SkillPin` / maturity ladder), the MCP tool surface, and the
  connector-dispatch and configuration / environment-variable contracts.
- **Hardening (changes avoided, not yet frozen):** the core CLI command surface.

`1.0.0` is earned, not scheduled: two consecutive minor releases with no breaking
change to the skills, MCP, configuration, or connector schemas. See the
[CHANGELOG](CHANGELOG.md) for the full release notes.

## Install

### From a verified release (recommended)

Every release publishes per-platform archives (`linux-x86_64`, `macos-arm64`)
containing the `arcana` and `arcana-credential-broker` binaries and their
packaging files, together with CycloneDX SBOMs, SHA-256 files, keyless Sigstore
bundles, and GitHub build-provenance attestations.

Do not trust an archive because it appears on the Releases page. Verify all
three layers — checksum, signature, and provenance — before extracting
anything. Prerequisites: `gh` 2.40+, `cosign` 3.0+, and `sha256sum`.

```bash
TAG=v0.2.0                 # exact release tag
PLATFORM=linux-x86_64      # or macos-arm64
REPOSITORY=Arcanada-one/arcana-agent-system

mkdir "arcana-${TAG}-${PLATFORM}" && cd "arcana-${TAG}-${PLATFORM}"
gh release download "$TAG" --repo "$REPOSITORY" --pattern "*${PLATFORM}*"

sha256sum -c ./*.sha256
for artifact in ./*.tar.gz ./*.cdx.json ./*.sha256; do
  cosign verify-blob \
    --bundle "${artifact}.cosign.bundle" \
    --certificate-identity "https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/tags/${TAG}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$artifact"
  gh attestation verify "$artifact" --repo "$REPOSITORY"
done
```

Every command must exit zero. A checksum alone is not enough: an attacker who
can replace the archive can replace the checksum with it. Any signature or
attestation failure makes the release untrusted — do not extract it.

### From source

Requires Rust `1.88+`:

```bash
cargo install --locked --path crates/cli
```

This builds the `arcana` binary from the `arcana-agent` crate. It does
not install or activate the separately packaged credential broker.

A crates.io publish and a Homebrew tap are **not yet available**. Full detail,
including broker activation, is in
[docs/how-to/install.md](docs/how-to/install.md).

## Usage

```bash
arcana                    # interactive session — type a task, get a result;
                          #   `exit`/`quit`/`:q` or Ctrl-D to leave (--live
                          #   routes through the real Model Connector when
                          #   ARCANA_MC_TOKEN is set)
arcana login              # sign in via the OIDC device grant: shows a short
                          #   code to enter in a browser, then stores the
                          #   credentials under the XDG state home (mode 0600)
arcana models             # curated model list from the LIVE Model Connector
                          #   catalogue, with price per 1M tokens
arcana models use <ID>    # choose the model this agent uses; any id is
                          #   accepted, including one the list does not show
arcana usage              # token spend as the Model Connector recorded it
arcana version            # print version, embedded git SHA, and license
arcana whoami             # permission-cascade + audit smoke check
arcana demo [TASK]        # offline-deterministic driver + dispatch + tool +
                          #   permission + audit loop (--live routes through the
                          #   real Model Connector when ARCANA_MC_TOKEN is set)
arcana kb-read <QUERY>    # one fail-closed agent loop grounded by the wiki KB
arcana mcp serve [--bind 127.0.0.1:PORT]
                          # expose the capability core as an MCP server
                          #   (stdio by default; --bind starts a loopback-only
                          #   HTTP listener — non-loopback binds are rejected)
```

Run `arcana --help` for the full command reference.

## Known limitations

- `arcana login` (OIDC device grant, RFC 8628) reaches a working provider:
  Auth Arcana advertises `device_authorization_endpoint` in its discovery
  document, and the command prints a real verification URL and user code. What
  is not claimed here is a completed sign-in — that needs a human at the
  verification URL, so the end-to-end flow is unverified rather than known
  good. Against a provider without the grant it still fails closed and exits
  `2`, writing no credential.
- Tool calls in an interactive session are gated by the permission cascade,
  which is **fail-closed**. On a terminal you are prompted per call; without
  one, `ARCANA_PERMISSION_AUTO` decides and defaults to deny — so a piped or
  CI invocation runs the loop but declines the tool call unless that variable
  is set explicitly.
- `arcana models` needs `ARCANA_MC_TOKEN`. The list is read from the live
  catalogue and is never hard-coded, so without a token there is nothing to
  show and the command says so rather than printing a stale table.
- The model list is capped at 10 per provider. Providers that publish prices
  sort first, and part of each cap is reserved for rows that actually show a
  price, so a provider's free tier cannot fill every slot and hide its paid
  models. The cap is presentational only — `arcana models use` accepts any id,
  including one the list does not show.
- `mc-ping` is a hidden debug surface, not a supported command.

## Documentation

Documentation follows the [Diátaxis](https://diataxis.fr/) taxonomy under
[`docs/`](docs/):

- [Tutorials](docs/tutorials/) — learning-oriented walkthroughs.
- [How-to guides](docs/how-to/) — install, permissions, deployment, testing.
- [Reference](docs/reference/) — architecture, CLI exit codes, MCP server,
  `permissions.toml`, supervisor.
- [Explanation](docs/explanation/) — the capability-execution boundary.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option (`MIT OR Apache-2.0`).
