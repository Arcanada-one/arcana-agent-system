# How-to: deployment

> Stub — full pipeline lands in Phase 2 release task.

## Release matrix (planned)

| Target | Runner | Artefact |
|---|---|---|
| `x86_64-unknown-linux-musl` | ubuntu-latest (or self-hosted Linux) | `arcana-linux-x64` |
| `aarch64-unknown-linux-musl` | self-hosted arm64 | `arcana-linux-arm64` |
| `aarch64-apple-darwin` | macos-14 | `arcana-macos-arm64` |
| `x86_64-apple-darwin` | macos-13 | `arcana-macos-x64` |
| `x86_64-pc-windows-gnu` | windows-latest | `arcana-windows-x64.exe` |

## Distribution

Binaries attached to GitHub Releases on `Arcanada-one/arcana-agent-system`. Optional Homebrew tap + Cargo install (`cargo install --locked arcana-agent-system`) once public surface hygiene is verified.

## Post-deploy

- Health probe: `arcana --version` exits 0 and prints semver.
- Failure events → Ops Bot `POST https://ops.arcanada.one/events` `category: fatal`.
