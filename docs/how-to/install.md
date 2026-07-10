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
| `arcana-agent` | free | free |
| `arcana-agent-system` (current `crates/cli` package name) | free | free |

Both single-word ergonomic names from the original fallback list
(`arcana` default, `arcana-cli` per OQ-4) are already occupied on
crates.io. The workspace's current package name, `arcana-agent-system`,
is unclaimed and requires no rename — it is the default install target
below. `arcana-agent` remains available as a shorter alternative if a
rename is ever wanted; that is a product-naming decision for the operator,
not a mechanical follow-up.

## Install

```bash
cargo install arcana-agent-system
```

This builds and installs the `arcana` binary (declared via `[[bin]] name
= "arcana"` in `crates/cli/Cargo.toml`) to `~/.cargo/bin/arcana`.

No published release exists yet — `cargo install` from crates.io only
works after a `cargo publish` of `crates/cli` (and its path dependencies).
Publishing itself is a hard-gated, operator-run action (public,
effectively irreversible on crates.io) and is out of scope for this probe
— this document only records the collision-free path to take when that
publish happens. Until then, install from source:

```bash
git clone https://github.com/Arcanada-one/arcana-agent-system.git
cd arcana-agent-system
cargo install --path crates/cli
```

A Homebrew tap is not yet created; both `arcana` and `arcana-agent-system`
are free on `formulae.brew.sh` as of the probe run above, so no rename is
forced on that front either.
