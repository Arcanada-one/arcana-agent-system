# arcana v0.1.0 — Initial public release

`arcana` is an interactive CLI agent written in Rust: a single static binary
that integrates with the Arcanada service mesh. This is its first public
release.

## What it is

A Rust workspace shipping the agent capability core and its subsystems:

- A core agent loop with a tool dispatcher and a data-driven, deterministic
  model-selection policy (task-type → abstract model id + cost tier).
- A layered permission cascade with a synchronous, durable audit log.
- A terminable process supervisor with heartbeat/timeout watchdog, cost
  budgets, and a cost-breaker.
- A JSON-Schema-validated built-in tool standard (Read/Write/Edit/Grep/Bash/
  WebFetch/ArcanaSearch).
- An MCP server adapter that exposes the capability core over loopback only.
- An evolutionary skills engine: declarative skill plans as data, a
  template → instance maturity ladder, a skill builder, and a pinned,
  trust-fenced interpreter.
- Connectors to Model Connector, Auth Arcana, Scrutator, and Ops Bot.

The interactive REPL and the OIDC login flow are stubs in this release.

## Install

Once published to crates.io:

```bash
cargo install arcana-agent-system
```

This installs the `arcana` binary to `~/.cargo/bin/arcana`. (The crate name
is `arcana-agent-system`; the single-word `arcana` / `arcana-cli` names are
already taken on crates.io.)

Until the crates.io publish, install from source:

```bash
git clone https://github.com/Arcanada-one/arcana-agent-system.git
cd arcana-agent-system
cargo install --path crates/cli
```

Homebrew: a tap is not yet created. When one lands, `brew install` instructions
will be added here.

## Stability (please read)

This is a `0.x` release. **The API may change between minor versions** —
breaking changes are allowed in `0.x` minors under SemVer.

- Provisional (may change in any minor): skills schema, MCP tool surface,
  connector-dispatch contracts, config / env-var contract.
- Hardening (changes avoided): the core CLI command surface.

Path to 1.0: two consecutive minors with no breaking change to the skills /
MCP / config / connector schemas earns the `1.0.0` API-freeze promise.

## License

Dual-licensed under **Apache-2.0 OR MIT** — your choice. See `LICENSE-APACHE`
and `LICENSE-MIT`.

## Documentation

Diátaxis-structured docs live under `docs/`:

- Tutorials: `docs/tutorials/`
- How-to (install, permissions, deployment, testing, gotchas): `docs/how-to/`
- Reference (architecture, CLI exit codes, MCP server, permissions TOML,
  supervisor): `docs/reference/`
- Explanation (capability-execution boundary): `docs/explanation/`

## Verifying this release

Each release binary is published with a SHA-256 checksum, a cosign blob
signature, and a GitHub build attestation. See the release-verify recipe to
round-trip `cosign verify-blob` + `gh attestation verify` before running the
binary.
