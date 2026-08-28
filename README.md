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

This is the initial public release (`0.1.0`). The capability core and its
supporting subsystems ship in this release, as does the interactive session
(`arcana` with no subcommand). The OIDC login flow is still a stub (see
[Known limitations](#known-limitations) and the [CHANGELOG](CHANGELOG.md)).

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

Build and install from source (requires Rust `1.88+`):

```bash
cargo install --path crates/cli
```

This builds the `arcana` binary from the `arcana-agent-system` crate. A
crates.io publish and a Homebrew tap are **not yet available** — install from
source for now. See [docs/how-to/install.md](docs/how-to/install.md).

## Usage

```bash
arcana                    # interactive session — type a task, get a result;
                          #   `exit`/`quit`/`:q` or Ctrl-D to leave (--live
                          #   routes through the real Model Connector when
                          #   ARCANA_MC_TOKEN is set)
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

- `arcana login` is not implemented. It is specified as an Auth Arcana OIDC
  device-code flow, but the identity provider does not currently offer one:
  its discovery document advertises `authorization_code`, `refresh_token` and
  `client_credentials`, and no `device_authorization_endpoint`. Implementing
  login therefore needs a change on the provider side (enabling the device
  grant, or registering a client for the loopback authorization-code + PKCE
  flow that IS supported) before there is anything for the CLI to talk to.
- Tool calls in an interactive session are gated by the permission cascade,
  which is **fail-closed**. On a terminal you are prompted per call; without
  one, `ARCANA_PERMISSION_AUTO` decides and defaults to deny — so a piped or
  CI invocation runs the loop but declines the tool call unless that variable
  is set explicitly.
- `arcana demo` runs its loop through an empty permission cascade, which the
  cascade treats as deny-all, so the demo terminates on `PermissionDenied`
  before completing a tool call. The interactive session does not share this
  limitation.
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
