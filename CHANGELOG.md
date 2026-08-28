# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `arcana login` — sign-in through the OIDC device-authorization grant
  (RFC 8628). Prints a short user code and a verification URL, polls the token
  endpoint through `authorization_pending`, honours a `slow_down` back-off, and
  on approval writes the credentials to the XDG state home with mode `0600`.
  The access token is never echoed to the terminal. A provider that does not
  offer the grant, an unreachable provider, a declined request, and a success
  envelope carrying no token are each reported as distinct fail-closed errors
  rather than a panic or a partially written credential.

- Interactive session: `arcana` with no subcommand now opens a REPL instead of
  printing a placeholder. It builds one capability core — the same driver,
  multi-model dispatch, tool dispatcher and audit log `arcana demo` assembles —
  and runs each entered task against it, so a session shares one append-only
  audit log and accumulates cost across turns. `exit`, `quit`, `:q` and Ctrl-D
  end it. On a terminal the prompt is `rustyline`; when stdin is not a terminal
  the same loop reads plain lines, so piped input is predictable rather than
  hanging.
- `--live` on the bare invocation, routing the session through the real Model
  Connector when `ARCANA_MC_TOKEN` is set (mirroring `demo --live`).

### Changed

- Interactive tool calls are gated by the canonical `Schema → Rule →
  Interactive` permission cascade rather than the empty cascade `arcana demo`
  uses. The cascade is fail-closed, so a call is denied unless a layer allows
  it: the operator is prompted on a terminal, and `ARCANA_PERMISSION_AUTO`
  decides off one (default deny).

## [0.1.0] - 2026-07-24

Initial public release.

`arcana` (crate `arcana-agent-system`, binary `arcana`) is an interactive CLI
agent written in Rust — a single static binary that integrates with the
Arcanada service mesh. This first release ships the capability core and the
supporting subsystems as a Rust workspace; the interactive REPL and the OIDC
login flow are still stubs (see *Known limitations*).

### Added

- **CLI (`arcana`).** Clap-based command surface with subcommands `version`
  (version / embedded git SHA / license), `whoami` (permission-cascade + audit
  smoke), `demo` (offline-deterministic vertical prototype of the full
  driver + dispatch + tool + permission + audit loop, `--live` opts into the
  real Model Connector), `kb-read` (one fail-closed agent loop grounded by the
  authenticated wiki KB), and `mcp serve` (expose the capability core as an
  MCP server over stdio or a loopback-only HTTP bind).
- **Core agent loop (`arcana-core`).** Agent loop, tool dispatcher, context
  and execution management, and a data-driven, deterministic model-selection
  policy that maps a step task-type to an abstract model id and a cost tier
  (cheap fast vs. expensive reasoning), tunable without touching the loop.
- **Permission cascade + audit.** Layered permission engine (rule / schema /
  interactive / hook-bridge) with a synchronous append-and-flush audit log, so
  a successful evaluation guarantees the decision and result records are durable
  on disk (Supreme-Directive Law-5 traceability).
- **Cost-budget + terminable supervision (`arcana-supervisor`).** Process
  supervisor with process-group ownership, heartbeat/timeout watchdog,
  restart/escalation policy, cost budgets, and a cost-breaker that terminates a
  run on `MaxCostUsd`.
- **Built-in tool standard (`arcana-tools`).** Read, Write, Edit, Grep, Bash,
  WebFetch, and ArcanaSearch tools, each behind a path/exec guard.
- **MCP server adapter (`arcana-mcp`).** Exposes the capability core over the
  Model Context Protocol on loopback only; non-loopback bind addresses are
  rejected before any socket is created.
- **Evolutionary skills engine (`arcana-skills`).** Declarative skill plans as
  data executed over the capability executor: a template → instance maturity
  ladder (Draft → … → production run floor), a skill builder that materialises
  schema-valid draft stubs, and a pinned interpreter that resolves a `SkillPin`
  through a `trust-class fence → hash → schema validate → maturity gate`
  pipeline.
- **Ecosystem connectors (`arcana-connectors`).** HTTP bridges to Arcanada
  services (Model Connector, Auth Arcana, Scrutator, Ops Bot) and a coworker
  subprocess wrapper.
- **Docs.** Diátaxis-structured documentation under `docs/` (tutorials,
  how-to, reference, explanation), including install, permissions, MCP server,
  supervisor, architecture, and CLI exit-code references.
- **Release provenance.** The binary embeds its git SHA; a falsifiable smoke
  gate (`dev-tools/smoke/arcana-smoke.sh`) asserts build provenance, audit
  behaviour, connector negative controls, agent-loop e2e, the cost breaker, and
  secret non-leak.

### Known limitations

- The interactive REPL is a stub (`arcana` with no subcommand prints a
  placeholder).
- `arcana login` (Auth Arcana OIDC device-code flow) is not yet implemented.
- `mc-ping` is a hidden debug surface, not a supported command.

### Stability (0.x caveat)

This is a `0.x` release. **The API may change between minor versions.** Per
[SemVer](https://semver.org/spec/v2.0.0.html), breaking changes are permitted
in `0.x` minors. Concretely:

- **Provisional surfaces (may change in any minor):** the skills schema
  (`SkillPlan` / `SkillPin` / maturity ladder), the MCP tool surface, the
  connector-dispatch contracts, and the configuration / environment-variable
  contract.
- **Hardening (changes avoided, but not yet frozen):** the core CLI command
  surface.

`0.1.0` is the SemVer floor and the pin baseline for every subsequent
`cargo install` / Homebrew consumer.

### Path to 1.0

`1.0.0` is an *earned* interface-stability milestone, not a quality badge. The
exit criterion: **two consecutive minor releases with no breaking change to the
skills, MCP, configuration, or connector schemas.** Meeting that bar promotes
the provisional surfaces above to stable and earns the `1.0.0` API-freeze
promise.

[Unreleased]: https://github.com/Arcanada-one/arcana-agent-system/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Arcanada-one/arcana-agent-system/releases/tag/v0.1.0
