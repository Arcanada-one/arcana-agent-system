# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `arcana kb-read` reports why the search failed, not that an internal invariant
  was violated. A missing client secret, an unreadable one, a 401, a 503 and a
  saturated backend all printed the identical line — `grounding proof requires
  exactly one successful search (observed 0)` — because the counter simply never
  incremented and the real failure was discarded. The cause is now captured
  where the tool call fails and carried into the message, with the invariant
  kept only as a backstop for when nothing was recorded. Internal error-variant
  names no longer leak into the sentence.

- `arcana models` lists the models the agent actually routes to. Curation is
  cheapest-first capped per provider, and `orq` carries enough free models to
  fill every slot — so both dispatch tiers were pushed out, and the header read
  `Selected: deepseek-v4-flash` above a list that did not contain it. The
  selected model and the dispatch tiers are now always listed, taking slots
  rather than adding to them. The ids come from the dispatch policy itself, so
  the listing cannot drift from what the agent will actually call.
- Piping `arcana models` or `arcana usage` into a reader that stops early no
  longer exits 101. Rust ignores `SIGPIPE`, so a closed reader arrives as an
  `EPIPE` write error and `println!` panics on it — with the panic message
  itself lost to the same closed pipe, leaving a plausible prefix of the output
  and an unexplained failure code. `models` prints 123 lines against the live
  catalogue, so `| head`, `| grep -m1` and quitting out of `| less` are the
  ordinary ways to read it, and each of them broke `set -o pipefail` scripts.
  Both commands now write through a checked handle and treat a closed reader as
  the reader having finished, which it has.
- `arcana --help` is written for the person reading it. It described commands in
  internal vocabulary — `Phase-C vertical prototype`, `Bootstrap smoke check`,
  `Tier-1 loopback`, `capability core` — which name our roadmap phases and
  architecture rather than what a command does. The product's main mode was
  invisible: running `arcana` with no subcommand starts an interactive session,
  and that appeared nowhere except inside the `--live` flag text. And the
  environment variables that most commands require were documented nowhere, so
  a first run met them in an error message or not at all. All three fixed, with
  a test that fails if internal vocabulary or an internal task id reappears.

- `arcana models` and `arcana usage` say what the server said. Both carried
  their own HTTP client and collapsed every non-2xx into the bare status
  number, reading the response body and throwing it away — so a 402 whose body
  said `Insufficient credit: balance 0.00 USD`, a 400 naming exactly which
  query parameters were missing, and a 503 were all rendered as a number. The
  message now carries the server's own text, and a `Retry-After` header is
  reported instead of discarded.

## [0.2.0] - 2026-08-31

The first release you can actually drive. `0.1.0` shipped the capability core
with the interactive session and sign-in still stubbed out; this release turns
both into working commands, adds model selection and spend reporting, and
splits provider credentials out of the agent process into a separate,
privilege-separated broker.

### Added

- **Interactive session.** `arcana` with no subcommand now opens a session
  instead of printing a placeholder. It builds one capability core — the same
  driver, multi-model dispatch, tool dispatcher and audit log `arcana demo`
  assembles — and runs each entered task against it, so a session shares one
  append-only audit log and accumulates cost across turns. `exit`, `quit`,
  `:q` and Ctrl-D end it. On a terminal the prompt is `rustyline`; when stdin
  is not a terminal the same loop reads plain lines, so piped input is
  predictable rather than hanging. `--live` routes the session through the
  real Model Connector when `ARCANA_MC_TOKEN` is set.
- **`arcana login`.** Sign-in through the OIDC device-authorization grant
  (RFC 8628). Prints a short user code and a verification URL, polls the token
  endpoint through `authorization_pending`, honours a `slow_down` back-off, and
  on approval writes the credentials to the XDG state home with mode `0600`.
  The access token is never echoed to the terminal. A provider that does not
  offer the grant, an unreachable provider, a declined request, and a success
  envelope carrying no token are each reported as distinct fail-closed errors
  rather than a panic or a partially written credential.
- **`arcana models` and `arcana models use <ID>`.** The model list comes from
  the live Model Connector catalogue (`GET /connectors/catalog`), never a
  hard-coded table, and shows the price per 1M tokens beside each model.
  Capped at 10 per provider, cheapest first, with free models leading and
  unpriced ones last — an unknown price is not a cheap price. The cap is
  presentational: `use` accepts any id, including one the list does not show.
  The choice persists in the XDG state home, defaults to `deepseek-v4-flash`,
  and an explicit choice pins the model policy so it is honoured on task-typed
  turns rather than only supplying the fallback arm.
- **Spend reporting.** The interactive session prints tokens and cost for each
  turn plus the session running total, and `arcana usage` reports what the
  Model Connector has recorded. The per-turn figure is a delta — the session
  cost tracker is cumulative, so echoing it would bill every later turn for
  everything before it. Figures carry six decimals, because a cheap call costs
  far less than a cent and two decimals would show `$0.00`. `arcana usage`
  reads from the connector and refuses without a token rather than falling
  back to a local tally that would look authoritative while disagreeing with
  what was actually charged.
- **Credential broker (`arcana-credential-broker`).** A privilege-separated
  local broker that is the sole holder of provider credentials, shipped as a
  second binary alongside `arcana`. Its library is protocol, policy, ledger and
  audit only and contains no secret-loading code, so nothing that links it can
  acquire provider authority. Platform packaging ships with the release: a
  socket-activated systemd unit on Linux, a launchd agent on macOS, an example
  capability policy, and a lifecycle helper for install, upgrade and rollback.
- **Execution boundary (`arcana-execution-boundary`).** A typed, fail-closed
  boundary for launching child processes in a clean environment with streaming
  output quarantine, so a subprocess neither inherits ambient credentials nor
  streams unvetted output back into the agent loop.
- **Opt-in paired first-dispatch measurement** on `arcana demo --live`, behind
  explicit flags and restricted to identifier-only metadata: the payload must
  carry no prompt text, credentials, token counts, or authorization claims.
- **Signed, attested release artefacts.** Releases now carry per-platform
  archives for `linux-x86_64` and `macos-arm64` containing both binaries and
  the packaging files, plus CycloneDX SBOMs, SHA-256 files, keyless Sigstore
  bundles, and GitHub build-provenance attestations for every artefact. See
  [docs/how-to/install.md](docs/how-to/install.md) for the verification recipe.

### Changed

- Interactive tool calls are gated by the canonical `Schema -> Rule ->
  Interactive` permission cascade rather than the empty cascade `arcana demo`
  used. The cascade is fail-closed, so a call is denied unless a layer allows
  it: the operator is prompted on a terminal, and `ARCANA_PERMISSION_AUTO`
  decides off one (default deny).
- The default model policy now names real, priced, dispatching models in every
  tier, so a fresh install dispatches without first being reconfigured.
- Release notes are taken from this file rather than generated from commit
  subjects.

### Fixed

- Connector failures say what went wrong. Every transport error used to render
  as `error sending request for url (...)` — the same eleven words for a
  connection refused in 8 ms and a stall that burned the full 120-second
  request budget, because `reqwest::Error::to_string()` drops the cause chain.
  Failures now lead with a headline (`could not connect`, `timed out after
  120s`) and carry the underlying cause, so `Connection refused (os error 111)`
  reaches the operator instead of being discarded.
- A credential containing a newline no longer fails with `transport error:
  builder error`. `ARCANA_MC_TOKEN` is validated where it is read: surrounding
  whitespace is trimmed before use rather than only before the emptiness check,
  and a control byte that cannot go in an HTTP header is reported by name and
  offset. The message never echoes the credential.
- Out-of-credit and rate-limit responses show their remediation. The connector's
  logical-error contract carries `recommendation` and `retryAfter`; both were
  parsed and then dropped by the error's `Display`, so the one field whose whole
  purpose is telling the caller what to do next never reached them. A rejected
  request now reads `the request was rejected — Insufficient credit: balance
  0.00 USD. Top up your balance at <url>. (insufficient_credit)` instead of
  `upstream logical error [insufficient_credit]: ...`.
- `arcana usage` works against the real stats route. It sent neither of the
  two query parameters the route requires, so every call was an unconditional
  HTTP 400 — masked as a 403 until the read token was configured, which is why
  the command shipped and stayed broken. The response shape was wrong
  underneath that as well: rows arrive as `day` / `totalTokens` / `costUsd`
  aggregated per model, and every field defaulted, so the table would have
  rendered zeroes rather than failing. Adds `--since` / `--until`, defaulting
  to the last 30 days, and prints the server's own message when it refuses.
- `arcana models` works against the real catalogue. It decoded the response as
  a bare JSON array while `GET /connectors/catalog` returns
  `{"models": [...], "count": N}`, so the command failed on the first byte for
  its whole life — `the catalogue response could not be read` against a healthy
  endpoint serving 969 models. The entry shape was wrong underneath that too:
  tariffs arrive nested under `pricing`, so fixing only the envelope would have
  listed every model as `price unknown`. Models the connector reports as
  unavailable are no longer offered as choices.
- The interactive session exits non-zero when a turn fails. It returned `0`
  unconditionally on a clean session end, so `printf 'task\n' | arcana --live`
  against an out-of-credit key printed the failure and exited `0` — and
  `arcana ... && deploy` deployed. `arcana demo` already exited `1` on the
  identical condition; two commands wrapping the same driver no longer
  disagree about what failure is.
- Terminal verdicts are explained in words. `demo` and the interactive session
  formatted `TerminalReason` with `{:?}`, so the operator was shown
  `ConnectorFatal` and `ContextWindowExhausted` verbatim. Each verdict now
  carries a sentence — an over-long prompt says to shorten it or choose a model
  with a larger context window — with the variant name kept as a trailing
  parenthetical for support.
- The interactive permission prompt no longer waits forever. Failing closed on
  EOF is not enough on its own, because a terminal that is attached and idle
  never reaches EOF: `script -qec 'arcana whoami' /dev/null < /dev/null` was
  still alive at 60 seconds and had to be killed, with the prompt line as the
  last thing the process ever printed. That is the shape of every `ssh -t host
  arcana ...`, every CI job that allocates a pty, and every unattended pane.
  The read is now bounded — two minutes by default, overridable with
  `ARCANA_PROMPT_TIMEOUT_SECS`, and `0` restores the unbounded wait — and a
  prompt nobody answers denies, saying so.
- `arcana kb-read` tells a failed search apart from one that found nothing. A
  search that never dispatched, one that timed out in transport, and one that
  ran and matched nothing all produced the same message — and the last of the
  three, a legitimately empty result, exited non-zero. They are three outcomes
  now: a dispatch problem, a transport failure that points at the search
  service, and a plain `No matches` that exits 0.
- `arcana version` can no longer claim a commit the binary does not contain. It
  stamped `git rev-parse HEAD` with no check on the working tree, so a build
  carrying uncommitted changes reported that commit and said nothing; the
  rebuild triggers were also inert inside a git worktree, letting a stale stamp
  outlive the commit it named. A dirty build now carries a `-dirty` marker and
  prints an explicit warning that its provenance cannot be verified.
- `arcana demo` completes its loop. It ran through an empty permission cascade,
  which is fail-closed and therefore denied every tool call, so the command
  advertised as demonstrating the permission cascade only ever demonstrated a
  refusal. It now runs the same canonical cascade as the interactive session;
  off a terminal it still denies by default, so the demo is not the one path
  where permissions are waived.
- `arcana demo` writes its audit log under the per-user XDG state home instead
  of a fixed path in the shared temp dir. A stale world-readable log left there
  by an earlier run made every later demo fail outright, because the audit
  writer correctly refuses an insecure file.
- `arcana login` now reports an expired device code plainly. The provider
  answers an expired code with `invalid_grant`, not the `expired_token` RFC
  8628 specifies, so the operator previously saw "sign-in failed
  (invalid_grant): grant request is invalid" instead of being told to request
  a new code. Found on a live sign-in attempt.
- `arcana usage` sends the credential the stats route actually accepts, so the
  command reports spend instead of failing authorization.
- The interactive session and `arcana demo` dispatch through a connector that
  exists, and say which one failed and why when a dispatch does not land,
  instead of reporting a generic error.

### Security

- The runtime credential boundary is closed: secret loading lives exclusively
  in the broker binary, and security-sensitive crates, packaging, workflows and
  release controls now require review from a named code-owner group.
- Dependency updates carrying advisory fixes, including `chacha20` 0.10.2
  (0.10.1 was yanked) and `h2` 0.4.19 (RUSTSEC-2026-0258).

### Known limitations

- `arcana login` only works against an identity provider that offers the device
  grant. Until the provider side is rolled out, the command fails closed with a
  message saying exactly that and exits `2` — it does not hang, and it writes
  no credential.
- `arcana models` and `arcana usage` need `ARCANA_MC_TOKEN`. Without one there
  is nothing to show and each command says so rather than printing a stale
  table or a local tally.
- `mc-ping` is a hidden debug surface, not a supported command.
- The crate is not on crates.io and there is no Homebrew tap. Install from a
  verified release archive or build from source.

### Stability (0.x caveat)

This is still a `0.x` release and **the API may change between minor
versions**. The provisional surfaces named in `0.1.0` — the skills schema, the
MCP tool surface, and the connector-dispatch and configuration contracts —
remain provisional. `1.0.0` is earned by two consecutive minor releases with no
breaking change to those schemas.

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

[Unreleased]: https://github.com/Arcanada-one/arcana-agent-system/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Arcanada-one/arcana-agent-system/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Arcanada-one/arcana-agent-system/releases/tag/v0.1.0
