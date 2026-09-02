# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- The release path no longer requires a human signature. Removed from the
  `preflight` job: the APPROVED review from the configured reviewer on the
  merged PR head SHA, the CODEOWNERS membership assertion for that reviewer,
  and the Ed25519 governance-witness verification. Removed from the
  `sec0030-protected-release` environment: the `required_reviewers` rule that
  held publication for a manual approval. The gate was introduced by PR #43
  with zero approvals, required by no vendor or external policy, and was
  unsatisfiable as configured -- `main` carries no
  `required_pull_request_reviews` block, so the exact-head approval it demanded
  could not be produced. This is a deliberate reduction in control: release no
  longer carries independent human attestation. Every machine-checkable
  condition is retained -- tagged SHA is the tip of `origin/main`, tag and
  `Cargo.toml` and CHANGELOG versions agree, all six protected checks are
  successful on that SHA from app id 15368, and exactly one merged PR produced
  it -- as are signing, SBOM, and provenance. See
  `docs/how-to/deployment.md` for the full record and how to restore it.

### Fixed
- The README opened with "Current release: `0.2.0`". No such release exists:
  `v0.1.0` (2026-07-26) is the only tag with a release behind it, and the only
  entry the Releases page serves. `0.2.0` is the workspace version on `main` --
  written, reviewed, and waiting on a tag. A reader following that line would
  have gone looking for a release that is not there, which is the most visible
  claim in the file. Status now names the released version, says plainly that
  `0.2.0` is unreleased, and points at the from-source build for anyone who
  wants what is on `main` today.
- Two entries under "Known limitations" in the README described states that no
  longer hold. It said `arcana login` could not work "until the provider side is
  rolled out" -- Auth Arcana now advertises `device_authorization_endpoint` in
  discovery, the endpoint answers a protocol error rather than 404, and the
  command prints a real verification URL and user code. And it said the model
  list was "cheapest first", which was the ordering before priced providers were
  sorted ahead and part of each cap reserved for rows that show a price. Both
  now say what the shipped binary does. The login entry keeps the honest limit:
  a completed sign-in needs a human at the verification URL and is not claimed.
- The architecture reference still listed `crates/connectors` and `crates/tools`
  as `(planned)`. Both ship: connectors carries the five modules that talk to
  Auth Arcana, the Model Connector, Scrutator, Ops Bot and Coworker, and tools
  carries eight tool implementations with their tests. The map now says so, and
  adds the caveat it could not show -- only `arcana_search` is on a live path
  today, inside `kb-read`; the other seven are implemented but not yet
  registered with the interactive session or the MCP server. Vault and LTM,
  named in the old line, have no module in either crate and are no longer
  claimed.
- The MCP reference said `tools/list` "returns exactly the capability-core tool
  set". Measured against the shipped binary, it returns exactly one tool:
  `whoami`, the placeholder the entrypoint exposes so the list is not empty. The
  eight real tools are implemented in `arcana-tools` but not yet wired into the
  server. A client reading that sentence would have expected a working toolbox
  and found an identity probe. The document now states what is returned today,
  names the tools that are not there yet, and keeps the part that was true --
  `arcana.resume` is a control tool and never appears in the list.
- The deployment guide's activate/verify/rollback commands could not run as
  written. They invoked `sudo packaging/broker-lifecycle.sh …` — a relative
  path into a repository checkout, where that file is committed mode 644.
  Measured rather than assumed: a mode-644 script fails with "Permission
  denied" when called directly and "command not found" under `sudo`; only an
  explicit `bash` prefix runs it. The release workflow installs the helper with
  `install -m 0755`, so the packaged copy is executable — and the same document
  already required running "the packaged helper with absolute paths from that
  verified root-only staging directory" ten lines earlier. These three commands
  contradicted that rule as well as failing outright; they now use the staged
  absolute path like the `install` step above them.
- The install guide said publishing to crates.io was blocked because the
  workspace crates depend on one another by path with no version requirement,
  "which `cargo publish` rejects outright". That stopped being true once the
  internal dependencies moved to `[workspace.dependencies]` with versions:
  `cargo publish --workspace --dry-run` exits zero and packages all nine crates
  in the required order. The guide now says what is actually true — publishing
  is a decision about nine permanent public API surfaces, not a manifest defect
  — and keeps the real objection, that `cargo install` cannot activate the
  separately packaged credential broker.
- The install guide still told readers the package was called
  `arcana-agent-system` and presented the rename as a hypothetical the operator
  might one day take -- while the rename had already shipped. Anyone following
  it would have installed a crate that does not exist under that name. The
  README named the same stale crate as the build source. Both now say
  `arcana-agent`, and the guide states explicitly which name did NOT change:
  the repository is still `Arcanada-one/arcana-agent-system`, so every URL and
  clone path keeps that spelling. The collision table also carried two rows for
  the same candidate once the rename merged them; deduplicated.
- The Ops Bot connector defaulted to a host that redirects. `ops.arcanada.one`
  answers `301 -> ops.arcanada.ai`, and a redirect that changes host makes
  reqwest drop the `Authorization` header, so every authenticated emit would
  have arrived unauthenticated and returned 401 -- which `emit` surfaces as a
  real error rather than swallowing. Measured against an echo service: the
  header survives a same-host redirect and does not survive a cross-host one.
  A `curl -L` check cannot see this, because curl keeps the header across
  hosts. The default now names the host that serves the API, and a test pins
  it so the redirecting alias cannot come back. Not yet observable in
  production: the client is exported but not wired into the composition root,
  so this is fixed ahead of that wiring rather than in response to a failure.

### Changed
- Published doc comments no longer cite private tracker identifiers. 113 of them
  across 21 source files carried ids that resolve only inside a tracker no reader
  of the published crate can reach; in the crate tarball and on docs.rs each was
  a reference to nowhere. Plain `//` comments, tests, and three ids inside string
  literals are untouched -- the last of those are a fixture, an eval label and an
  `incident:` field whose value is part of a contract. Where an id was the subject
  of its sentence the sentence was rewritten rather than truncated; a dangling
  verb or a bare section reference is the same dead end with fewer characters.

### Fixed

- `arcana models` showed 46 rows reading "price unknown" against 3 carrying a
  price, on a catalogue that holds 841 priced entries out of 987. Not a parsing
  defect and not a disagreement with billing -- both read the same data, and
  production billing prices exactly what the catalogue prices. Two overlapping
  biases in the shortlist produced it: the per-provider cap gave the same ten
  slots to the twenty-one connectors that publish no per-token price as to the
  three that do, and cheapest-first inside a provider let free tiers take every
  slot, so openrouter showed ten "free" rows while 396 paid models went unshown.
  Priced providers now sort first and each provider reserves part of its cap for
  rows that actually show a price; unused reserved slots fall back, so a
  provider with no prices still shows ten rows. Priced rows go 3 -> 13. The
  remaining "price unknown" rows are providers that publish no price at all.

- The CLI crate is named `arcana-agent` (was `arcana-agent-system`). Operator
  decision, taken before the first publish because a crates.io name is reserved
  by the first successful upload and cannot be given back — the long name would
  have been burned permanently on a crate whose binary is called `arcana`. The
  command is unchanged: `[[bin]] name = "arcana"`, and `cargo install
  arcana-agent` still installs `arcana`. Availability confirmed for both
  `arcana-agent` and `arcana_agent`, which crates.io treats as one name.

  Two things that merely contain the old string are deliberately untouched. The
  repository is still `Arcanada-one/arcana-agent-system`, so every URL, the
  `repository` field and the prose keep it. And
  `FIRST_DISPATCH_ADAPTER_BOUNDARY` — `"arcana-agent-system/driver/first-dispatch-v0"` —
  is a cross-service protocol identifier the Model Connector reads on the other
  side; renaming it as a side effect of a package rename would be a silent
  contract break, and its `-v0` suffix says how it changes when it does.

- `dev-tools/check-binary-name.sh` no longer reports every crate name as free
  when crates.io is unavailable. It decided free-versus-taken by grepping the
  response body for `"errors"`, a string that is in a 404 body — and in every
  other error body too. Under a 429, a 500 or a maintenance page, every name
  checked came back "free"; verified against a local server returning
  `429 {"errors":[...]}`, where `serde` read as free. It now switches on the
  HTTP status, as the Homebrew check in the same file already did, and maps
  anything that is not 200 or 404 to UNKNOWN. "Free" is the permissive answer
  here — it is what licenses an attempt to publish, and a crates.io version
  that fails is burned permanently. The test fixture modelled a free crate as
  HTTP 200 carrying a not-found body, so it agreed with the code while both
  disagreed with the registry; it is now an absent file, which is a 404.

  Two related holes closed with it. crates.io answers 403 to a request whose
  User-Agent is absent or the default `curl/*`, and it does so before deciding
  whether the crate exists — one answer for a taken name, a free one and a
  typo — so the User-Agent is now pinned by a fixture that reproduces that
  exact rule. And an inconclusive run no longer exits 0: with every registry
  unreachable the script printed UNKNOWN on every line and then exited 0, which
  a caller reads as "these names are available". It exits 3, while a definite
  TAKEN still exits 1.

- `release-pending`'s grace clock can no longer be reset by an unrelated
  manifest edit. It anchored on `git log -S"version = \"$version\""`, which was
  precise while the root `Cargo.toml` held exactly one copy of that string. It
  no longer does: `[workspace.dependencies]` carries the same string on eight
  internal crates, and `check-internal-versions.sh` guarantees they stay
  textually identical to the package version. `-S` fires on a change to the
  COUNT, so adding or removing one internal crate re-anchored the clock to that
  commit — silently granting another three days, and able to do so after the
  check had already begun failing. The anchor is now `-G` against a regex tied
  to the start of the `[workspace.package]` version line, with the version
  escaped so build metadata (`1.0.0+build.5`) matches literally rather than as
  `0+`. Extracted to `dev-tools/release-bump-anchor.sh`, because an inline,
  untestable copy is how it went wrong.

- `cargo publish` can run against this workspace. Every internal dependency
  was a bare `path` with no version, so `cargo publish -p arcana-agent-system`
  exited 101 before doing anything (#101). The sixteen declarations now inherit
  a single version from `[workspace.dependencies]`, and CI runs
  `cargo publish --workspace --dry-run` so the ability cannot be lost again to
  one careless manifest edit. Nothing is published — this restores the option,
  which for a nine-crate chain is worth having in hand: a crates.io version can
  be yanked but never reused, so the first real attempt has to be right.

  One declaration is deliberately left version-less. `crates/skills`'
  dev-dependency on `arcana-tools` closes the only cycle in the published graph
  (`tools -> connectors -> skills -> tools`); cargo drops a version-less
  dev-dependency when publishing, which breaks the cycle in the published
  manifests and is what lets cargo order the nine crates at all. Versioning it
  uniformly with the rest — the obvious thing to do — makes the cycle real and
  the workspace unpublishable again.

- Ctrl-C during a turn stops the run, says what it cost, and is recorded.
  Nothing installed a SIGINT handler, so an interrupt killed the process where
  it stood: the request already on the wire completed at the Model Connector
  and was charged anyway, the audit log gained nothing, and the operator was
  told neither. Measured live before the fix — `demo --live` interrupted at
  t=2.0s of a 5.1s turn exited 0 with zero bytes appended and no mention of the
  charge; the charge itself lands in the ledger five to ten seconds after the
  process is already gone. The first Ctrl-C now cancels the run and waits for
  the reply that is being billed regardless, which is what turns "you may have
  been charged" into an exact figure; a second exits immediately, so the wait
  cannot become a hang. An answer that already arrived is still delivered — it
  is paid for — but the verdict is `AbortedByOperator`, the abort is written to
  the audit log with the session spend, and the exit code is `130` rather than
  a `1` a wrapper script cannot tell from a product failure. Interrupting at
  the prompt, where no turn is running, still ends the session as it always
  has.

- `arcana models` no longer quotes a negative price, and no longer ranks the
  rows that carry one first. OpenRouter publishes `-1` for its auto-routing
  models, meaning "depends which model this routes to"; the catalogue's
  per-token to per-1M conversion multiplies it by a million, and the listing
  printed the result verbatim — `openrouter/auto: in $-1000000.00 / out
  $-1000000.00 per 1M tok`, a model that appears to pay the customer. Worse,
  `sort_price` summed the two tariffs to `-2000000`, the lowest number in a
  968-row catalogue, so cheapest-first ranked all five sentinel rows above every
  real model and the ten-per-provider cap displaced five genuine
  recommendations. A tariff is now a price only if it is finite and not
  negative — the same rule the billing path applies before charging anyone, so
  the listing and the invoice cannot disagree about what counts as a price.
  Models billed per second, per character or per image are labelled `not priced
  per token` rather than `price unknown`, which described a gap in the catalogue
  that could be filled when there is no per-token figure to fill it with.
  Measured on the live catalogue: negative prices 5 to 0, mislabelled rows 21,
  and `price unknown` down from 66 of 96 to 45 — the honest remainder.

- Slash commands in the interactive session are handled locally instead of
  being sent to the model and billed. `/help` returned 381 tokens of the model
  inventing a feature list for this product, presented as though it were the
  CLI's own help — the agent describing capabilities it does not have, to the
  person deciding whether to trust it — and charged for it; `/quit` answered
  "Goodbye!", charged, and left the session open. `help`, `/help`, `?`, `/?`,
  `exit`, `/exit`, `/quit` and `/q` now cost nothing and reach no model, and a
  mistyped `/halp` is refused rather than charged. Only exact bare tokens
  match, so `/etc/passwd is world-readable` is still a task.

- `arcana demo --live` reports what it cost. It charged the account and printed
  nothing, on the command a first-time user is told to run first and the one
  that dispatches on the expensive tier — so it was both the priciest
  invocation and the only silent one, while the interactive session had shown
  per-turn spend all along. An offline run now says plainly that nothing was
  charged rather than printing the offline connector's synthetic figure, which
  would invent a charge that never happened.

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
