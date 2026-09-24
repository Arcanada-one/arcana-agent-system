# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`arcana run --work-item … --ground-truth <PATH>`** quotes a file from the
  repository into the work item's brief as the authority on names, flags and
  environment variables, and records each path with the sha256 of the bytes that
  reached the prompt in the receipt's new `ground_truth` section. A2-285's run
  produced the page it was asked for and got every command in it wrong: the brief
  described the deliverable and never showed the command it was about. Grounding
  is a DECLARATION by whoever dispatches the run, in the same shape as
  `--read-only` — a repository file such as `arcana run --help` piped out, not
  prose written for the model to copy, which would make the run a measurement of
  the operator. A named file that cannot be read or is empty refuses the run
  (`GROUND_TRUTH_UNREADABLE`, `GROUND_TRUTH_EMPTY`) before the first model call,
  because a run that silently lost its grounding is indistinguishable in the
  receipt from a grounded one that went wrong (A2-292).
- **A command line printed in our documentation is now parsed by the CLI's real
  clap definition.** `crates/cli/tests/docs_truth.rs` extracts every command in
  every fenced block under `docs/` and in `README.md`, and runs it through
  `Cli::try_parse_from`; every `NAME=` assignment in those blocks must occur
  somewhere in the program outside the docs. It exists because PR #214's
  `docs/how-to/run-work-item-under-kc2-contract.md` — written end to end by the
  agent under its KC2 contract, reviewed as an artefact, green on all eight
  checks — named a binary `aras` (it is `arcana`), a flag `--contract` (it is
  `--contract-file`, which requires `--work-item`), a flag `--item` (it is
  `--work-item`), and two environment variables, `KC2_CONTRACT` and
  `KC2_SNAPSHOT`, that exist nowhere in this repository. "The page was written"
  and "the page is true" were being measured by the same check, which was the
  first one only (A2-292).

  Run against that page unedited, the check reports twelve findings and two
  unknown variables; the page is kept as a fixture so the red is reproducible
  rather than described. The clap definition moved out of `main.rs` into
  `arcana_cli::cli` for this: a test parsing against a second copy of the
  surface would have accepted `--contract` as soon as the copy drifted.

  Names that are not `arcana` but are this tool (`aras`, `arcana-agent-system`,
  …) are findings in themselves — without that list the check would have passed
  #214's page in silence, because the page never mentioned the binary at all.
  Printed OUTPUT is out of scope and stated as such: a parser cannot judge a
  success line a model invented. Nine dated allowances cover shell locals of the
  runbooks' own example scripts (`VAULT_*`, `BROKER`, `TAG`); an allowance that
  excuses nothing any more is itself a failing test.

### Fixed
- **`write` reported success for writing nothing.** Measured in the A2-285 live
  run: the model called `write` twice, each call created the same 0-byte file,
  each was recorded `outcome: success` in the audit log, and the run's effect
  check read the moved tree digest as progress. Empty or whitespace-only
  `content` is now refused before any filesystem I/O, with a refusal that names
  the way to ask for it on purpose — `allow_empty: true`, which is in the schema
  the model is shown, because an enforced rule nobody stated is a defect of its
  own (A2-231). Truncating a file still works; it is now declared (A2-292).
- **The audit log could not tell a written page from a written nothing.** The
  `result` record kept `output_hash` and nothing else, so the two 0-byte writes
  above were indistinguishable in the log from a call that wrote the
  deliverable. The record now carries `bytes_written`, lifted from the tool's own
  metadata under the constant both ends share
  (`arcana_core::hooks::audit::BYTES_WRITTEN`). A count carries no file text and
  no model text, so it can be written in clear where the output cannot; it is
  `null`, not `0`, for every tool that does not write (A2-292).

### Fixed
- **`arcana run` said "Completed" for work it never wrote.** The done-marker's
  `completed` was decided by the terminal reason and the number of tool calls
  that executed, and a count cannot tell reading from writing. Pilot A2-278
  (2026-09-24, `deepseek-v4-flash`, live) ran one Muneral work item twice: runs
  2 and 4 executed nine and three calls, every one a `read` or a `grep`, wrote
  nothing, and both ended `"completed":true` with rc `0` while the model
  described "the documentation page `docs/how-to/run-work-item.md`" — a file
  that does not exist, containing commands this binary does not have. The guard
  documented in `docs/how-to/run-one-task-unattended.md` ("`completed` is never
  `true` with `tool_calls` at `0`") counted the reads and passed them.

  Completion is now tied to an effect a third party can check. The working tree
  under `--cwd` is digested before the first model call and again after the last
  one — tracked and untracked files alike, excluding `.git/`, the runner's own
  `.arcana/`, and everything the repository's `.gitignore` files exclude, so a
  `cargo build` is not mistaken for an artefact. A run that completed with the
  digest unmoved ends on **`NoEffect`**: `"completed":false`, exit `1`. Both
  digests, the executed tools by name, and the successful `write`/`edit` calls
  are carried in `ARCANA_RUN_DONE` and in the `ReadinessReceipt/v1`.

  A second refusal, measured into existence by the first live run under the new
  check: that run executed two `write` calls, both of which created the same
  EMPTY probe file `test-write-check.md`, then described
  `docs/how-to/run-work-item-under-kc2-contract.md` in four numbered points. The
  page does not exist — but the tree HAD changed, so the digest alone said
  `Completed`. An incidental write must not buy a run out of its own claim, so
  the paths the final message names are looked up on disk and a non-empty
  `effect.claimed_but_absent` ends the run on **`ClaimedButAbsent`**, exit `1`
  (printed on stderr as well as carried in the marker). A string scan and a
  `stat`; no model call. `claimed_but_unchanged` is reported and not refused —
  a rewrite with identical bytes is ambiguous. And a task that legitimately changes nothing
  is declared `--read-only` **by the caller, before the run**; nothing the model
  does during the run can set it. An unmeasurable tree — an unreadable directory
  or more than 200 000 files — reports `tree_changed: null` and refuses nothing,
  because `NoEffect` is a refusal and a refusal has to be provable.
- **A tool call may carry a code fence.** The closing fence of a `tool_call`
  block used to be the first ```` ``` ```` after the opening one — including a
  fence inside the JSON payload. Asked on a live contract-bound run for a
  Markdown how-to page, the model sent a well-formed `write` whose `content`
  held ```` ```json ````; the body was cut there, the slice was not JSON, and
  the run ended `UnsupportedToolCallFormat` having written nothing. Every
  documentation page with a code block in it was unwritable through the runner.
  The closing fence is now one that STARTS A LINE: the block's body is JSON, so
  a real newline never occurs inside one of its string literals, which makes
  that boundary exactly the line between the model's markup and its data. A
  block with no line-initial fence is still `Unterminated`.

### Changed
- **A contract-bound run is told how it will be judged.** The brief a
  `--work-item` run is given now states, in the prompt, that the working
  directory is digested before the first turn and after the last, that equal
  digests are `NoEffect`, that a path named in the closing message and absent
  from disk is `ClaimedButAbsent`, and that a probe file does not help — then
  asks for the deliverable in a single `write` before anything is said about
  it. An enforced-but-undisclosed rule is the same defect as no rule at all
  (A2-231), and this one decides whether the run counts.

  Measured on the same work item and model as the failures above: four live
  runs under the old brief produced nothing while reporting success, the fifth
  wrote an empty probe file and described a page it had not written, and the
  first run under this brief wrote the whole page in one `write` call for
  $0.009045 (`claimed_but_absent: []`, `changed_paths` naming exactly the page).
- **The model choice is configuration, and survives an isolated state
  directory.** It used to be read from `$XDG_STATE_HOME/arcana/model.json`.
  Every isolated runner overrides that directory so one run's audit log cannot
  leak into the next, and the choice went with it: a pilot run under an
  overridden state home fell through to the tiered policy and dispatched its
  first turn to `grok-3-latest` and its remaining five to `deepseek-v4-flash`,
  while the lane had pinned a single model. Resolution is now, first answer
  wins: `--model <id>` → `ARCANA_MODEL` → `$XDG_CONFIG_HOME/arcana/model.json`
  (where `arcana models use` writes from now on, beside `permissions.toml`) →
  the old state file, still read but reported as deprecated on stderr → the
  tiered policy. A resolved model pins every dispatch in the run; the value
  `tier` in any of the top three slots selects tiered dispatch on purpose, and
  is reported as a decision rather than as an absence.

  The run prints which source answered before the Model Connector client is
  built, so it cannot have spent anything by the time it says so:
  `model: deepseek-v4-flash (source: env)`. A contract-bound run records the
  same answer in its receipt as `mc_usage.model_source` beside
  `mc_usage.configured_model` — the intent next to `selected_models`, which is
  what was dispatched. A receipt that carries only the second cannot tell a
  lane's choice from a policy filling a gap.

- **A `ReadinessReceipt/v1` written by a run is no longer committable by
  accident.** `/receipts/ReadinessReceipt-*.json` is ignored. Graph admission
  reads a committed run receipt as a historical claim — asserted, never
  re-verified — and returns `not_measured`, which admits the change
  `PAUSED_SAFE`; the evidence of a paid run belongs in the pull request and in
  the dispatcher's run directory. `receipts/graph/` stays tracked: an admission
  receipt is a claim about the change that carries it.

### Added
- **Every executed work item now leaves a blueprint candidate.** A
  `--work-item` run writes a `LearningTraceCandidate/v1` next to its receipt:
  the contract digest it ran under, the ordered steps the audit log records it
  actually took with the decision and outcome of each, the distinct tools that
  executed, cost, the receipt linked by digest, and the verification state.
  KC2's upward half — `LearningTrace` → `PromotionProposal` → `Blueprint` — had
  no producer at all: all five upward records in the knowledge store were
  hand-authored, none came out of an executed task.

  Derived, never narrated. Every field comes from the audit log, the contract
  binding and the driver's counters; there is no model call and the model's own
  final text is not read. A trace assembled by asking the model what it had
  done would be the model's account of itself, which is the one kind of
  evidence a promotion may not rest on. A run that was refused, ran out of
  budget or changed nothing writes a trace too, marked `negative` — a
  capability set that succeeds twice and fails nine times is not a blueprint,
  and that is only visible if the nine were kept. Verification is reported as
  `not_measured` by name rather than as an empty list of verdicts, so a reader
  cannot take "nothing ran" for "nothing was wrong".

  The grouping key is the capability set: the distinct tools the run ACTUALLY
  executed, not the contract's allowlist. It is derived twice, independently —
  once by reading the durable audit log, once from the driver's own
  `executed_tools` — and a disagreement marks the trace negative rather than
  picking a winner. The first live run of this code reported an empty
  capability set for a run that had executed three tools, because the
  derivation matched an outcome literal the log has never written, and every
  unit test agreed with it: the fixtures carried the same wrong literal. The
  second witness is what that defect bought.
- **`arcana run --work-item <id>` — one Muneral work item, executed under the
  KC2 contract it is bound to, and a `ReadinessReceipt/v1` that says so.** The
  command is four steps and the first three are refusals. Read the work item
  (`GET /tasks/{id}`, agent key from the file named by
  `ARCANA_MUNERAL_KEY_FILE`, read-only — the status transition belongs to the
  control plane and an executor that closed its own work item would be the only
  witness to its own success). No `contractDigest` → `CONTRACT_MISSING`, before
  the Model Connector client is constructed and therefore before a token is
  paid for. Fetch the contract under that digest from Argana
  (`GET /v1/contract/{digest}`, `ARCANA_ARGANA_URL`) or from `--contract-file`,
  and RE-HASH it → `CONTRACT_DIGEST_MISMATCH`, also before the first model
  call. Only then run, with the contract's tool allowlist in the permission
  cascade, and write `receipts/ReadinessReceipt-<id>.json`.

  **The digest is re-hashed, never re-derived.** Argana stamps a contract with
  `H(canonical(body) ‖ canonical(closure_manifest))` computed by the KC2 pin's
  own canonicaliser; a second implementation of that rule in Rust would
  disagree with the first eventually. So `arcana_core::contract` hashes the
  bytes the SOURCE declares as the preimage — `canonical.bytes_b64` from
  Argana's answer — and compares them to the digest the WORK ITEM carries,
  never to the digest the answer carries. A projection that is an OBJECT is
  never hashed: re-serialising it would be this client inventing a
  canonicalisation rule and arriving at a digest that is nobody's.

  **What a contract that names no tools grants.** `read`, `grep`, `write`,
  `edit` — and no shell. A shell is the one capability whose blast radius is
  not bounded by its own arguments, so it has to be granted in words. The
  default is recorded on the binding and in the receipt as
  `default-no-shell`, so it is never indistinguishable from a contract that
  asked for those four.

  **The catalogue is the allowlist.** Under a contract, the system prompt
  offers only the admitted tools. This is not cosmetic: the first live run on
  work item `b1227e82` ended on turn 2 with `tool_calls: 0` because the prompt
  listed `bash` under AVAILABLE TOOLS while a paragraph below said the contract
  did not admit it, and the model read the list. Registration is unchanged —
  every tool stays in the dispatcher and the cascade still owns every refusal.

  Measured end to end on arcana-devs 2026-09-24 against live Muneral, live
  Argana on arcana-prd and live Model Connector: receipt
  `contractDigest == sha256:769cc084…` equal to Muneral's, `tool_calls: 3`,
  6 dispatches, $0.0319; and the run before the catalogue fix as the negative
  control, `bash` denied by the `contract-allowlist` layer with the refusal in
  `.arcana/denied/0001-turn2.json`. Both receipts are in the pull request that landed this,
  and on arcana-devs under `arc2/runs/A2-272/live/`.
- **The `input` key applied twice is read as the call it is.** Pilot A2-240c
  (arcana `17cffe0`, 68 turns, 63 attempted calls, 13 denied) spent **7 of its
  13 denials** on one shape: a `bash` call whose command was already correct,
  wrapped in a second `input` key — `{"name": "bash", "input": {"input":
  {"command": …}}}` — refused at the `schema` layer with `Additional properties
  are not allowed ('input' was unexpected)`
  (`/home/dev/aup/arc2/wt/A2-240c/.arcana/denied/`, turns 11, 25, 30, 42, 43,
  54, 65). Four of the seven wrapped the arguments as a JSON *string*, each
  with one surplus `}` inside it, so the existing `OpenAI`-style decode read
  them as "not JSON" and left the envelope standing.

  An arguments object whose ONLY key is `input`, `arguments`, `parameters` or
  `args` is now unwrapped, one level, and the inner value is decoded under the
  same surplus-closing-punctuation licence A2-248 wrote for the fence body
  (that helper moved to `tool_dialect`, where both readers can share one copy).
  The licence is a property of the shipped tool set, not a guess: no tool
  declares a property with one of those names and every tool schema sets
  `additionalProperties: false`, so such an object is invalid for *every* tool
  in the registry and cannot be a call to anything —
  `crates/cli/tests/run_envelope_premise.rs` pins that against the registry
  `assemble` actually builds, so a future tool with an `input` argument turns
  the licence red instead of widening it silently. Two keys, a non-object
  inner value, and a second level of wrapping all stay corrections
  (`driver_input_envelope.rs`).

  **Why this one is unwrapped and the quoted integer is not.** The runner
  already corrected this shape, naming the unexpected key and the missing one,
  seven times in one run, and the model wrote it again each time. The same
  pilot is the control: `"timeout_seconds": "400"` (turn 52) was refused once
  and the very next call carried an unquoted `300` (turn 53), and nothing
  quoted a number again in the remaining 16 turns. A quoted scalar is
  therefore still **refused, never coerced** — the schema is where the type
  contract lives — and what changed is only that the refusal now carries the
  corrected spelling (`— send it unquoted, as \`400\``) when the quoted text
  is unambiguously one scalar. `"soon"` gets no invented spelling.

- **`/dev/null` is the one path outside the workspace a command may name.**
  Turn 6 of the same pilot was refused on `2>/dev/null`
  (`.arcana/denied/0003-turn6.json`) — the only one of its five boundary
  refusals where the model had not tried to leave the workspace at all. A sink
  with no storage can neither carry workspace contents out nor bring anything
  in, which is the whole of the argument and also why the exception is one
  path and not a directory: `/dev/zero`, `/dev/urandom`, `/dev/stdout` and
  `/dev/sda` stay refused, `/dev/` is never matched as a prefix, the
  comparison is on the canonicalized path, and the path tools (`read`,
  `write`, `edit`, `grep`) are not covered at all. The system prompt names the
  exception from the constant, so prompt and policy cannot drift.

- **A call the permission cascade refused is now readable afterwards.** The
  `reason` built in `CapabilityExecutor::deny` reached the model and stopped
  there: `audit_decision` was handed the layer and nothing else, so the log
  said a call had been refused and never why, or with what arguments. Pilot
  A2-240b spent **21 of its 100 paid turns** on refused calls — 14 at the
  `schema` layer, 7 at `workspace_boundary`, the run's largest single sink of
  turns — and the post-mortem could count them but not read one
  (`/home/dev/aup/arc2/runs/A2-248/report.md` § 1 and D1).

  Two records now exist where there was one. The `decision` entry carries a
  `reason_hash`, so denials refused with the same sentence group in the log;
  and the call itself, with the sentence in full, is written to
  `.arcana/denied/NNNN-turnN.json` under the same counter discipline as
  `.arcana/rejected/`. The operator also gets a line per denial naming that
  file, where before a refused turn was simply a gap in the log.

  The reason is **hashed** in `audit.log` and kept whole only in the workspace
  file, and that split is the audit's own rule rather than a new one: the
  module refuses to persist raw inputs and error strings, and a refusal
  sentence is both — `schema` quotes the offending argument (`"…" is not of
  type "integer"`), `workspace_boundary` quotes the path. `audit.log` lives
  under `$XDG_STATE_HOME` and is never rotated; `.arcana/denied/` lives inside
  the workspace beside a `.arcana/rejected/` file that would have held the same
  text inside the whole reply anyway. `driver_denied_calls.rs` pins both halves,
  including the stated limit of the log-only view: a sentence that quotes the
  model's own text does not group, which is why the file has to exist.

- **`ARCANA_RUN_DONE` says what the model tried, not only what worked.**
  `tool_calls` counts executions and always has, so a refused call and a call
  never made are the same number: pilot A2-240b reported `"tool_calls":72` for
  a run that made **98** attempts, 21 of them refused. Read as intent, 72 says
  "the model barely used its tools"; the truth was "it used them constantly and
  often wrongly", and the two point at opposite fixes. `tool_calls_attempted`
  and `tool_calls_denied` are now reported beside it. `tool_calls` keeps its
  meaning exactly — evidence of work done — so nothing that reads it today
  changes.

### Changed
- **The destructive floor refuses a `git stash` that CHANGES the stack, not the
  word `git stash`.** Pilot A2-240d (arcana `5fc4684`) had finished its task —
  commit `6302742`, published as `arcanada-support#114` — and died on turn 62
  (`/home/dev/aup/arc2/wt/A2-240d/.arcana/denied/0006-turn62.json`) on

  ```text
  git format-patch … && git apply --stat … && git stash list && git log --oneline -1
  ```

  `git stash list` only READS the stack, and a floor refusal is terminal by
  design (`RECOVERABLE_DENIAL_LAYERS` excludes it), so a listing ended a
  completed run. The floor's entry named a git *command* where it meant a git
  *effect*.

  `git stash list` and `git stash show` are now permitted; every other form —
  a bare `git stash` (which IS `push`), and `push`, `pop`, `apply`, `drop`,
  `clear`, `branch`, `store`, `create` — stays refused. The rule is an
  **allow-list of the two read-only subcommands**, so a spelling git itself
  does not know is refused, not allowed by omission. Both were measured on git
  2.43.0 rather than read off the manual: `git stash list drop` exits 1 with
  `fatal: bad revision 'drop'` and drops nothing, `git stash list
  --exec='touch pwned'` is rejected with `fatal: unrecognized argument`, and
  neither form leaves the stack changed.

  Two holes closed on the way, **both ALLOWED before this change** and both
  measured (`/home/dev/aup/arc2/runs/A2-259/receipt-before-floor.txt`):
  `git --no-pager stash drop` and `git -C sub stash drop` ran, because the
  floor matched `git` and `stash` as adjacent words and a global option sits
  between them. The rule now also reads `stash` as git's subcommand past its
  global options, and strips quotes, which closes `git "stash" drop` as well.
  One hole stays open and is pinned as a test rather than left to be
  rediscovered: `git -c alias.l='stash drop' l` still drops (measured), because
  reading it means evaluating git's config — the module header has always said
  this check is a string heuristic and not a sandbox.

  The prompt carries the split, generated from the same constants the floor
  evaluates, and `crates/cli/tests/run_destructive_floor_prompt.rs` pins that
  what the prompt SAYS about each `git stash` form is what the floor DOES to
  it.

  **Terminality is unchanged, deliberately.** A floor refusal that became
  recoverable "when the command mutates nothing" would be decided by the
  floor's own string heuristic — so the run would continue exactly in the case
  where the heuristic was fooled — and would hand back precisely the refusals
  the classifier judged harmless, which is what a probe looks like. A command
  that mutates nothing must not reach the floor at all; that is a defect in the
  list, and it is fixed in the list. The argument is written out on
  `DestructiveCommandFloor`; changing terminality would need a DEC-level
  decision and nothing measured here argues for one.

- **A `..` refusal now says how to write the path instead.** The workspace
  check resolves `..` against the workspace ROOT, not against a `cd` earlier in
  the same command, so `cd sub && tar -x -C ../snap` is refused even though
  `../snap` lands inside the workspace. That stays: tracking a `cd` through a
  shell string has no single reading — subshells, `cd -`, `cd "$VAR"`, `;` vs
  `&&` vs `||` — and a boundary that guesses is not a boundary.

  What was missing is the correction, and its absence was measured: pilot
  A2-240d spent **three of its six denied calls** on this one shape (turns 15,
  16 and 54), the second immediately after the first and the third
  thirty-eight turns later. A boundary refusal IS handed back to the model, so
  it is a correction, and one that says only what is wrong leaves the model
  nothing to change but the spelling. The refusal and the system prompt now
  state, from one constant, that `..` is judged against the workspace root and
  that the path should be written from the root or absolutely under it.
  `crates/cli/tests/run_boundary_relative_path_recovery.rs` drives the pilot's
  shape both ways: with the new wording the model recovers on the next turn and
  the file is copied; with the pre-A2-259 wording the same model reaches for
  `..` again and the file is never copied.

- **`bash` gets a `HOME` per run instead of one fixed path in `/tmp`.**
  `BashTool` hard-coded `/tmp/arcana-runtime/bash`: the same directory for
  every run and every workspace on a host, in a world-writable parent. Two
  measured consequences — concurrent runs shared one `HOME`, and the directory
  on arcana-devs was `drwx------ dev dev` dated 2026-08-01, created by
  something outside any run (`/tmp` is `drwxrwxrwt`, and the sticky bit stops
  a local user deleting another's entry but not pre-creating a path that does
  not exist yet). `arcana run` now creates one owner-only directory per run
  under its own state directory, fail-closed, and gives it back at the end
  **non-recursively**, so a run that wrote to `~` keeps what it wrote.

  Stated because the card that asked for this assumed otherwise: an existing
  `HOME` is NOT what fixes `git config --global`. Measured side by side, git
  reports `unable to read config file '$HOME/.gitconfig': No such file or
  directory` identically whether the directory exists or not — that message is
  about the config file, which a credential-free lane has by design. What an
  existing `HOME` fixes is everything needing the directory itself: a bare
  `cd`, and any tool that writes under `~`.

- **The system prompt says this lane has no credentials.** `bash` runs under a
  constructed, credential-free environment and refuses caller-declared
  variables, so a private repository cannot be cloned, fetched or read. The
  pilot did not know that and spent many turns proving it; the prompt now
  states it, with the exact error a private clone will produce, so the absence
  is a fact rather than a fault to diagnose.

### Fixed
- **One reply can no longer erase the history of a run.** A tool result has
  been bounded when it enters the transcript since this loop was written
  (`carry_tool_result`, 8 000 units); a model **reply** was not.
  `prompt_budget::entry_ceiling` reached an oversized reply only from inside
  compaction — after the budget had already been blown, when the guard's
  remaining move was to fold earlier turns away. Measured on pilot A2-240b:
  between turn 36 and turn 37 the transcript grew 63 485 → 111 713 UTF-16 units
  (**+48 228 from a single reply, 54 % of the whole budget**) and compaction #1
  folded **28 earlier entries** into a summary. Thirty-six turns of history
  were spent on one turn of output — the mechanism a reader would have
  attributed to "the context window is too small".

  A reply is now cut at intake to `entry_ceiling` of the run's budget — the
  same number compaction would have imposed, applied before the damage instead
  of after it — head and tail kept, with an explicit marker in the middle
  stating how much went and why. Nothing else changes: the whole reply is read
  first, so the tool call the loop executes and the final answer the operator
  is handed are both taken from the complete text.
  (`crates/core/tests/driver_reply_intake_cap.rs`.)

- **Waiting for an answer already bought no longer costs a prompt build per
  poll.** A2-241 made the loop wait out a turn Model Connector is still
  computing, and left every poll re-entering the whole of `step()`: the prompt
  was re-serialized from the history, a block was appended to
  `--save-transcript` and a `dispatch` record to `audit.log` — for a request
  that is not being re-asked but collected. Measured on the A2-240 fixture with
  a turn of 80 000 characters: **13 prompt builds and 1 040 782 bytes of
  transcript for one waited turn**, and the live pilot's turn was larger still.

  The wait now owns its re-dispatches. It keeps the exact bytes the dispatch
  built and re-sends them under the same `Idempotency-Key`, so one waited turn
  is one prompt build, one transcript block and one `dispatch` record whatever
  the poll count. Everything an operator can observe is unchanged — the same
  deadline, the same key, the same poll schedule, the same two verdict lines,
  and `RunOutput::turns` still counts every poll. Re-sending what was sent is
  also the stricter reading of the key: a replay only holds while the payload is
  identical, and a rebuilt prompt is only *probably* identical.

  `crates/core/tests/driver_idempotent_turn.rs` counts the builds where they
  land — `===== dispatch` blocks in the transcript and `dispatch` events in the
  audit log — and re-introducing the per-poll build turns it red with exactly
  the numbers above (A2-245).

- **A complete tool call followed by one surplus `}` is that call, not
  garbage.** Turn 62 of pilot A2-240b opened this runner's own
  ```` ```tool_call ```` fence and wrote a whole `write` call — right tool,
  right path, the entire file content, in the A2-219 flat form the parser
  already accepts — and then one more `}`. `serde_json::from_str` refuses
  trailing data, so the reply was classified "not valid JSON", nothing ran, and
  one of that run's hundred turns went on a correction for a character that
  carried no information (the reply as the model sent it is now
  `crates/core/tests/fixtures/a2-248-surplus-brace-reply.txt`, sha256
  `252d444b5fe0dd…`; run log `/home/dev/aup/arc2/runs/A2-240b/log`).

  A body that does not parse whole now gets exactly one more reading, and it is
  a **truncation, never an edit**: the JSON value at the front of the block is
  used only when everything after it is `}`, `]` or whitespace. That licence is
  a property of the text rather than a guess about the model — surplus closing
  punctuation cannot name a tool, add an argument or change a value, so
  dropping it leaves exactly one reading and the dispatch is still only what
  was written. Everything that *could* change what runs stays a correction, and
  `crates/core/tests/driver_surplus_closer.rs` is what keeps it that way: a
  second JSON object after the first is a second call and is refused rather
  than silently dropped, and a trailing comma (`{"name":"bash",}`) never
  reaches the rule at all because it fails *inside* the braces — a parser that
  truncates a suffix is reading, a parser that edits between the braces is
  guessing at intent.

  The correction handed back for a body that still does not parse now carries
  serde's own message, so it names the line and column of the fault instead of
  only "not valid JSON".

### Tests
- **Every waiting test now runs under a ceiling, so an unbounded wait fails in
  seconds instead of running until the CI job is killed.** A mutation of the
  A2-241 fix that restarts the in-flight clock on every same-key re-dispatch —
  an unbounded wait, the precise defect the deadline exists to prevent — turned
  no test red: `driver_idempotent_turn` ran for over thirty minutes and had to
  be killed, because on a paused clock an unbounded wait is an infinitely fast
  infinite loop. Every run in that file now goes through a
  `tokio::time::timeout` at twenty-five times the deadline the connector's own
  stated dispatch budget implies, and the failure message names that deadline.
  The same mutant is now two red tests in 0.05 s (A2-245).

- **Exactly which permission denials may be retried is now pinned, name by
  name.** `recoverable_denial_layers_are_exactly_pinned`
  (`crates/core/src/agent_loop.rs`) writes down every layer the cascade or the
  executor can hand the loop as a denial — the site that emits it and whether
  folding it back to the model is intended — and compares that table against
  `RECOVERABLE_DENIAL_LAYERS`. Before it, adding `hook_bridge` or `rule` to the
  recoverable set failed no test (measured on `92a4a7a`), so an operator-owned
  refusal could have become retryable in silence. With it, on `c24cd49`, adding
  `destructive_command_floor`, `hook_bridge` or `rule`, or removing `schema`,
  each fails this test. Test-only: no runtime behaviour changes. Written by the
  `arcana` DeepSeek-lane pilot (A2-204c5); CHANGELOG entry drafted by A2-231.

### Fixed
- **A turn the Model Connector is still computing is waited out, not
  abandoned.** Pilot A2-240 sent 144k input tokens on turn 24; Cloudflare cut
  the socket at its ~100 s origin timeout with HTTP 524 while the Connector
  went on producing the answer. `arcana` did the expensive part right — it
  re-dispatched under the same `Idempotency-Key`, so nothing was charged twice
  — and then threw the answer away: `ConnectorFatal … after 6 attempt(s) over
  41s`, on a turn that needed more than a hundred.

  Two bounds were wrong, and both are fixed. The patient in-flight wait **shared
  its counter with the edge-retry schedule**, so the single 524 spent "1 of 5"
  and the wait for the answer that 524 interrupted started at "2 of 5"; it now
  has its own counter, and the edge budget is untouched by it. And the wait was
  **a count of sleeps** (five, ≤60 s nominal, shortened to 41 s by jitter) with
  no relation to how long the request may legitimately run; it is now a
  deadline — the connector's own per-dispatch budget
  (`ModelConnector::upstream_dispatch_budget`, for the real client the
  `ExecuteRequest.timeout` we send widened by Model Connector's own attempts and
  queue) plus a 30 s settle margin, measured from the moment the request FIRST
  left this client. Inside it the loop polls on a capped 2/4/8/15 s backoff.

  Waiting is also the cheap side, and that is read off the server rather than
  assumed: an intent stays `held` — and therefore replayable rather than
  re-charged — for 30 minutes (`BILLING_HOLD_TTL_MS`, `src/billing/intent.ts:36`
  on model-connector `3911773`), swept hourly, so every wait this schedule can
  produce is far inside the window in which a retry is free.

  A poll no longer spends one of the run's `max_turns` either: it asks no
  question, Model Connector charges nothing for the 409, and counting them would
  have had a wait span the whole default budget of 24 attempts — trading
  `ConnectorFatal` for `MaxTurns` on the same abandoned, already-paid-for
  answer. `RunOutput::turns` still reports every attempt, polls included. And
  the terminal verdict now names both budgets, so an operator cannot read it as
  "raise the retry limit" when it is the clock that ran out.
  `crates/core/tests/driver_idempotent_turn.rs` reproduces A2-240 on a virtual
  clock: 100 s of upstream work, one provider call, the stored answer replayed.

- **A re-dispatched turn is no longer paid for twice.** A2-230 gave a turn cut
  off by the network edge up to five re-dispatches and, in the same breath,
  measured what each of them cost: Model Connector settles the charge in the
  same transaction as the request row *before* the response reaches the socket,
  so a request the edge cut may already have been executed and billed — and
  `arcana` sent no `Idempotency-Key`, so every re-dispatch was a second provider
  call and a second charge. Raising the budget from two to five raised the worst
  case with it.

  Every dispatch now carries `Idempotency-Key: arcana.<run-uuid>.<turn>` —
  stable across all re-dispatches of one turn, fresh on the next turn. A request
  that was executed and billed comes back as a stored replay: one provider call
  and one ledger row however many times the client re-POSTs. Measured against a
  stub implementing Model Connector's own intent-store contract
  (`crates/connectors/tests/idempotent_turn_retry.rs`): an edge-cut turn that
  cost two provider calls before costs one now.

  The key is bound to the payload, not assumed stable with it: the request's
  fingerprint is recorded when the key is minted, and a payload that changes
  under a key gets a fresh one rather than the server's `idempotency_key_reused`
  refusal. Model Connector's other two answers are handled by name —
  `idempotency_conflict` (the first attempt is still running upstream) is waited
  out on the patient schedule under the *same* key, never a new one, because a
  new key is what would dispatch and charge a second time;
  `idempotency_replay_unavailable` ends the run and says the turn was charged
  exactly once rather than implying it never ran. The retry line states the
  outcome instead of the risk: a cut re-dispatch "is replayed rather than
  charged again".
- **The model is told which commands the destructive floor refuses.** Pilot
  A2-231 (2026-09-23) ran 78 turns, 62 tool calls and $0.27, then asked for
  `rm -rf` on its own scratch directory; the floor refused, correctly, and the
  run ended there. The model was not evading the floor — `rm -r` without `-f` is
  permitted and would have done exactly what it wanted — it had never been told.
  The system prompt's only word on the subject named no command and offered no
  alternative.

  The prompt now carries the floor's closed lists in full, generated from the
  same constants the floor evaluates, plus the permitted alternatives and the
  fact that a floor refusal ends the run with no second attempt. A command added
  to the floor therefore cannot start refusing runs silently, and
  `crates/cli/tests/run_destructive_floor_prompt.rs` asserts that what the
  prompt *states* about a command equals what the floor *does* to it.
- **Three 502s from the edge no longer throw away a finished run.** Measured on
  pilot A2-204c5 (2026-09-23, `arcana` c24cd49): 94 turns, 61 tool calls, the
  test written and four mutants run — ended `ConnectorFatal` at $0.34 when three
  consecutive `HTTP 502: upstream returned a non-contract error body (16 bytes):
  error code: 502` arrived from `connector.arcanada.ai`. The retry policy was
  two re-dispatches two seconds apart, so the run spent about four seconds
  finding out whether a Cloudflare edge would come back.

  A gateway status (502/503/504/520–524) whose body is neither the
  connector-response envelope nor a `NestJS` envelope is now its own class: it
  is the edge speaking, not Model Connector, and it gets **five** re-dispatches
  on a bounded exponential schedule with jitter — 2, 4, 8, 16, 30 s, each
  shortened by up to half at random, so at worst 60 s of added waiting.
  Everything else transient keeps the conservative two, because an envelope
  Model Connector authored already has Model Connector's own server-side
  attempts behind it. A single turn may spend at most 120 s asleep between
  re-dispatches whatever the class, so an upstream-named `retryAfter` cannot
  park an unattended run.

  The retry line now warns when a re-dispatch may be paid for twice: Model
  Connector settles the charge in the same transaction as the request row
  *before* the response is written to the socket
  (`src/connectors/connectors.service.ts`), and `arcana` sends no
  `Idempotency-Key`, so a request the edge cut may already have been executed
  and billed. A failure Model Connector itself reported carries no such warning
  — there the provider call failed, the hold was released and nothing was
  charged.
- **`ConnectorFatal` says what killed the run.** The same pilot left
  `"error": null` in its done-marker and `the Model Connector could not complete
  the request` on stderr. Both now carry the status, the attempts made this
  turn, the elapsed time and why the loop stopped — `HTTP 502 after 6
  attempt(s) over 63s — the 5 re-dispatch(es) allowed for a transient gateway
  failure in front of the Model Connector are spent: …`. A2-225 did this for
  permission denials; this is the connector's half.
- **`MAX_DENIALS_PER_DISTINCT_CALL` is now the rule it claimed to be.** It was
  documented as the bound on how often one distinct call may be refused at a
  correctable layer, while the code carried the rule in a `HashSet::insert` —
  which can only ever mean "one". Editing the constant changed no behaviour and
  broke no test. `RunState` now counts refusals per distinct call and checks
  them against it. The dead `consecutive_denials` counter beside it, written
  every refusal and read nowhere, is gone.
- **A long run no longer loses its history to compaction.** Measured on pilot
  run A2-204c4 (2026-09-23, audit `~/.local/state/arcana/run/audit.log`): the
  request grew from 78 234 to 179 037 characters in one turn, and the guard
  answered by folding **73** earlier entries into a summary and handing the
  model a 7 098-character request — 8% of its 90 000-character budget, with
  every fact twenty tool calls had gathered gone.

  Two causes, both fixed. A tool result is bounded when it enters the
  transcript; a **model reply is not**, and one of ~100 000 characters is what
  overflowed the budget in a single turn. Folding is strictly oldest-first, so
  reaching that one entry meant destroying everything in front of it, and the
  only other stop was "two entries left". The guard now shortens an entry that
  is itself more than a quarter of the budget (head and tail kept, the gap
  stated), every stage cuts only what the arithmetic asks for and stops at a
  stated target of three quarters of the budget, and the newest six entries are
  kept out of the summary unless the transcript does not otherwise fit at all.
  `CompactionReport` carries the target and a separate count of oversized
  entries, and the operator's line states both. On the pilot's shape:
  174 395 → 66 199 characters against a target of 67 500, 24 entries folded
  instead of 73.
- **A schema refusal no longer ends a run, and whatever does ends it says so.**
  The same pilot spent its last three turns on one `read` call the schema layer
  refused (`input_hash fe133faf0121151c`), then ended `PermissionDenied`,
  `completed: false`, `"error": null`. Two reasons it could not recover: the
  validation error it was handed was the message alone — `"one" is not of type
  "integer"` — with the offending field on a separate `jsonschema` field nobody
  read, and a flat cap of three *consecutive* refusals killed the run whether or
  not the refusals were related.

  Validation errors now name the instance path (`at \`/value\`: …`), which
  discloses nothing the model's own tool list does not already carry. The cap is
  replaced by the repeat: a call refused at a correctable layer and sent again
  **unchanged** ends the run; distinct correctable mistakes keep being answered,
  bounded by `--max-turns` and the cost cap like everything else a run spends.
  Policy layers (destructive-command floor, operator rules, hooks) stay terminal
  on the first refusal, as before. `RunOutput::terminal_detail` carries which
  layer refused, which tool and the error, and it is printed on the run's last
  stderr line and in the done-marker's `error` field.

### Added
- **A reply the runner refuses to act on is kept, verbatim.** Measured
  2026-09-23 (`runs/A2-204c3/log`, ARAS `92a4a7a`): a live run reached turn 34
  with 21 executed tool calls and one compaction, then died
  `UnsupportedToolCallFormat` on two replies that "named `edit` but carried no
  arguments" — the call that was about to write the patch. What the model had
  actually sent was unrecoverable: the audit log keeps `input_hash` /
  `output_hash` and no text, and no transcript is written to disk, so the
  defect could be reported and not diagnosed.

  Every rejected reply — an unreadable dialect, or one the output limit cut off
  mid-block — is now written to `.arcana/rejected/NNNN-turnT.txt` inside the
  working directory, byte for byte with nothing prepended, and the operator's
  line names the file. A failed write is not fatal: the run was already going
  to correct or end on that reply, and turning a full disk into a second,
  different failure would hide the first. A cut-off reply is deliberately kept
  out of the transcript, so for that case the file is the only copy there is.
- **Every dispatch records the size of its request in the audit log.** Sizes,
  never text: `{"kind":"dispatch","fields":{"turn","model","prompt_utf16",
  "system_prompt_utf16"}}`, written *before* the dispatch and fail-closed like
  every other append, so a turn whose size could not be recorded is not a turn
  the operator is charged for. An absent system prompt is `null`, not `0` — an
  absent field and an empty one are different requests. Without this, a run
  that died against the connector's 100 000-unit field limit left nothing to
  reconstruct from and the post-mortem had to estimate the split from a token
  count.
- **Arguments written as siblings of `name` are the call's arguments.**
  Measured 2026-09-23 on `deepseek-flash`: the model opened this runner's own
  fence and wrote `{"name": "bash", "command": "git clone …",
  "timeout_seconds": 600}` — right fence, right tool, right arguments, no
  wrapper object around them — and the reply became a correction because
  `arguments_of` looks only for a key that holds the arguments. The saved reply
  is the test fixture (`crates/core/tests/fixtures/a2-219-flat-arguments-reply.txt`).

  `tool_dialect::flat_arguments` reads the remaining keys as the input object,
  and `declared_call_arguments` prefers a wrapper key when there is one. It
  applies only inside markup that exists for no other purpose — this runner's
  fence and the `<tool_call>` wrapper — because there the model has already
  said the object is a call. A bare JSON object in prose is untouched:
  `{"name": "Alice", "age": 30}` is a plausible answer, and reading it as a
  call to `Alice` would charge a correction turn to a model that answered the
  question. An object with nothing but a `name` still has no arguments and is
  still told so.
- **`arcana run --tool-result-budget <units>`** sets the ceiling on one tool
  result's contribution to the transcript (`240`..=`--context-budget`; default
  unchanged at 8 000). Refused before anything is spent when it is below the
  elision marker itself — every oversized result would be replaced by the
  marker and nothing else — or above the run's transcript ceiling, where it
  cannot bind. It exists because no ordinary command crosses 8 000 units
  cheaply, so the elision-and-spill path had offline evidence and nothing else;
  at `--tool-result-budget 400` an 18 893-byte `cat` was elided in the
  transcript, written whole to `.arcana/tool-output/0001-bash.txt`, and the
  model answered from the spill file.
- **`arcana run --save-transcript <path>`** appends the exact request of every
  dispatch to a file. Off unless asked for: a transcript is the whole
  conversation in clear text, so keeping one is a decision about the operator's
  disk. Appended per dispatch rather than written once at the end, because a
  run that compacts does not carry its early turns into the last request — the
  turns folded away are precisely the ones a post-mortem cannot otherwise see.
  The system prompt is written once. A path that cannot be appended to is
  refused before the run starts, and a write that fails mid-run says so once
  and the run continues.
- **A tool call wrapped in `<tool_call>` XML no longer ends the run as an
  answer.** Measured 2026-09-23 on `deepseek-flash` through Model Connector
  (`runs/A2-216/live.log:9-12`, ARAS `92a4a7a`): the last reply of a real task
  was a complete, correct call —
  `<tool_call>{"name":"bash","input":{"command":…}}</tool_call>` — in the
  wrapper the Hermes/Qwen function-calling template teaches (*"return a json
  object with function name and arguments within `<tool_call></tool_call>` XML
  tags"*, `Qwen/Qwen2.5-7B-Instruct` `tokenizer_config.json` → `chat_template`).
  Nothing in `arcana_core::tool_dialect` knew those tags, the loop read the
  whole thing as prose, and the run printed `ARCANA_RUN_DONE
  {"completed":true,"reason":"Completed"}` with that text delivered as the
  operator's answer, the command never run.

  A closed `<tool_call>` wrapper whose body is a JSON object naming a tool is
  now translated and dispatched, like `<invoke>` markup and through the same
  permission cascade; the argument key may be the template's `arguments` or
  this runner's `input`. Anything that looks like the wrapper but cannot be
  read as a call — unclosed, or wrapped around an apology — is a
  `MalformedToolCall` that costs the model one correction naming the format
  that works, never a `Completed`. A `` `<tool_call>` `` written inside
  backticks stays prose: a model explaining the encoding has answered, and an
  answer must not cost a turn.
- **`arcana run --context-budget <units>`** sets the ceiling the serialized
  transcript is held under (1..=100000; default unchanged at 90 000), and the
  run prints the number it is working to. Two things needed it: a model whose
  own context window is below Model Connector's 100 000-unit field limit had no
  way to be given the lower ceiling, and the compaction path shipped in the
  previous entry could not be exercised by a live run at all — no ordinary task
  grows a transcript past 90 000 units cheaply, so its only evidence was
  offline. A value above the connector's limit is refused before the run starts
  rather than after it has paid for every turn up to the `HTTP 400`.
- **A long run no longer dies when its transcript outgrows the request
  contract.** Model Connector's `/execute` caps `prompt` and `systemPrompt` at
  100 000 UTF-16 code units *each*
  (`model-connector src/connectors/dto/execute.dto.ts:53,55`); the agent loop
  had a context guard whose default ceiling was 1 000 000 and whose measure was
  `String::len` — ten times the wall, counted in the wrong unit. Measured
  2026-09-23: a run that had executed five tool calls and cloned a repository
  died at turn 10 on `HTTP 400 {"message":"Validation failed","errors":
  ["prompt: Too big: expected string to have <=100000 characters"]}`, reported
  as `ConnectorFatal`.

  Requests now fit by construction. The new `arcana_core::prompt_budget` writes
  the contract down once, in UTF-16 code units, with the live probes that
  established it (a byte count is wrong by a factor of three on Russian or
  Chinese text, a `char` count by a factor of two on emoji — both in the
  direction that sends an over-limit request). Each tool result is bounded as
  it enters the transcript, head and tail, with a marker stating how many
  characters were removed; the complete output is written to
  `.arcana/tool-output/` inside the working directory and the marker names the
  file, so the model re-reads the part it needs instead of re-running the
  command. When the transcript still overflows, the oldest entries — never the
  task framing, never the turn being answered — are folded into one
  `[compacted]` line that states how many entries, how many model replies and
  which tool calls it replaced. The run prints what it did (`arcana:
  transcript compacted …`) and the done-marker carries a new `compactions`
  count: a model answering from a summary of its own history is not something a
  log should hide.

  A request that still cannot be made to fit is the new terminal verdict
  `RequestTooLarge`, which names the limit, and an upstream size refusal
  (`400 … Too big`, `413 Request body is too large`) maps to it as well rather
  than being retried with the same oversized body or reported as a failure of
  a connector that kept its contract. `RequestTooLarge` is deliberately
  distinct from `ContextWindowExhausted`: that one is about the model's window
  and is answered by a bigger model, this one is about the wire and would not
  be.

- **The TCP+TLS connect budget is separately configurable**
  (`ARCANA_MC_CONNECT_TIMEOUT_SECS`, `1`..`60` s, default `10`), and `arcana
  run` now prints it beside the model budget. The default is measured, not
  assumed: five probes of `connector.arcanada.ai` from a fleet host on
  2026-09-23 connected in 10.3–11.4 ms of TCP and 31.8–33.5 ms through TLS, so
  ten seconds is ~300× the healthy case and raising it would only lengthen the
  pause before the retry that actually fixes the failure. A connect timeout was
  already transient and re-dispatched — the live run of 2026-09-23 lost its
  first dispatch that way and its second succeeded — and a regression test now
  pins that classification, with a refused connection as its negative control.

- **A reply cut off by the output limit is no longer read as "the model did
  nothing."** A ```` ```tool_call ```` block whose closing fence never arrived
  used to fall through `interpret`'s fail-closed arm to `Final`, so the loop
  concluded the model had answered in prose: measured 2026-09-23, DeepSeek was
  asked for a 3000-word file, emitted ~9148 output tokens of `tool_call`, was
  cut off, and the run ended on `NoAction` having written nothing and charged
  $0.040.

  Truncation is now its own classification (`AssistantAction::Truncated`) and
  its own outcome. The half-written call is **never executed**, however
  complete the JSON inside it happens to look — a call the model did not finish
  emitting is not a call it asked for. The fragment is discarded rather than
  fed back as something the model said, and the turn is re-dispatched once
  (`ContinueReason::MaxOutputTokensRecovery`, until now an inert variant
  reserved for exactly this event) carrying an instruction to do the work in
  smaller pieces. The re-dispatch is an ordinary attempt: it consumes a turn
  from `--max-turns` and is charged against `--max-cost-usd`. A second cut-off
  reply in a row ends the run on the new terminal verdict
  `ResponseTruncated` — "the model's reply was cut off by its output limit …
  ask for the work in smaller steps, or choose a model with a larger output
  limit" — which is the opposite advice to `NoAction`'s and was previously
  unavailable because the two were the same verdict. The counter resets on any
  reply that parses, so a long run may legitimately hit the limit more than
  once.

  Detection is local, and deliberately so: Model Connector's response contract
  carries no finish/stop reason to read instead
  (`src/connectors/interfaces/connector.interface.ts:42` on `main` 3911773),
  and its DeepSeek adapter does not even decode the provider's
  `choices[].finish_reason` (`src/connectors/deepseek/deepseek.connector.ts:4`,
  `:82`). An open fence is the only evidence ARAS is given. A reply truncated
  before it opened a fence at all still looks like an ordinary short answer and
  is not detected — that limit needs the upstream field.
- **A model that asks for a tool in its own markup is no longer told the job is
  done.** The driver executes one encoding — a fenced ```` ```tool_call ````
  block — and used to fail closed to "this was the final answer" on everything
  else, including on replies that were plainly a request to run a command.
  Measured 2026-09-23 on `deepseek-v4-flash`, turn one of a real task arrived as
  DeepSeek's native markup (`<｜｜DSML｜｜ invoke name="bash">…`), was read as
  prose, and the run printed `{"completed":true,"reason":"Completed"}` having
  executed nothing.

  `invoke` markup — DeepSeek's `DSML` form and the sentinel-less
  `<invoke>`/`<parameter>` form — is now translated into a real call and
  executed, through the full permission cascade like any other. A recognisable
  attempt we will *not* run unseen — a `tool_call` block whose body is not
  usable JSON, a bare OpenAI-shaped `{"name": …, "arguments": …}` object — costs
  the model exactly one correction restating the encoding that works, and then
  ends the run on the new `TerminalReason::UnsupportedToolCallFormat`
  (`"completed":false`, exit `1`). Nothing on this path is ever dispatched
  unchecked, and a call that executes clears the streak.

  Arguments now reach the tool under any of `input`, `arguments`, `parameters`
  or `args`, including OpenAI's JSON-encoded-string form. The reader was
  `value.get("input").cloned().unwrap_or(Value::Null)`, so a call spelt any
  other way was dispatched with **no arguments at all** — a `bash` with no
  command — and refused for a mistake the model had not made. That is the
  `blake3("null")` input hash behind the A2-204 live denial; it cannot recur.
- **A slow model turn no longer ends the run.** `arcana run --request-timeout
  <secs>` (or `ARCANA_MC_TIMEOUT_SECS`, default `120`) sets how long one model
  turn may take, and the number is used twice: it travels with the request as
  the dispatch's own budget, and it sizes how long the client waits — the
  budget plus up to 60 s of upstream queue, a second server-side attempt and
  its backoff, 310 s at the default. The client used to wait a fixed 120 s
  while the server's own worst case was already about 121 s, so a healthy but
  slow turn came back as `connector dispatch failed: timed out after 120s` and
  the whole run ended `ConnectorFatal` — measured on a run that lost an hour of
  work on turn 3. Sending the budget matters on its own: with no `timeout`
  field the Model Connector applies the connector's default, 30 s for most API
  connectors, which no amount of client patience can widen.

  A connector error that says nothing about the request — a timeout, a gateway
  status, or an envelope the upstream itself marked `retryable` — is now
  re-dispatched up to twice (`ContinueReason::ConnectorRetry`) instead of
  ending the run. Each re-dispatch is an ordinary attempt: it consumes a turn
  from `--max-turns` and is charged against `--max-cost-usd`, so an upstream
  that is simply down cannot spend the whole budget. A missing key, an unknown
  connector id or a policy refusal is not retried — it would fail identically
  forever, and retrying only delays the message the operator needs.

  One ceiling is not ours to move and is documented rather than papered over:
  the public Model Connector origin is fronted by an edge proxy that cuts any
  single `/execute` at about 125 s (measured 2026-09-23 — three calls cut at
  125.1 s, 125.2 s, 125.3 s with HTTP 524). A budget above 120 s helps only a
  deployment reached without that proxy in the path.
- **`arcana run` — one task, unattended, with real tools.** `arcana run --cwd
  DIR --prompt-stdin` drives a single task to completion in a working
  directory: the built-in `read`, `write`, `edit`, `grep` and `bash` tools are
  registered and rooted at that directory, and a workspace policy replaces the
  interactive prompt — auto-allow inside the directory, refuse paths outside
  it (compared after canonicalization, so symlinks and `..` are covered),
  refuse a closed list of destructive commands. The last line of stdout is
  always `ARCANA_RUN_DONE <json>`, printed even when the run never started, so
  a caller never has to interpret a missing marker. Exit `0` on completion,
  `130` on interrupt, `1` otherwise. Always live: there is no offline mode,
  because replaying the canned offline turns against a real working directory
  would produce a receipt for work that never happened.

  The command also carries the reason a task could previously print a shell
  command and change nothing: the driver recognises exactly one tool-call
  encoding, and no surface had ever told a model so. `run` states the wire
  format and the tool catalogue in its system prompt, built from the tools
  that are actually registered.

  The marker carries `tool_calls` — the number of tool calls the executor
  actually carried out — and a run that executed none of them is `NoAction`:
  `"completed":false`, exit `1`. Told in plain language to create a file, a
  model answered `The file has been created successfully.` in a single turn,
  called nothing, created nothing, and the run reported `"completed":true` and
  exited `0`. Judging a run by its own sentence was the last way this command
  could still hand a runner a receipt for work nobody did.
- **The loop asks once for an action.** When a run that requires an action gets
  a first answer with no tool call, the driver tells the model that nothing was
  executed and asks it to act, buying exactly one more dispatch
  (`ContinueReason::NoActionRetry`). Off by default — an interactive turn may
  legitimately be a question answered in prose — and switched on by
  `DriverConfig::require_action`, which `arcana run` sets.

  Measured, 10 live runs per arm, same prompt and same model
  (`deepseek-v4-flash`), judged by the file on disk: **without** the nudge 4/10
  runs produced the file, and all 6 that did not reported `"completed":false`
  with `"tool_calls":0` and exit `1` — honest, but a 40% success rate.
  **With** it, 10/10 produced the file; the nudge fired in 5 of those 10 and
  the model acted every time. The verdict alone stops the lie; the nudge is
  what makes the command usable.
- **Explicit workspace roots for the built-in tools.** `ReadTool`,
  `WriteTool` and `EditTool` gain `with_root`, `GrepTool` gains `with_root`
  and `BashTool` gains `in_directory`. Each still defaults to the process
  working directory, so existing behaviour is unchanged; what is new is that
  a caller can say where a tool's reach ends instead of depending on global
  mutable state shared with every other task in the process.
- **`arcana demo --first-dispatch-prompt-stdin`.** The exact prompt for a
  measured live first dispatch can now be handed to the demo on stdin instead
  of argv, so a baseline or compiled corpus prompt never appears in a process
  listing. The prompt is carried through the driver as a bounded, redacted
  type, applied only to the first `ModelConnector::execute` request (later
  tool-loop turns keep the ordinary history-derived prompt), and redacted again
  at the downstream request `Debug` boundary. It is rejected before any
  connector I/O when it arrives without the paired first-dispatch measurement
  metadata, when it exceeds the 1 MiB UTF-8 byte cap, or when it exceeds Model
  Connector's own 100,000 UTF-16-code-unit limit.

### Changed
- **A `--live` that cannot go live now fails instead of going offline.**
  `demo --live` and the interactive `--live` session used to print `(live
  requested but unavailable: ...; using offline demo)`, replay the canned
  offline script, and exit `0` — and, with a key present, print a dollar
  figure for a dispatch that never left the machine. A caller reading the exit
  code learned that a live run had succeeded; every part of that was false.
  Both now exit non-zero with the cause on stderr, having run and charged
  nothing. The production base-URL pin that refuses an unapproved Model
  Connector origin is unchanged: it is a deliberate control, and the fix was
  to report that it refused.
- **sha2 0.11.** Upgraded from 0.10.9. `Sha256::digest` now returns
  `digest::Array`, which no longer implements `LowerHex`; hex-formatting
  call sites format the digest bytes manually instead of via `{:x}`.
- **xdg 3.0.** Upgraded from 2.5.2. `BaseDirectories::with_prefix` is now
  infallible, and `get_state_home`/`get_config_file` return `Option<PathBuf>`
  instead of an unconditional `PathBuf`. Updated every call site;
  `RuleLayer::xdg_user_path()` now returns `Option<PathBuf>` directly instead
  of `Result<PathBuf, xdg::BaseDirectoriesError>`, matching how its three
  callers already used it (`.ok()`).
- **rmcp 3.2.** Upgraded from 2.2.0. `model::Meta` was renamed to
  `model::MetaObject`, and `ServerHandler::call_tool` now returns
  `CallToolResponse` (an enum covering complete/task/input-required outcomes)
  instead of `CallToolResult` directly. Converted at the trait boundary via
  the provided `From<CallToolResult>` impl; internal helpers still return
  `CallToolResult` unchanged.

### Fixed
- **One malformed tool call no longer ends the whole `arcana run`.** A denial
  from the permission cascade was terminal at every layer, including `schema`
  — which means only that the arguments did not match the tool's published
  JSON schema. Measured with `deepseek-flash`: turn 1 called `bash`, the
  arguments failed the schema, and the run ended `PermissionDenied` with
  `tool_calls: 0` and exit `1`. The model was never told what was wrong, so it
  could not correct itself, and one typo cost the whole task.

  A denial at `schema`, `registry` or `workspace_boundary` is now handed back
  to the model as a tool result naming the violated constraint, so it can send
  a corrected call — the same rule the loop already applied to dispatch
  errors. Nothing executed: `tool_calls` is not incremented and the `Denied`
  audit record is written exactly as before.

  Refusals that are policy rather than a typo stay terminal: the destructive
  command floor, operator hooks, the operator's `permissions.toml`, the
  `ARCANA_PERMISSION_AUTO` directive and the fail-closed cascade tail. Layers
  not on the recoverable list are terminal by default, so a layer added later
  cannot become recoverable by omission. Telling a model which word is on the
  refusal list invites a hunt for one that is not; telling it a path is
  outside its own working directory does not.

  Bounded by `MAX_CONSECUTIVE_DENIALS = 3` in a row, reset by any tool call
  that actually executes — so it stops a model hammering one wall without
  punishing a long run for occasional typos. Only executed work clears that
  streak: a connector re-dispatch in the middle of it (the `ConnectorRetry`
  above) does not, or a model that cannot write a valid call could keep a run
  alive indefinitely by being unlucky with the network in between. The reverse
  is deliberately not symmetric — any reply resets the retry budget, including
  one the cascade then refused, because a refused call is still proof the
  upstream is answering. The two counters are independent, and each direction
  is pinned by a test that was watched to fail against the opposite behaviour.

  The workspace policy's deny-only half is now two layers,
  `DestructiveCommandFloor` ahead of `WorkspaceBoundary`, so the loop can tell
  the two refusals apart. Both are deny-or-defer over the same assessment, so
  the gate-set is unchanged.
- **`arcana run --max-turns N` above 100 died on its first dispatch.** The
  run-level connector-attempt cap was forwarded as the per-request Model
  Connector field `maxTurns`, which that service validates as
  `1..=100` and hands to CLI connectors (`claude-code --max-turns`) for a
  single invocation. The two are different quantities, so a run budget of 120
  was rejected as a per-request one: HTTP 400, zero tokens, before the model
  was ever reached. The loop cap is no longer sent on the wire at all — no
  run-level number is a correct per-request value, the upstream work of one
  request stays bounded by `maxBudgetUsd`, and a caller who really wants to cap
  an upstream agentic CLI still sets `max_turns` on its own `model_call`
  request.
- **An upstream error body that does not match the contract now says why.**
  `upstream returned a non-contract error body (91 bytes)` was a byte count
  where the diagnosis was: the body was the validation message naming the
  offending field. A bounded excerpt of it is now appended — at most 200 bytes,
  truncated on a character boundary, control characters stripped so an upstream
  string cannot forge a log line or repaint the terminal. Body only: never a
  response header, never the API key. This deliberately narrows the earlier
  rule that such a body is never echoed at all; the text stays labelled as
  non-contract, and the length is still reported in full.
- **Path-traversal gap in the filesystem tools' path guard.** When neither a
  path nor its parent existed, `path_guard::resolve` returned the path with
  its `..` components intact, so any downstream "is this inside my directory?"
  test answered yes for `<root>/missing/../../escaped.txt`. With
  `create_parent_dirs` set, that is a write one level above the directory the
  caller believed it had confined. Unresolvable paths are now normalized
  lexically before they are returned.

## [0.2.0] - unreleased

Publication deferred on 2026-09-03: the agent is being substantially reworked
-- resolver, watcher, and the surrounding architecture -- before anything is
published. The notes below describe what is on `main` and are kept together
under the version they belong to; they are not a shipped release. `v0.1.0`
remains the latest tag. This heading takes a date when the tag is cut.


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
- Published doc comments no longer cite private tracker identifiers. 113 of them
  across 21 source files carried ids that resolve only inside a tracker no reader
  of the published crate can reach; in the crate tarball and on docs.rs each was
  a reference to nowhere. Plain `//` comments, tests, and three ids inside string
  literals are untouched -- the last of those are a fixture, an eval label and an
  `incident:` field whose value is part of a contract. Where an id was the subject
  of its sentence the sentence was rewritten rather than truncated; a dangling
  verb or a bare section reference is the same dead end with fewer characters.
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
