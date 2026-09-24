//! A2-234: the four answers Model Connector gives a repeated
//! `Idempotency-Key`, and what the loop does with each.
//!
//! `src/billing/billing.service.ts`, `resolveReplay`, gives "four honest
//! answers, and deliberately no fifth that guesses". Two of them are the happy
//! path and are measured end-to-end over HTTP in
//! `crates/connectors/tests/idempotent_turn_retry.rs` — a completed intent
//! replays, and an intent still `held` answers `idempotency_conflict`. The
//! other two are refusals, and they are measured here, at the driver, because
//! what matters about them is the loop's decision rather than the wire:
//!
//!   * `idempotency_key_reused` — the key belongs to a DIFFERENT payload.
//!     Nothing of ours was dispatched or charged under it, and the server's
//!     own remedy is "Use a fresh key for a new request".
//!   * `idempotency_replay_unavailable` — the request completed and was
//!     charged exactly once, but its answer was too large to store. The one
//!     failure class that is terminal AND already paid for.
//!
//! Plus the budget: a conflict is the most patient class there is, because the
//! answer is being produced upstream and the alternative to waiting is
//! abandoning a turn that has already been bought.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_core::agent_loop::{
    Driver, DriverConfig, RunOutput, TerminalReason, ASSUMED_UPSTREAM_DISPATCH_BUDGET,
    DEFAULT_CONNECTOR_RETRY_LIMIT, DEFAULT_EDGE_RETRY_LIMIT, IN_FLIGHT_SETTLE_MARGIN,
};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, IdempotencyKey, ModelConnector,
    NON_CONTRACT_BODY_HEADLINE,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use tokio_util::sync::CancellationToken;

use common::response;

/// An idempotency outcome in the envelope `gateErrorResponse` builds, with the
/// `retryable` / `recommendation` pair Model Connector's own `ERROR_ACTION_MAP`
/// assigns it and the HTTP status `HTTP_ERROR_STATUS` maps it to.
fn outcome(kind: &str, http_status: u16, retryable: bool, recommendation: &str) -> ConnectorError {
    ConnectorError::Logical {
        http_status,
        kind: kind.to_owned(),
        message: match kind {
            "idempotency_key_reused" => {
                "This Idempotency-Key was already used for a DIFFERENT request. Replaying the \
                 first request's response would hide the mismatch, so it is reported instead. \
                 Use a fresh key for a new request."
            }
            "idempotency_replay_unavailable" => {
                "This request completed, but its response was too large to store for replay. It \
                 has been dispatched and charged exactly once; retrieve the result from the \
                 original call rather than reissuing it."
            }
            _ => {
                "A request with this Idempotency-Key is still in flight. Retry shortly to \
                  receive its result; do not reissue it under a new key or it will be dispatched \
                  and charged twice."
            }
        }
        .to_owned(),
        retryable,
        recommendation: recommendation.to_owned(),
        retry_after: None,
        first_dispatch_observation: None,
    }
}

fn conflict() -> ConnectorError {
    outcome("idempotency_conflict", 409, true, "wait")
}

fn key_reused() -> ConnectorError {
    outcome("idempotency_key_reused", 422, false, "abort")
}

fn replay_unavailable() -> ConnectorError {
    outcome("idempotency_replay_unavailable", 409, false, "abort")
}

/// Fails `failures` times with `error`, recording the key on every attempt.
struct KeyRecordingConnector {
    failures: usize,
    calls: AtomicUsize,
    keys: Mutex<Vec<Option<IdempotencyKey>>>,
    error: fn() -> ConnectorError,
}

impl KeyRecordingConnector {
    fn new(failures: usize, error: fn() -> ConnectorError) -> Self {
        Self {
            failures,
            calls: AtomicUsize::new(0),
            keys: Mutex::new(Vec::new()),
            error,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn keys(&self) -> Vec<Option<IdempotencyKey>> {
        self.keys.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ModelConnector for KeyRecordingConnector {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.keys.lock().unwrap().push(req.idempotency_key.clone());
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.failures {
            return Err((self.error)());
        }
        Ok(response("done at last", 0.0))
    }
}

fn config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    // Real sleeping is dead time here; the schedule itself is pinned by the
    // unit tests in `agent_loop.rs`.
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 32;
    config
}

/// How far past its own deadline a waiting run is allowed to go before the
/// test calls it unbounded, as a multiple of that deadline.
///
/// Twenty-five, which is an absurd number of deadlines and that is the point:
/// it can only be reached by a wait that is not bounded at all, so the ceiling
/// never has to be tuned against jitter or a schedule change.
const WAIT_CEILING_DEADLINES: u32 = 25;

/// Drive the task, under a ceiling on how long the run may take.
///
/// **Every waiting test in this file goes through here**, and that is A2-245's
/// second half. Control mutated A2-241's fix so that the in-flight clock
/// restarted on every same-key re-dispatch — an unbounded wait, the exact
/// defect the deadline exists to prevent — and no test went red:
/// `driver_idempotent_turn` ran for over thirty minutes and was killed, because
/// on a paused clock an unbounded wait is an infinitely fast infinite loop. A
/// defect that removes a bound has to be a red test in seconds, not a CI job
/// that runs until the runner's limit.
///
/// The ceiling is virtual time, so it costs no wall-clock; it is derived from
/// the connector's own stated dispatch budget, so the failure message names the
/// deadline the run was supposed to stop at rather than an arbitrary constant.
/// It bounds a wait that SLEEPS — which every schedule in this loop does. A
/// mutant that polled without sleeping at all would spin the virtual clock in
/// place, and only a wall-clock bound outside the runtime could catch that.
async fn drive(connector: &dyn ModelConnector, config: DriverConfig) -> RunOutput {
    let deadline = connector
        .upstream_dispatch_budget()
        .unwrap_or(ASSUMED_UPSTREAM_DISPATCH_BUDGET)
        .saturating_add(IN_FLIGHT_SETTLE_MARGIN);
    let ceiling = deadline.saturating_mul(WAIT_CEILING_DEADLINES);
    let Ok(out) = tokio::time::timeout(ceiling, drive_unbounded(connector, config)).await else {
        panic!(
            "the run was still going after {ceiling:?} of virtual time. Its in-flight wait is \
             bounded by {deadline:?} — the connector's stated dispatch budget plus the \
             {IN_FLIGHT_SETTLE_MARGIN:?} settle margin — so it must end far inside this \
             ceiling. A wait that outlives its own deadline is unbounded."
        )
    };
    out
}

async fn drive_unbounded(connector: &dyn ModelConnector, config: DriverConfig) -> RunOutput {
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let driver = Driver::new(
        connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    driver.run("answer the question").await
}

// ---------------------------------------------------------------------------

/// A conflict is retried under the SAME key, which is the only response that
/// does not pay twice. Model Connector says so in the refusal itself: "do not
/// reissue it under a new key or it will be dispatched and charged twice."
#[tokio::test(start_paused = true)]
async fn an_in_flight_conflict_is_retried_under_the_same_key() {
    let connector = KeyRecordingConnector::new(2, conflict);
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?}",
        out.terminal_detail
    );
    let keys = connector.keys();
    assert_eq!(keys.len(), 3, "{keys:?}");
    assert!(
        keys.iter().all(Option::is_some),
        "a dispatch carried no key: {keys:?}"
    );
    assert!(
        keys.windows(2).all(|pair| pair[0] == pair[1]),
        "the key changed while waiting on the request it identifies: {keys:?}"
    );
}

/// A conflict gets the patient treatment, not the flat two a
/// connector-authored envelope gets. The difference is what the wait is FOR:
/// an envelope Model Connector wrote has its server-side attempts already
/// behind it, while a conflict means an answer we have paid for is still being
/// produced.
///
/// A2-234 pinned "patient" as `DEFAULT_EDGE_RETRY_LIMIT + 1` dispatches, which
/// A2-240 then showed to be the wrong shape of bound entirely — a count, spent
/// in 41 s, on a turn the upstream needed more than 100 s for. Patient now
/// means the clock, and the assertion says so.
#[tokio::test(start_paused = true)]
async fn an_in_flight_conflict_is_waited_out_on_the_patient_budget() {
    let connector = KeyRecordingConnector::new(usize::MAX, conflict);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert!(
        u32::try_from(connector.calls()).unwrap() > DEFAULT_EDGE_RETRY_LIMIT + 1,
        "a conflict was given a counted budget — the flat connector one \
         ({DEFAULT_CONNECTOR_RETRY_LIMIT}) or the edge one ({DEFAULT_EDGE_RETRY_LIMIT}) — \
         instead of the upstream's own clock: {} dispatch(es)",
        connector.calls()
    );
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("still in flight"),
        "the verdict must say a paid-for answer was abandoned, not just that something failed: \
         {detail}"
    );
    // The connector states no budget, so the assumed one applies.
    assert!(
        detail.contains("150s"),
        "the verdict must name the clock that ran out — 120s assumed upstream budget plus \
         the 30s settle margin: {detail}"
    );
}

/// The key was claimed by a different payload, so ours was never dispatched
/// and never charged. Retrying it unchanged can only be refused again; the
/// server's own remedy is a fresh key, and taking it saves the run.
///
/// It should never fire — `TurnIntentSeries::stamp` compares the payload and
/// mints a new key before the server has to — so this measures the backstop.
#[tokio::test(start_paused = true)]
async fn a_key_the_server_says_belongs_to_another_request_is_replaced_not_repeated() {
    let connector = KeyRecordingConnector::new(1, key_reused);
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a key collision cost the whole run: {:?}",
        out.terminal_detail
    );
    let keys = connector.keys();
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert_ne!(
        keys[0], keys[1],
        "the refused key was sent again, which can only be refused again: {keys:?}"
    );
}

/// And the replacement is bounded like everything else: a server that refuses
/// every key does not get an unbounded supply of them.
#[tokio::test(start_paused = true)]
async fn replacing_a_reused_key_is_bounded_by_the_ordinary_retry_budget() {
    let connector = KeyRecordingConnector::new(usize::MAX, key_reused);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        u32::try_from(connector.calls()).unwrap(),
        DEFAULT_CONNECTOR_RETRY_LIMIT + 1,
        "a fresh key is a retry, not an exemption from the retry budget"
    );
}

/// The request ran and was charged; only its answer is gone. Retrying would
/// buy a second execution of work already bought, so the run stops — and the
/// verdict has to say the money is spent, or an operator reads a dead turn as
/// a turn that never happened.
#[tokio::test(start_paused = true)]
async fn an_answer_too_large_to_replay_stops_the_run_and_says_it_was_already_charged() {
    let connector = KeyRecordingConnector::new(usize::MAX, replay_unavailable);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        connector.calls(),
        1,
        "a request that was charged exactly once must not be dispatched again"
    );
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("charged exactly once"),
        "the verdict does not say the turn was paid for: {detail}"
    );
    assert!(
        detail.contains("not retryable"),
        "the verdict does not say why it stopped: {detail}"
    );
}

/// Every dispatch carries a key. A turn dispatched without one has no
/// at-most-once guarantee at all, and the failure is silent: the run looks
/// identical and the bill does not.
#[tokio::test(start_paused = true)]
async fn every_dispatch_of_a_run_carries_a_key() {
    let connector = KeyRecordingConnector::new(0, conflict);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::Completed);
    let keys = connector.keys();
    assert!(!keys.is_empty());
    assert!(keys.iter().all(Option::is_some), "{keys:?}");
}

// ---------------------------------------------------------------------------
// A2-241: the wait for a turn the upstream is still computing.

/// Pilot A2-240, turn 24, replayed on a virtual clock.
///
/// 144k input tokens went to `deepseek-flash`; Cloudflare cut the socket at
/// its ~100 s origin timeout with HTTP 524 while Model Connector went on
/// computing the answer. `arcana` re-dispatched under the same key — which is
/// correct, and the only response that does not pay twice — and was refused
/// `idempotency_conflict` four times before ending the run `ConnectorFatal`
/// "after 6 attempt(s) over 41s". The answer it abandoned was already bought.
///
/// The upstream here behaves exactly as Model Connector does: one provider
/// execution, held while it runs, replayable once it settles.
struct CutThenStillComputing {
    /// How long the intent stays `held` after the first dispatch.
    computing_for: Duration,
    /// What this connector states one dispatch may legitimately take.
    dispatch_budget: Option<Duration>,
    /// Executions that reached the provider. The whole point is that there is
    /// exactly one, however many times the client asks for its result.
    provider_calls: AtomicUsize,
    conflicts: AtomicUsize,
    first_dispatch: Mutex<Option<tokio::time::Instant>>,
}

impl CutThenStillComputing {
    fn new(computing_for: Duration, dispatch_budget: Option<Duration>) -> Self {
        Self {
            computing_for,
            dispatch_budget,
            provider_calls: AtomicUsize::new(0),
            conflicts: AtomicUsize::new(0),
            first_dispatch: Mutex::new(None),
        }
    }

    fn provider_calls(&self) -> usize {
        self.provider_calls.load(Ordering::SeqCst)
    }

    fn conflicts(&self) -> usize {
        self.conflicts.load(Ordering::SeqCst)
    }
}

/// The 16-byte Cloudflare body, in the shape `is_edge_gateway_failure` reads.
fn edge_524() -> ConnectorError {
    ConnectorError::Http {
        status: 524,
        message: format!("{NON_CONTRACT_BODY_HEADLINE} (16 bytes): error code: 524"),
        retry_after: None,
    }
}

#[async_trait::async_trait]
impl ModelConnector for CutThenStillComputing {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let mut first = self.first_dispatch.lock().unwrap();
        let Some(started) = *first else {
            // The one and only provider execution. The edge cuts the socket
            // before its answer can come back; upstream, it keeps running.
            *first = Some(tokio::time::Instant::now());
            self.provider_calls.fetch_add(1, Ordering::SeqCst);
            return Err(edge_524());
        };
        drop(first);
        if started.elapsed() < self.computing_for {
            self.conflicts.fetch_add(1, Ordering::SeqCst);
            return Err(conflict());
        }
        Ok(response("the answer this turn had already paid for", 0.0))
    }

    fn upstream_dispatch_budget(&self) -> Option<Duration> {
        self.dispatch_budget
    }
}

/// The in-flight schedule needs real pauses to be a schedule; the clock they
/// run against is virtual (`start_paused`), so none of it is dead time.
fn waiting_config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 128;
    config
}

/// The defect, stated as the outcome an operator cares about: a turn whose
/// answer is still being produced upstream is waited out, not abandoned, and
/// the provider is asked exactly once.
///
/// 100 s of upstream work against a 110 s stated dispatch budget. Before the
/// fix the run died `ConnectorFatal` after ~41 s of it — five re-dispatches
/// out of a counter it shared with the edge schedule, on a budget that was a
/// COUNT and so had nothing to do with how long the request may legitimately
/// run.
#[tokio::test(start_paused = true)]
async fn a_turn_the_upstream_is_still_computing_is_waited_out_not_abandoned() {
    let connector =
        CutThenStillComputing::new(Duration::from_secs(100), Some(Duration::from_secs(110)));
    let out = drive(&connector, waiting_config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a paid-for answer was abandoned while it was still being produced: {:?}",
        out.terminal_detail
    );
    assert_eq!(
        out.final_text.as_deref(),
        Some("the answer this turn had already paid for"),
        "the run did not replay the answer it waited for"
    );
    assert_eq!(
        connector.provider_calls(),
        1,
        "the turn was dispatched to the provider more than once"
    );
    assert!(
        connector.conflicts() > 0,
        "the fixture never exercised the in-flight path"
    );
}

/// The in-flight wait is bounded by the upstream's own budget, not by a count
/// of polls — and it does not wait forever either.
#[tokio::test(start_paused = true)]
async fn the_in_flight_wait_stops_at_the_upstream_budget_and_says_so() {
    // Never settles: past any honest bound on how long this request may run.
    let connector =
        CutThenStillComputing::new(Duration::from_secs(10 * 60), Some(Duration::from_secs(110)));
    let out = drive(&connector, waiting_config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("140s"),
        "the verdict must name the wait it spent — 110s upstream budget plus the \
         settle margin: {detail}"
    );
    assert!(
        detail.contains("re-dispatch"),
        "the verdict must also name the counted budget it did NOT spend: {detail}"
    );
    // A count-shaped budget would have given up around the sixth attempt; a
    // deadline-shaped one polls until the upstream's budget is gone.
    assert!(
        connector.conflicts() >= 8,
        "the wait was cut short by a count rather than by the clock: {} conflict(s)",
        connector.conflicts()
    );
}

/// The wait has to fit inside the budget the run actually ships with.
///
/// `arcana run` caps a run at 24 connector attempts by default
/// (`crates/cli/src/main.rs:135`), and the client's own dispatch budget spans
/// more polls than that. Measured before this was handled: the same fixture
/// under `max_turns = 10` ended `MaxTurns` — a different verdict on the same
/// abandoned, already-paid-for answer. A poll asks no question and is charged
/// nothing, so it does not spend the run's allowance of questions.
#[tokio::test(start_paused = true)]
async fn polling_for_an_answer_already_paid_for_does_not_spend_the_runs_turns() {
    let connector =
        CutThenStillComputing::new(Duration::from_secs(100), Some(Duration::from_secs(110)));
    let mut config = waiting_config();
    // Two questions' worth: the one turn this run has, and room to prove the
    // cap is still enforced rather than removed.
    config.max_turns = 2;
    let out = drive(&connector, config).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "the turn budget cut short a wait for an answer already bought: {:?}",
        out.terminal_detail
    );
    assert!(
        out.turns > 2,
        "the polls are not being reported at all, which hides what the run did: {}",
        out.turns
    );
}

/// And the cap is still a cap: polls are exempt, dispatches are not.
#[tokio::test(start_paused = true)]
async fn the_turn_cap_still_stops_a_run_that_keeps_asking_new_questions() {
    // Never answers, and never conflicts: every attempt is a fresh failed
    // dispatch of the ordinary kind.
    let connector = KeyRecordingConnector::new(usize::MAX, key_reused);
    let mut config = config();
    config.max_turns = 3;
    let out = drive(&connector, config).await;

    assert!(
        matches!(
            out.reason,
            TerminalReason::MaxTurns | TerminalReason::ConnectorFatal
        ),
        "a run that keeps asking must still hit a bound: {:?}",
        out.reason
    );
    assert!(
        out.turns <= 3,
        "the cap was removed, not narrowed: {}",
        out.turns
    );
}

/// Defect 1 of A2-240, on its own: the patient in-flight wait shared its
/// counter with the edge-retry schedule, so a 524 that had already spent "1 of
/// 5" left the conflicts starting at "2 of 5". Counters that measure different
/// upstream facts must not subtract from each other.
#[tokio::test(start_paused = true)]
async fn waiting_out_an_in_flight_turn_does_not_spend_the_edge_budget() {
    let connector =
        CutThenStillComputing::new(Duration::from_secs(100), Some(Duration::from_secs(110)));
    let out = drive(&connector, waiting_config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?}",
        out.terminal_detail
    );
    // The edge budget is five. The run made one edge re-dispatch (the 524) and
    // then polled far more than four times; had the two shared a counter, the
    // run could not have reached the answer at all.
    assert!(
        connector.conflicts() > usize::try_from(DEFAULT_EDGE_RETRY_LIMIT).unwrap(),
        "the in-flight wait fitted inside the edge budget, so the two are still \
         sharing it: {} conflict(s)",
        connector.conflicts()
    );
}

// ---------------------------------------------------------------------------
// A2-245: what one waited turn costs the client that waits.

/// A task big enough that rebuilding its prompt is a cost worth counting.
///
/// 80 000 characters — just under the 90 000-unit working ceiling, so the
/// guard leaves it alone and every dispatch carries the whole of it. The live
/// turn this comes from (A2-240, turn 24) was 144k tokens, which is larger
/// than this loop will now send at all: the point of the number is that it is
/// the biggest prompt a real run can rebuild, not that it matches the pilot.
fn bulky_task() -> String {
    "sift the evidence and report. ".repeat(80_000 / 30)
}

/// What one run wrote while it waited.
struct WaitCost {
    out: RunOutput,
    /// Prompt builds, counted where they land: one `===== dispatch` block per
    /// call to `compose_request`.
    prompt_builds: usize,
    /// Bytes the wait added to the operator's transcript file.
    transcript_bytes: u64,
    /// `dispatch` events in the audit log — the other per-build record.
    dispatch_records: usize,
    /// Polls the upstream answered `idempotency_conflict`.
    conflicts: usize,
}

/// Run the waiting fixture with both artefacts a dispatch writes to disk kept,
/// and count what one waited turn cost.
async fn measure_waited_turn(computing_for: Duration, budget: Duration) -> WaitCost {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let transcript = dir.path().join("transcript.txt");
    let audit = arcana_core::hooks::audit::AuditLog::new(dir.path()).expect("audit log");
    let executor = arcana_core::execution::CapabilityExecutor::new(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
        audit,
    );
    let connector = CutThenStillComputing::new(computing_for, Some(budget));
    let mut config = waiting_config();
    config.transcript_path = Some(transcript.clone());

    let deadline = budget.saturating_add(IN_FLIGHT_SETTLE_MARGIN);
    let ceiling = deadline.saturating_mul(WAIT_CEILING_DEADLINES);
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let Ok(out) = tokio::time::timeout(ceiling, driver.run(&bulky_task())).await else {
        panic!(
            "the run was still going after {ceiling:?} of virtual time, against a \
             {deadline:?} deadline — the wait is unbounded"
        )
    };

    let written = std::fs::read_to_string(&transcript).expect("transcript");
    let audit_log = std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log");
    WaitCost {
        prompt_builds: written.matches("===== dispatch ").count(),
        transcript_bytes: u64::try_from(written.len()).unwrap(),
        dispatch_records: audit_log
            .lines()
            .filter(|line| line.contains("\"dispatch\""))
            .count(),
        conflicts: connector.conflicts(),
        out,
    }
}

/// One waited turn = one prompt build and one transcript record.
///
/// A2-241 made the loop wait, and left each poll going through the whole of
/// `step()`: prompt rebuilt from the history, block appended to the
/// transcript, `dispatch` event appended to the audit log — for a request the
/// client is not re-asking but merely collecting. Measured here before the fix
/// on this very fixture: **13 prompt builds and 1 040 782 bytes of transcript**
/// for a single turn of 80 000 characters waited out over 100 s (11 polls; the
/// schedule is jittered, so a run lands between 11 and 13 polls).
///
/// Two builds, not one, is the honest expectation: the first dispatch, and the
/// one re-dispatch the 524 earned. What must not scale is the wait — the
/// twenty-odd polls between them.
#[tokio::test(start_paused = true)]
async fn one_waited_turn_builds_one_prompt_per_dispatch_and_none_per_poll() {
    let cost = measure_waited_turn(Duration::from_secs(100), Duration::from_secs(110)).await;

    assert_eq!(
        cost.out.reason,
        TerminalReason::Completed,
        "{:?}",
        cost.out.terminal_detail
    );
    assert!(
        cost.conflicts >= 8,
        "the fixture did not exercise a long wait, so it measures nothing: {} conflict(s)",
        cost.conflicts
    );
    assert_eq!(
        cost.prompt_builds, 2,
        "one build for the first dispatch and one for the re-dispatch the 524 earned — the \
         {} poll(s) in between must re-send the request they are waiting on, not rebuild it \
         ({} prompt build(s), {} bytes of transcript)",
        cost.conflicts, cost.prompt_builds, cost.transcript_bytes
    );
    assert_eq!(
        cost.dispatch_records, 2,
        "a poll appended a `dispatch` record: {} record(s) for 2 dispatches",
        cost.dispatch_records
    );
    // The transcript is the operator's file and the bigger of the two: a
    // per-poll block turns one 80 kB turn into megabytes.
    assert!(
        cost.transcript_bytes < 300_000,
        "the wait grew the transcript past two dispatches' worth: {} bytes",
        cost.transcript_bytes
    );
}

/// The polls still reach the upstream, and still under the same key — the
/// saving is the local work, not the asking.
#[tokio::test(start_paused = true)]
async fn a_wait_that_costs_no_prompt_build_still_polls_the_upstream() {
    let cost = measure_waited_turn(Duration::from_secs(100), Duration::from_secs(110)).await;

    assert_eq!(cost.out.reason, TerminalReason::Completed);
    assert_eq!(
        cost.out.final_text.as_deref(),
        Some("the answer this turn had already paid for"),
        "the run did not collect the answer it waited for"
    );
    assert!(
        cost.out.turns > u32::try_from(cost.prompt_builds).unwrap(),
        "the polls stopped being reported when they stopped costing a build: {} turn(s), {} \
         prompt build(s)",
        cost.out.turns,
        cost.prompt_builds
    );
}
