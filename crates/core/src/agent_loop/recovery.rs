//! Connector-error recovery: whether a failed dispatch is retried, waited
//! out or ends the run, and the retry schedule and verdict text behind that.

use super::{
    ConnectorError, ContinueReason, Dispatch, Driver, Duration, Instant, Polled, Recovered,
    RunState, StepResult, TerminalReason, IN_FLIGHT_POLL_BASE, MAX_EDGE_RETRY_PAUSE,
    MAX_IN_FLIGHT_POLL_PAUSE, MAX_RETRY_AFTER,
};

impl Driver<'_> {
    /// Decide what a failed connector attempt means for the run: another
    /// dispatch, or the end of it.
    ///
    /// Retrying is safe here because a `/execute` dispatch has no local side
    /// effect — the tools run on this side of the wire, and the only thing a
    /// second attempt can spend twice is money, which the cost cap already
    /// bounds. It is NOT a guarantee about the upstream: a connector that runs
    /// tools server-side could act twice on a request whose answer never
    /// arrived, which is why the retry is bounded and the upstream's own
    /// `retryable` flag is respected rather than second-guessed.
    pub(super) async fn recover_or_stop(
        &self,
        state: &mut RunState,
        failure: &ConnectorError,
        first_dispatch: bool,
        dispatch: &Dispatch<'_>,
    ) -> Recovered {
        if first_dispatch {
            state.first_dispatch_observation = failure.first_dispatch_observation().cloned();
        }
        // The clock the terminal verdict reports. Started at the first failure
        // of the streak, not at the start of the run: "94 turns" and "three
        // 502s over four seconds" are different facts and the second one is
        // what says whether the retry policy was a serious attempt.
        //
        // Hoisted above the loop, so a second lap — the in-flight wait handing
        // back a refusal of a different class — measures the same streak rather
        // than starting a new one.
        let started = *state
            .connector_failure_since
            .get_or_insert_with(Instant::now);
        // The loop exists for exactly one transition: the in-flight wait owns
        // its own re-dispatches (A2-245), so when a poll is refused by
        // something that is NOT "still in flight", that refusal has to be
        // judged here, by the counters that belong to it, without going back
        // out through `step()` and rebuilding the request to be told the same
        // thing again.
        let mut polled: Option<ConnectorError> = None;
        loop {
            let error = polled.as_ref().unwrap_or(failure);
            // The connector's own message is the diagnosis — `ConnectorError`
            // carries `HTTP {status}: {message}`, e.g. `HTTP 404: Connector
            // "arcana-repl" not found`. Mapping to `ConnectorFatal` without it left
            // the operator a verdict and no evidence, and cost a four-commit bisect
            // and two wrong root causes to recover what this one line says.
            // `eprintln!` rather than `tracing`: the CLI installs no subscriber, so
            // a log line here is discarded.
            eprintln!("arcana: connector dispatch failed: {error}");
            // A size refusal is not a connector failure: the request was ours and
            // it was too big. Retrying sends the same oversized body again, and
            // reporting `ConnectorFatal` points the operator at a service that did
            // exactly what its contract says.
            if error.is_request_too_large() {
                return Recovered::Step(StepResult::Terminal(
                    TerminalReason::RequestTooLarge,
                    None,
                ));
            }
            // Not a transient failure, whatever the envelope's `retryable`
            // flag says (A2-290). The upstream was aborted for spending the
            // WHOLE per-attempt budget this client itself stated, and a
            // re-dispatch of this turn sends byte-identical bytes under that
            // identical budget — the same experiment, not a second chance.
            //
            // Stopping here rather than after the class's re-dispatches is the
            // money decision. Model Connector reports an aborted attempt as
            // `usage: 0` while the provider has already been fed the whole
            // prompt, so `max_cost_usd` cannot see this class at all: measured
            // on A2-278 run 5 (deepseek-v4-pro, a ~37 000-token turn), the run
            // ended `ConnectorFatal` after 15 attempts having spent two more
            // full 120 s budgets of provider compute that the cost tracker
            // recorded as $0. The verdict names the budget and the model
            // because those are the two things an operator changes.
            if error.is_upstream_attempt_timeout() {
                let turn_attempts = state.turn_attempts();
                state.terminal_detail = Some(connector_fatal_detail(
                    error,
                    turn_attempts,
                    started.elapsed(),
                    FatalCause::UpstreamAttemptBudgetExhausted {
                        attempt_budget: self.connector.upstream_attempt_budget(),
                        model: dispatch.model,
                    },
                ));
                return Recovered::Step(StepResult::Terminal(TerminalReason::ConnectorFatal, None));
            }
            let class = RetryClass::of(error);
            let limit = if class.is_patient() {
                self.config.edge_retry_limit
            } else {
                self.config.connector_retry_limit
            };
            // Attempts of THIS turn, the failed first dispatch included — the
            // number an operator counts in the log, not either retry counter.
            let attempts = state.turn_attempts();
            // The key belongs to a DIFFERENT payload, so nothing of ours was
            // dispatched or charged under it, and sending it again can only be
            // refused again. Model Connector marks this non-retryable and says in
            // the same breath what the recovery is — "Use a fresh key for a new
            // request" — so dropping the key and re-dispatching is the upstream's
            // own instruction rather than a second-guess of its flag. It should
            // never fire: `TurnIntentSeries::stamp` compares the payload itself
            // and mints a new key before the server has to. This is the backstop
            // for the case that comparison failed to predict, and it says so.
            let reused_key = error.is_idempotency_key_reused();
            if reused_key {
                eprintln!(
                    "arcana: the Idempotency-Key this turn was dispatched under belongs to a \
                 different request — re-dispatching under a fresh key; this is a defect in \
                 arcana, not in the connector"
                );
                state.intent.abandon_key();
            }
            if !reused_key && !error.is_transient() {
                state.terminal_detail = Some(connector_fatal_detail(
                    error,
                    attempts,
                    started.elapsed(),
                    FatalCause::NotRetryable,
                ));
                return Recovered::Step(StepResult::Terminal(TerminalReason::ConnectorFatal, None));
            }
            // A turn whose answer is still being produced upstream is not a
            // failed request at all, and it is not bounded by a count. It leaves
            // here for a wait with its own counter, its own clock and — since
            // A2-245 — its own re-dispatches.
            if class == RetryClass::InFlight {
                match self
                    .wait_out_in_flight(state, error, started, dispatch)
                    .await
                {
                    Polled::Answered(resp) => return Recovered::Answered(resp),
                    Polled::Stop(step) => return Recovered::Step(step),
                    // Not an in-flight refusal any more: back to the top with it,
                    // where the counters that judge its class live.
                    Polled::Refused(next) => {
                        polled = Some(next);
                        continue;
                    }
                }
            }
            if state.connector_retries >= limit {
                state.terminal_detail = Some(connector_fatal_detail(
                    error,
                    attempts,
                    started.elapsed(),
                    FatalCause::RetriesSpent { limit, class },
                ));
                return Recovered::Step(StepResult::Terminal(TerminalReason::ConnectorFatal, None));
            }
            let wait = match self.plan_counted_redispatch(state, error, started, class, limit) {
                Ok(wait) => wait,
                Err(step) => return Recovered::Step(step),
            };
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            // The next step re-checks it too, but an operator who pressed Ctrl-C
            // during the pause should not then watch another dispatch go out.
            if self.cancel.is_cancelled() {
                return Recovered::Step(StepResult::Terminal(
                    TerminalReason::AbortedByOperator,
                    None,
                ));
            }
            return Recovered::Step(StepResult::Continue(ContinueReason::ConnectorRetry));
        }
    }

    /// Book the next re-dispatch of a failed request on the counted budget and
    /// say how long to sleep first — or refuse, with the verdict that says why.
    ///
    /// Split out of [`Self::recover_or_stop`] so the counted schedule and the
    /// in-flight deadline read as the two separate policies they are.
    ///
    /// # Errors
    /// The terminal step when the sleep budget is spent.
    fn plan_counted_redispatch(
        &self,
        state: &mut RunState,
        error: &ConnectorError,
        started: Instant,
        class: RetryClass,
        limit: u32,
    ) -> Result<Duration, StepResult> {
        let requested = retry_pause(
            error,
            state.connector_retries.saturating_add(1),
            self.config.connector_retry_backoff,
            class,
        );
        let Some(wait) = plan_retry_pause(
            requested,
            state.connector_retry_pause_spent,
            self.config.connector_retry_pause_budget,
        ) else {
            state.terminal_detail = Some(connector_fatal_detail(
                error,
                state.turn_attempts(),
                started.elapsed(),
                FatalCause::PauseBudgetSpent {
                    budget: self.config.connector_retry_pause_budget,
                },
            ));
            return Err(StepResult::Terminal(TerminalReason::ConnectorFatal, None));
        };
        state.connector_retries = state.connector_retries.saturating_add(1);
        state.connector_retry_pause_spent = state.connector_retry_pause_spent.saturating_add(wait);
        eprintln!(
            "{}",
            retry_line(
                error,
                wait,
                class,
                RetryBudget::Counted {
                    attempt: state.connector_retries,
                    limit,
                },
            )
        );
        Ok(wait)
    }
}

/// Which clock a transient failure heals on, which decides how patiently the
/// loop waits for it.
///
/// Three classes, and the split is about WHO is not answering, not about
/// severity — see [`ConnectorError::is_edge_gateway_failure`] for the first
/// half of the argument and [`ConnectorError::is_idempotency_conflict`] for
/// the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetryClass {
    /// Model Connector authored the refusal. It has already spent its own
    /// server-side attempts by the time the client sees one, so a long
    /// client-side wait on top buys little: two flat re-dispatches.
    Connector,
    /// The network edge in front of Model Connector. The request never reached
    /// a decision, and an edge heals in tens of seconds: five re-dispatches on
    /// the exponential schedule.
    EdgeGateway,
    /// The first attempt of THIS turn is still running upstream, and Model
    /// Connector is refusing to start a second one under the same key.
    ///
    /// The most patient class of the three, and the cheapest: the answer is
    /// being produced and already paid for, and the alternative to waiting is
    /// abandoning a turn that was bought. Model Connector's own message is
    /// explicit that the wrong recovery is a new key — "do not reissue it
    /// under a new key or it will be dispatched and charged twice."
    InFlight,
}

impl RetryClass {
    pub(super) fn of(error: &ConnectorError) -> Self {
        if error.is_idempotency_conflict() {
            Self::InFlight
        } else if error.is_edge_gateway_failure() {
            Self::EdgeGateway
        } else {
            Self::Connector
        }
    }

    /// Whether this class gets the deeper budget and the exponential schedule.
    pub(super) const fn is_patient(self) -> bool {
        matches!(self, Self::EdgeGateway | Self::InFlight)
    }

    /// The class as a terminal verdict names it.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Connector => "transient connector failure",
            Self::EdgeGateway => "transient gateway failure in front of the Model Connector",
            Self::InFlight => "request still in flight upstream under this turn's Idempotency-Key",
        }
    }
}

/// How long to wait before re-dispatching a transient failure.
///
/// An upstream that named a `retryAfter` knows better than we do — up to
/// [`MAX_RETRY_AFTER`], past which an unattended run would be parked for
/// longer than any operator expects a single turn to take. It wins over both
/// schedules below, because it is the only one of the three that is a
/// statement about this particular upstream at this particular moment.
///
/// Failing that: a gateway failure gets the exponential schedule, and anything
/// else keeps the flat `fallback` it has always had. `retry` is 1-based — the
/// first re-dispatch of the turn is 1.
pub(super) fn retry_pause(
    error: &ConnectorError,
    retry: u32,
    fallback: Duration,
    class: RetryClass,
) -> Duration {
    if let Some(secs) = error.retry_after_secs() {
        return Duration::from_secs(secs).min(MAX_RETRY_AFTER);
    }
    if class.is_patient() {
        return edge_backoff_pause(retry, fallback, jitter_permille());
    }
    fallback
}

/// One pause of the bounded exponential gateway schedule, with jitter.
///
/// Nominal is `base * 2^(retry - 1)`, capped at [`MAX_EDGE_RETRY_PAUSE`]: with
/// the shipped 2 s base that is **2 s, 4 s, 8 s, 16 s, 30 s** — 60 s of sleep
/// across the five re-dispatches [`DEFAULT_EDGE_RETRY_LIMIT`] allows, which is
/// the worst-case wall time this schedule adds to a turn.
///
/// Jitter only ever SHORTENS a pause (the factor is `0.5 ..= 1.0` of nominal),
/// so the worst case above is a real ceiling rather than an average. Jitter is
/// not decoration: an edge that drops a burst of requests hands every client
/// the same failure at the same instant, and a fleet of runs that all wake at
/// exactly 2 s re-creates the burst that took the edge down. `permille` is the
/// randomness, passed in so the schedule is a pure function and can be pinned.
pub(super) fn edge_backoff_pause(retry: u32, base: Duration, permille: u32) -> Duration {
    backoff_pause(retry, base, MAX_EDGE_RETRY_PAUSE, permille)
}

/// One pause of the in-flight poll schedule.
///
/// The same doubling with the same jitter, on its own base and its own
/// ceiling: **2, 4, 8, 15, 15, …** seconds nominal. It has no count limit
/// because the count is not what bounds it — see
/// [`Driver::wait_out_in_flight`] — so the ceiling is what decides how stale
/// an already-settled answer may get, and 15 s is that answer.
pub(super) fn in_flight_poll_pause(poll: u32, permille: u32) -> Duration {
    backoff_pause(
        poll,
        IN_FLIGHT_POLL_BASE,
        MAX_IN_FLIGHT_POLL_PAUSE,
        permille,
    )
}

/// Bounded exponential backoff with jitter, shared by both schedules.
pub(super) fn backoff_pause(retry: u32, base: Duration, cap: Duration, permille: u32) -> Duration {
    let steps = retry.saturating_sub(1).min(16);
    let nominal = base.saturating_mul(1_u32 << steps).min(cap);
    // 500..=1000 permille of nominal. Integer arithmetic on nanos: the pauses
    // are seconds-scale, so u128 cannot overflow and no float rounding can
    // push a pause above nominal.
    let factor = 500 + u128::from(permille.min(1000)) / 2;
    let nanos = nominal.as_nanos() * factor / 1000;
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// Jitter source: the sub-second part of the wall clock.
///
/// Deliberately not a `rand` dependency. The property needed here is that two
/// runners failing on the same edge burst do not wake together, and the
/// nanosecond the process reaches this line is already uncorrelated between
/// them. A clock that refuses to answer yields the full pause, which is the
/// conservative direction.
pub(super) fn jitter_permille() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1000, |since| since.subsec_nanos() % 1001)
}

/// Clamp a requested pause to what is left of the turn's sleep budget.
///
/// `None` means the budget is spent and the run must stop instead of sleeping
/// again — a bound on the sum of pauses, which no per-pause cap can express.
pub(super) fn plan_retry_pause(
    requested: Duration,
    spent: Duration,
    budget: Duration,
) -> Option<Duration> {
    let remaining = budget.checked_sub(spent).unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return None;
    }
    Some(requested.min(remaining))
}

/// Why the loop stopped re-dispatching.
#[derive(Debug, Clone, Copy)]
pub(super) enum FatalCause<'a> {
    /// The same request would fail the same way — a 404 connector id, a bad
    /// key, an envelope the upstream marked non-retryable.
    NotRetryable,
    /// Every re-dispatch this class is allowed has been made.
    RetriesSpent { limit: u32, class: RetryClass },
    /// The turn has slept as long as it may.
    PauseBudgetSpent { budget: Duration },
    /// The upstream attempt was aborted for consuming the whole per-attempt
    /// budget this client sent, and a re-dispatch could only repeat it
    /// (A2-290).
    UpstreamAttemptBudgetExhausted {
        /// What one attempt was allowed, when the connector states it.
        attempt_budget: Option<Duration>,
        /// The model the turn was dispatched to — half of what an operator
        /// has to change, the other half being the budget.
        model: &'a str,
    },
    /// The answer was still being produced upstream when the time that
    /// request may legitimately take ran out (A2-241).
    InFlightWaitSpent {
        /// Since the request first left this client.
        waited: Duration,
        /// Upstream dispatch budget plus [`IN_FLIGHT_SETTLE_MARGIN`].
        budget: Duration,
        /// Polls made under the turn's key.
        polls: u32,
        /// Re-dispatches of a FAILED request this turn made — a separate
        /// budget, named so the verdict cannot be read as "retries spent".
        redispatches: u32,
        redispatch_limit: u32,
    },
}

/// The line a run that died on the connector leaves behind, in the marker's
/// `error` field and on stderr.
///
/// Pilot A2-204c5 ended `ConnectorFatal` with `"error": null` and the single
/// stderr line `the Model Connector could not complete the request` — which
/// named neither the status, nor how many times it had been tried, nor over
/// how long. Three 502s in four seconds and an upstream down for an hour read
/// identically, and only one of them is a retry policy that was too short.
/// A2-225 gave denials this treatment; this is the connector's half.
pub(super) fn connector_fatal_detail(
    error: &ConnectorError,
    attempts: u32,
    elapsed: Duration,
    cause: FatalCause<'_>,
) -> String {
    let why = match cause {
        FatalCause::NotRetryable => {
            "not retryable — the same request would fail the same way".to_owned()
        }
        FatalCause::RetriesSpent { limit, class } => format!(
            "the {limit} re-dispatch(es) allowed for a {} are spent",
            class.label()
        ),
        FatalCause::PauseBudgetSpent { budget } => format!(
            "the {}s this turn may spend waiting between re-dispatches are spent",
            budget.as_secs()
        ),
        FatalCause::UpstreamAttemptBudgetExhausted {
            attempt_budget,
            model,
        } => {
            let budget = attempt_budget.map_or_else(
                || "the per-attempt budget".to_owned(),
                |budget| {
                    format!(
                        "the {}s this client allows one upstream attempt",
                        budget.as_secs()
                    )
                },
            );
            format!(
                "not retryable — the upstream attempt was aborted for spending {budget}, and a \
                 re-dispatch would send the same prompt to {model} under the same budget. Raise \
                 the per-attempt budget or dispatch to a faster model; re-running it as it \
                 stands only buys another aborted attempt, which the provider charges for and \
                 Model Connector reports as usage 0"
            )
        }
        // Both budgets, deliberately. The one that ran out is a clock, and an
        // operator who reads "re-dispatches are spent" would go looking for a
        // limit to raise that has nothing to do with why the turn was
        // abandoned — which is exactly the wrong lesson A2-240's own verdict
        // taught.
        FatalCause::InFlightWaitSpent {
            waited,
            budget,
            polls,
            redispatches,
            redispatch_limit,
        } => format!(
            "the answer was still being produced upstream after {} of the {} this turn's \
request may legitimately take, across {polls} poll(s) under its Idempotency-Key — the \
separate budget of {redispatch_limit} re-dispatch(es) for a FAILED request is untouched at \
{redispatches}, so raising it would change nothing here; it is the clock that ran out",
            format_elapsed(waited),
            format_elapsed(budget),
        ),
    };
    format!(
        "{} after {attempts} attempt(s) over {} — {why}: {}",
        error.status_label(),
        format_elapsed(elapsed),
        error.detail_text()
    )
}

/// The line printed before each re-dispatch.
///
/// Pure so its shape can be pinned without capturing stdio. It carries the one
/// fact an operator reconciling a bill at 3 a.m. needs and no layer above will
/// tell them: what this re-dispatch costs.
///
/// A2-230 could only say the bad half of that — Model Connector settles the
/// charge before the response reaches the socket, `arcana` sent no
/// `Idempotency-Key`, so a re-dispatch of a cut request "may be a paid
/// duplicate". Since A2-234 the same key goes out with every attempt of a
/// turn, so the sentence states the outcome instead of the risk: a request
/// that was executed and billed comes back as a replay.
pub(super) fn retry_line(
    error: &ConnectorError,
    wait: Duration,
    class: RetryClass,
    budget: RetryBudget,
) -> String {
    let headline = match class {
        RetryClass::Connector => String::new(),
        RetryClass::EdgeGateway => format!(
            "{} is the gateway in front of the Model Connector, not the Model Connector — ",
            error.status_label()
        ),
        RetryClass::InFlight => "the first attempt of this turn is still running upstream — \
waiting for the answer it is already producing rather than dispatching a second paid one, "
            .to_owned(),
    };
    let charge = match class {
        RetryClass::InFlight => "",
        _ if error.response_may_have_been_completed_upstream() => {
            " — the cut request may already have been executed and charged upstream, so the \
re-dispatch carries the same Idempotency-Key and is replayed rather than charged again"
        }
        _ => "",
    };
    format!(
        "arcana: {headline}retrying this turn in {} ({}){charge}",
        format_elapsed(wait),
        budget.render()
    )
}

/// Which budget the parenthetical in [`retry_line`] is reporting against.
///
/// Two shapes because there are two bounds, and A2-240 printed the wrong one:
/// every conflict said "n of 5" while the thing that would end the wait was a
/// clock, so the log answered a question nobody had asked and hid the one that
/// mattered.
#[derive(Debug, Clone, Copy)]
pub(super) enum RetryBudget {
    /// Re-dispatches of a failed request: `2 of 5`.
    Counted { attempt: u32, limit: u32 },
    /// Waiting for an answer already paid for: `polled 3 times, 27s of 140s`.
    Deadline {
        poll: u32,
        waited: Duration,
        budget: Duration,
    },
}

impl RetryBudget {
    pub(super) fn render(self) -> String {
        match self {
            Self::Counted { attempt, limit } => format!("{attempt} of {limit}"),
            Self::Deadline {
                poll,
                waited,
                budget,
            } => format!(
                "poll {poll}, {} of the {} this request may take",
                format_elapsed(waited),
                format_elapsed(budget)
            ),
        }
    }
}

/// A duration as an operator reads it: whole seconds past ten, one decimal
/// below, so `0.3s` and `63s` both say something.
pub(super) fn format_elapsed(d: Duration) -> String {
    if d.as_secs() >= 10 {
        // Rounded through the integer parts rather than through `f64`: this
        // string ends up in a done-marker a script may parse.
        let rounded = d.as_secs() + u64::from(d.subsec_millis() >= 500);
        format!("{rounded}s")
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}
