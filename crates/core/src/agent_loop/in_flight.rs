//! Waiting out a turn the connector is still computing (in-flight polls under
//! the same idempotency key).

use super::{
    connector_fatal_detail, in_flight_poll_pause, jitter_permille, retry_line, ConnectorError,
    Dispatch, Driver, Duration, FatalCause, Instant, Polled, RetryBudget, RetryClass, RunState,
    StepResult, TerminalReason, ASSUMED_UPSTREAM_DISPATCH_BUDGET, IN_FLIGHT_SETTLE_MARGIN,
};

impl Driver<'_> {
    /// How long one dispatch may legitimately take upstream before the loop
    /// stops waiting for its answer.
    ///
    /// Asked of the connector rather than configured here: the number that
    /// matters is the one the CALLER already told the upstream it may spend
    /// (`ExecuteRequest.timeout`, widened by the server's own attempts and
    /// queue), and a second copy in `DriverConfig` could only drift.
    fn in_flight_budget(&self) -> Duration {
        self.connector
            .upstream_dispatch_budget()
            .unwrap_or(ASSUMED_UPSTREAM_DISPATCH_BUDGET)
            .saturating_add(IN_FLIGHT_SETTLE_MARGIN)
    }

    /// Wait out a turn Model Connector is still computing, under the key it
    /// was dispatched with.
    ///
    /// Three things are deliberate here:
    ///
    /// * The counter is `RunState::in_flight_polls`, not
    ///   `RunState::connector_retries`: the edge re-dispatch that preceded the
    ///   conflict must not subtract from the wait for the answer it interrupted.
    /// * The bound is a deadline from the first dispatch
    ///   ([`TurnIntentSeries::dispatched_at`], which a re-dispatch under the
    ///   same key does not move), lasting as long as that request may
    ///   legitimately run plus [`IN_FLIGHT_SETTLE_MARGIN`]. A count shrinks with
    ///   jitter and can drop an answer the turn already paid for.
    /// * The wait owns its re-dispatches instead of returning
    ///   [`ContinueReason::ConnectorRetry`] per pause, which would re-enter
    ///   [`Self::step`] on every poll (prompt rebuild, transcript block, audit
    ///   `dispatch` event) for a request that is collected, not re-asked. A poll
    ///   re-sends the bytes the dispatch already built ([`Dispatch`]); the key
    ///   replays only while they are identical.
    ///
    /// Waiting is the cheap choice: the idempotency hold lives 30 minutes
    /// (`src/billing/intent.ts:36`), so every scheduled wait is far inside the
    /// window where a retry is a replay, not a second charge.
    ///
    /// The pauses are NOT charged to `connector_retry_pause_budget`, which
    /// bounds sleeps between attempts at a FAILED request; spending it here
    /// would add a second, unrelated bound to a wait that already has one.
    pub(super) async fn wait_out_in_flight(
        &self,
        state: &mut RunState,
        refusal: &ConnectorError,
        started: Instant,
        dispatch: &Dispatch<'_>,
    ) -> Polled {
        let budget = self.in_flight_budget();
        // The most recent conflict this loop has collected itself; the verdict
        // must quote the refusal that ENDED the wait, not the one that started it.
        let mut latest: Option<ConnectorError> = None;
        loop {
            let error = latest.as_ref().unwrap_or(refusal);
            // `started` is only the fallback: it is later than the dispatch, so
            // it can only shorten the wait, the safe direction.
            let dispatched = state.intent.dispatched_at().unwrap_or(started);
            let waited = Instant::now().saturating_duration_since(dispatched);
            let Some(remaining) = budget
                .checked_sub(waited)
                .filter(|remaining| !remaining.is_zero())
            else {
                state.terminal_detail = Some(connector_fatal_detail(
                    error,
                    state.turn_attempts(),
                    started.elapsed(),
                    FatalCause::InFlightWaitSpent {
                        waited,
                        budget,
                        polls: state.in_flight_polls,
                        redispatches: state.connector_retries,
                        redispatch_limit: self.config.edge_retry_limit,
                    },
                ));
                return Polled::Stop(StepResult::Terminal(TerminalReason::ConnectorFatal, None));
            };
            state.in_flight_polls = state.in_flight_polls.saturating_add(1);
            state.in_flight_polls_total = state.in_flight_polls_total.saturating_add(1);
            // Clamped so the last poll lands ON the deadline, not past it.
            let wait =
                in_flight_poll_pause(state.in_flight_polls, jitter_permille()).min(remaining);
            eprintln!(
                "{}",
                retry_line(
                    error,
                    wait,
                    RetryClass::InFlight,
                    RetryBudget::Deadline {
                        poll: state.in_flight_polls,
                        waited,
                        budget,
                    },
                )
            );
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            // The step-level cancel check cannot see this loop; Ctrl-C during
            // a poll must not let another request go out.
            if self.cancel.is_cancelled() {
                return Polled::Stop(StepResult::Terminal(
                    TerminalReason::AbortedByOperator,
                    None,
                ));
            }
            // The poll: the same bytes under the same key. `first_dispatch` is
            // `false` because the measurement metadata belongs to the attempt
            // that opened the key.
            //
            // `attempts` is still incremented so `RunOutput::turns` reports
            // every poll; the `max_turns` exemption bounds what the run is
            // allowed, not what it did.
            state.attempts = state.attempts.saturating_add(1);
            match self
                .call_connector(
                    &mut state.intent,
                    dispatch.prompt,
                    Some(dispatch.model),
                    false,
                )
                .await
            {
                Ok(resp) => return Polled::Answered(Box::new(resp)),
                Err(next) if RetryClass::of(&next) == RetryClass::InFlight => {
                    // Same line a poll printed when it was a step of its own.
                    eprintln!("arcana: connector dispatch failed: {next}");
                    latest = Some(next);
                }
                Err(next) => return Polled::Refused(next),
            }
        }
    }
}
