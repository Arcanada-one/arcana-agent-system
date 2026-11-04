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
    /// queue), and a second copy of it in `DriverConfig` could only drift from
    /// the first.
    fn in_flight_budget(&self) -> Duration {
        self.connector
            .upstream_dispatch_budget()
            .unwrap_or(ASSUMED_UPSTREAM_DISPATCH_BUDGET)
            .saturating_add(IN_FLIGHT_SETTLE_MARGIN)
    }

    /// Wait out a turn Model Connector is still computing, under the key it
    /// was dispatched with.
    ///
    /// This is the patient path, and A2-240 is what it is for: a 144k-token
    /// turn, cut by Cloudflare at its ~100 s origin timeout while the
    /// Connector went on producing the answer. `arcana` did the expensive part
    /// right — it re-dispatched under the SAME `Idempotency-Key`, so no second
    /// charge — and then threw the answer away after 41 s, because the wait
    /// was five sleeps out of a counter it shared with the edge schedule.
    ///
    /// Three things are therefore deliberate here:
    ///
    /// * The counter is `RunState::in_flight_polls`, not
    ///   `RunState::connector_retries`. The edge re-dispatch that PRECEDED the
    ///   conflict — the 524 — must not subtract from the wait for the answer
    ///   that same 524 interrupted. They are different facts about different
    ///   upstreams.
    /// * The bound is a deadline, not a count. It runs from the moment the
    ///   request first left this client ([`TurnIntentSeries::dispatched_at`],
    ///   which a re-dispatch under the same key does not move) and lasts as
    ///   long as that request may legitimately run plus
    ///   [`IN_FLIGHT_SETTLE_MARGIN`]. A count cannot express that: it is
    ///   whatever the schedule happens to add up to, and jitter shortened
    ///   A2-240's nominal 60 s to 41 s.
    /// * The wait owns its re-dispatches. It used to return
    ///   [`ContinueReason::ConnectorRetry`] after every pause, so every poll
    ///   re-entered [`Self::step`]: the prompt rebuilt from the history, a
    ///   block appended to the operator's transcript and a `dispatch` event to
    ///   the audit log — for a request that is not being re-asked but
    ///   collected. Measured on the `CutThenStillComputing` fixture with a
    ///   turn of 80 000 characters: **13 prompt builds and 1 040 782 bytes of
    ///   transcript for one waited turn**, against two dispatches' worth
    ///   (A2-245). A poll now re-sends the bytes the dispatch already built
    ///   ([`Dispatch`]) — which is also the only way they are guaranteed to be
    ///   the same bytes, and the key replays only while they are.
    ///
    /// Waiting is also the cheap choice, and that is measured rather than
    /// assumed: the hold that makes the retry a replay rather than a second
    /// dispatch lives 30 minutes (`src/billing/intent.ts:36`), so every wait
    /// this method can schedule is far inside the window where a retry is
    /// free. The expensive choice is the one this replaces — abandoning a turn
    /// that was bought.
    ///
    /// The pauses here are NOT charged to `connector_retry_pause_budget`: that
    /// budget bounds how long a turn may sleep between attempts at a FAILED
    /// request, and spending it here would put a second, shorter and unrelated
    /// bound on a wait that already has one.
    pub(super) async fn wait_out_in_flight(
        &self,
        state: &mut RunState,
        refusal: &ConnectorError,
        started: Instant,
        dispatch: &Dispatch<'_>,
    ) -> Polled {
        let budget = self.in_flight_budget();
        // The most recent conflict, once this loop has collected one of its
        // own. The verdict has to quote the refusal that ENDED the wait, not
        // the one that started it.
        let mut latest: Option<ConnectorError> = None;
        loop {
            let error = latest.as_ref().unwrap_or(refusal);
            // `started` (the first failure of the streak) is the fallback, not
            // the preference: it is later than the dispatch and so can only
            // shorten the wait, which is the safe direction for a bound that
            // must not be a guess. In practice the key is always in force here
            // — the conflict is an answer TO it.
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
            // Clamped to what is left, so the last poll lands ON the deadline
            // rather than past it: an answer that settles in the final second
            // is still an answer this turn paid for.
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
            // The step-level check cannot see this loop any more, and an
            // operator who pressed Ctrl-C during a poll must not then watch
            // another request go out.
            if self.cancel.is_cancelled() {
                return Polled::Stop(StepResult::Terminal(
                    TerminalReason::AbortedByOperator,
                    None,
                ));
            }
            // The poll itself: the same bytes under the same key, and nothing
            // else. `first_dispatch` is `false` because it is not one — the
            // measurement metadata belongs to the attempt that opened the key,
            // exactly as it did when a poll was a whole `step()`.
            //
            // `attempts` is still incremented, so `RunOutput::turns` keeps
            // reporting every poll: what A2-241 exempted from `max_turns` is
            // what the run is ALLOWED, never what it did.
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
                    // The same line a poll printed when it was a step of its
                    // own: the wait got quieter in cost, not in evidence.
                    eprintln!("arcana: connector dispatch failed: {next}");
                    latest = Some(next);
                }
                Err(next) => return Polled::Refused(next),
            }
        }
    }
}
