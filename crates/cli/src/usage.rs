//! Spend reporting (ARAS-0066).
//!
//! Two surfaces: the per-turn line the interactive session prints, and
//! `arcana usage`, which reports what the Model Connector has actually
//! recorded.
//!
//! ## Why `usage` asks the connector instead of adding up locally
//!
//! The connector is where money is measured (`Request.costUsd`) and, since
//! ARAS-0064, where it is charged. A second local tally would be a second
//! source of truth that drifts the moment a request is retried, fails
//! mid-flight, or is billed by a path the CLI never saw — and the number an
//! operator is shown must be the number they were charged. So `usage` reports
//! what the connector says, and says so when it cannot reach it, rather than
//! quietly falling back to a local guess that would look authoritative.

use arcana_core::cost::CostSnapshot;

/// Convert integer micros to USD for display.
///
/// The precision-loss lint is allowed deliberately: a spend figure would have
/// to exceed ~9 billion dollars before an f64 mantissa could not represent it
/// exactly, and this value is only ever formatted for a human.
#[allow(clippy::cast_precision_loss)]
fn micros_to_usd(micros: u64) -> f64 {
    micros as f64 / MICROS_PER_USD
}

/// Micros per USD. Cost is tracked in integer micros to avoid float drift
/// accumulating across a long session.
const MICROS_PER_USD: f64 = 1_000_000.0;

/// The change in spend between two points in a session.
///
/// The session's `CostTracker` is shared across turns (so a session accrues
/// one running total), which means a raw snapshot is CUMULATIVE. Reporting
/// that as "this turn" would overstate every turn after the first, so the
/// per-turn line is a delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnSpend {
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd_micros: u64,
    pub calls: u64,
}

impl TurnSpend {
    /// Difference between a later and an earlier snapshot.
    ///
    /// Saturating rather than wrapping: a counter that appears to go backwards
    /// (a reset, a racing read) must report zero for the turn, not a number
    /// near `u64::MAX` that would look like a catastrophic charge.
    #[must_use]
    pub fn between(before: &CostSnapshot, after: &CostSnapshot) -> Self {
        Self {
            tokens_in: after.total_tokens_in.saturating_sub(before.total_tokens_in),
            tokens_out: after
                .total_tokens_out
                .saturating_sub(before.total_tokens_out),
            cost_usd_micros: after
                .total_cost_usd_micros
                .saturating_sub(before.total_cost_usd_micros),
            calls: after.total_calls.saturating_sub(before.total_calls),
        }
    }

    #[must_use]
    pub fn cost_usd(&self) -> f64 {
        micros_to_usd(self.cost_usd_micros)
    }
}

/// A zero snapshot — the session's starting point, before any turn has run.
#[must_use]
pub fn zero_snapshot() -> CostSnapshot {
    CostSnapshot {
        total_tokens_in: 0,
        total_tokens_out: 0,
        total_cost_usd_micros: 0,
        total_calls: 0,
    }
}

/// Render the per-turn spend line.
///
/// Six decimal places because a single cheap call can cost well under a cent,
/// and rounding it to `$0.00` would tell the operator their spend is free.
#[must_use]
pub fn turn_line(turn: &TurnSpend, session_total_micros: u64) -> String {
    format!(
        "[{} in / {} out tokens · ${:.6} this turn · ${:.6} session]",
        turn.tokens_in,
        turn.tokens_out,
        turn.cost_usd(),
        micros_to_usd(session_total_micros),
    )
}

/// One day of recorded usage, as the Model Connector reports it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DailyUsage {
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub requests: Option<u64>,
    #[serde(default)]
    pub total_tokens: Option<u64>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
}

/// `arcana usage` — report what the connector has recorded, and the balance.
///
/// Returns a process exit code. Reports the connector's numbers or an error;
/// it never falls back to a local tally, because a locally-computed figure
/// presented next to a balance would look authoritative while disagreeing with
/// what was actually charged.
#[must_use]
pub fn run_usage() -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana usage: failed to start async runtime: {err}");
            return 1;
        }
    };
    runtime.block_on(usage_async())
}

async fn usage_async() -> i32 {
    let Ok(token) = std::env::var("ARCANA_MC_TOKEN") else {
        eprintln!(
            "arcana usage: ARCANA_MC_TOKEN is not set. Usage is read from the Model Connector, \
             which is where spend is measured and charged — there is no local figure to show \
             instead."
        );
        return 1;
    };
    if token.trim().is_empty() {
        eprintln!("arcana usage: ARCANA_MC_TOKEN is empty");
        return 1;
    }
    let base = std::env::var("ARCANA_MC_BASE_URL")
        .ok()
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| "https://connector.arcanada.ai".to_owned());

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            eprintln!("arcana usage: could not build an HTTP client: {err}");
            return 1;
        }
    };

    let url = format!("{}/stats/requests/daily", base.trim_end_matches('/'));
    let resp = match client.get(&url).bearer_auth(&token).send().await {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("arcana usage: cannot reach the Model Connector at {base}: {err}");
            return 1;
        }
    };
    if !resp.status().is_success() {
        eprintln!(
            "arcana usage: the Model Connector returned HTTP {} for {url}",
            resp.status().as_u16()
        );
        return 1;
    }
    let days: Vec<DailyUsage> = match resp.json().await {
        Ok(days) => days,
        Err(err) => {
            eprintln!("arcana usage: the usage response could not be read: {err}");
            return 1;
        }
    };

    if days.is_empty() {
        println!("No recorded usage.");
        return 0;
    }

    let mut total_cost = 0.0;
    let mut total_tokens = 0u64;
    let mut total_requests = 0u64;
    println!(
        "{:<12} {:>9} {:>12} {:>12}",
        "DATE", "REQUESTS", "TOKENS", "COST USD"
    );
    for day in &days {
        let cost = day.cost_usd.unwrap_or(0.0);
        let tokens = day.total_tokens.unwrap_or(0);
        let requests = day.requests.unwrap_or(0);
        total_cost += cost;
        total_tokens += tokens;
        total_requests += requests;
        println!(
            "{:<12} {:>9} {:>12} {:>12.6}",
            day.date.as_deref().unwrap_or("-"),
            requests,
            tokens,
            cost
        );
    }
    println!(
        "{:<12} {:>9} {:>12} {:>12.6}",
        "TOTAL", total_requests, total_tokens, total_cost
    );
    println!("\nSource: Model Connector — the same records the account is charged against.");
    0
}

#[cfg(test)]
mod tests {
    use super::{turn_line, TurnSpend};
    use arcana_core::cost::CostSnapshot;

    fn snap(tin: u64, tout: u64, micros: u64, calls: u64) -> CostSnapshot {
        CostSnapshot {
            total_tokens_in: tin,
            total_tokens_out: tout,
            total_cost_usd_micros: micros,
            total_calls: calls,
        }
    }

    #[test]
    fn reports_the_delta_not_the_running_total() {
        // The session tracker is cumulative. Reporting it raw would bill every
        // turn after the first for everything that came before it.
        let before = snap(100, 50, 2_000, 1);
        let after = snap(180, 90, 3_500, 2);

        let turn = TurnSpend::between(&before, &after);

        assert_eq!(turn.tokens_in, 80);
        assert_eq!(turn.tokens_out, 40);
        assert_eq!(turn.cost_usd_micros, 1_500);
        assert_eq!(turn.calls, 1);
    }

    #[test]
    fn a_counter_going_backwards_reports_zero_not_a_huge_number() {
        // Saturating, not wrapping: an apparent reset must not render as a
        // charge of ~18 quintillion dollars.
        let turn = TurnSpend::between(&snap(500, 500, 9_000, 5), &snap(100, 100, 1_000, 1));
        assert_eq!(turn.cost_usd_micros, 0);
        assert_eq!(turn.tokens_in, 0);
    }

    #[test]
    fn sub_cent_spend_is_not_rounded_away_to_zero() {
        // A cheap call costs far less than a cent. Two decimals would print
        // $0.00 and tell the operator the agent is free.
        let turn = TurnSpend::between(&snap(0, 0, 0, 0), &snap(10, 5, 250, 1));
        let line = turn_line(&turn, 250);
        assert!(line.contains("0.000250"), "line was: {line}");
        assert!(
            !line.contains("$0.00 "),
            "sub-cent spend rounded away: {line}"
        );
    }

    #[test]
    fn the_line_shows_both_this_turn_and_the_session_total() {
        let turn = TurnSpend::between(&snap(0, 0, 1_000, 1), &snap(10, 5, 3_000, 2));
        let line = turn_line(&turn, 3_000);
        assert!(line.contains("0.002000"), "turn cost missing: {line}");
        assert!(line.contains("0.003000"), "session total missing: {line}");
    }
}
