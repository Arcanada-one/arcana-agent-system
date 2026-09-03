//! Spend reporting.
//!
//! Two surfaces: the per-turn line the interactive session prints, and
//! `arcana usage`, which reports what the Model Connector has actually
//! recorded.
//!
//! ## Why `usage` asks the connector instead of adding up locally
//!
//! The connector is where money is measured (`Request.costUsd`) and, since
//!, where it is charged. A second local tally would be a second
//! source of truth that drifts the moment a request is retried, fails
//! mid-flight, or is billed by a path the CLI never saw — and the number an
//! operator is shown must be the number they were charged. So `usage` reports
//! what the connector says, and says so when it cannot reach it, rather than
//! quietly falling back to a local guess that would look authoritative.

use std::fmt::Write as _;

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

/// One row of recorded usage, exactly as `GET /stats/requests/daily` returns it.
///
/// The route aggregates by (connector, model, day), so a single day arrives as
/// MANY rows — one per model that was called. `usage` folds them back together
/// for the per-day table.
///
/// ## Why most fields are required
///
/// The previous shape of this struct declared `date`, `total_tokens` and
/// `cost_usd`, all `#[serde(default)]`, against a wire format that sends `day`,
/// `totalTokens` and `costUsd`. Nothing matched except `requests`, and because
/// every field defaulted, serde reported success and the table rendered `-`
/// dates with zero tokens and zero cost. A silent wrong answer about money.
///
/// So the fields the report is actually built from carry no `default`: if the
/// contract moves again, the decode fails loudly and says which field, instead
/// of printing a confident table of zeroes.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyUsageRow {
    pub connector: String,
    /// Null for rows the connector could not attribute to a model.
    #[serde(default)]
    pub model: Option<String>,
    /// An ISO-8601 instant at UTC midnight, e.g. `2026-08-24T00:00:00.000Z`.
    pub day: String,
    pub requests: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
}

impl DailyUsageRow {
    /// The calendar-date prefix of `day`, for grouping and display.
    fn date(&self) -> &str {
        self.day.get(..10).unwrap_or(self.day.as_str())
    }
}

/// The report window, as the two ISO dates the route requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageWindow {
    pub since: String,
    pub until: String,
}

/// Default report span, in days, inclusive of both endpoints.
const DEFAULT_WINDOW_DAYS: i64 = 30;

/// The server refuses a wider window (`src/stats/dto.ts`, threat T9). Checking
/// it here too means an over-wide `--since` is answered with a sentence naming
/// the limit, rather than with a bare HTTP 400 from the far side.
const MAX_WINDOW_DAYS: i64 = 92;

/// Days since the Unix epoch to a civil date. Howard Hinnant's `civil_from_days`,
/// exact for the whole proleptic Gregorian range.
#[allow(
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let d = i64::from(d);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Today's date at UTC, as days since the epoch.
#[allow(clippy::cast_possible_wrap)]
fn today_utc_days() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs as i64) / 86_400
}

fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parse a strict `YYYY-MM-DD`, rejecting anything the server would reject.
///
/// Round-tripping through [`days_from_civil`] is what catches a well-formed but
/// non-existent date such as `2026-02-30`, which a naive field-range check
/// accepts and the server refuses.
fn parse_iso_date(value: &str, flag: &str) -> Result<i64, String> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !shaped {
        return Err(format!(
            "--{flag} must be a calendar date in YYYY-MM-DD form (got {value:?})"
        ));
    }
    let y: i64 = value[0..4].parse().map_err(|_| {
        format!("--{flag} must be a calendar date in YYYY-MM-DD form (got {value:?})")
    })?;
    let m: u32 = value[5..7].parse().map_err(|_| {
        format!("--{flag} must be a calendar date in YYYY-MM-DD form (got {value:?})")
    })?;
    let d: u32 = value[8..10].parse().map_err(|_| {
        format!("--{flag} must be a calendar date in YYYY-MM-DD form (got {value:?})")
    })?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(format!("--{flag} is not a real calendar date: {value}"));
    }
    let days = days_from_civil(y, m, d);
    if civil_from_days(days) != (y, m, d) {
        return Err(format!("--{flag} is not a real calendar date: {value}"));
    }
    Ok(days)
}

/// Resolve the window to send, from whatever the user supplied.
///
/// `today` is a parameter rather than read from the clock so the defaults are
/// testable; callers pass [`today_utc_days`].
///
/// # Errors
/// Returns a message ready to print when a date is malformed, the window runs
/// backwards, or it exceeds the server's cap.
pub fn resolve_window(
    since: Option<&str>,
    until: Option<&str>,
    today: i64,
) -> Result<UsageWindow, String> {
    let until_days = match until {
        Some(value) => parse_iso_date(value, "until")?,
        None => today,
    };
    let since_days = match since {
        Some(value) => parse_iso_date(value, "since")?,
        // Inclusive of both endpoints, so a 30-day report spans today and the
        // 29 days before it.
        None => until_days - (DEFAULT_WINDOW_DAYS - 1),
    };

    if since_days > until_days {
        return Err(format!(
            "the window runs backwards: --since {} is after --until {}",
            format_date(since_days),
            format_date(until_days)
        ));
    }
    let span = until_days - since_days;
    if span > MAX_WINDOW_DAYS {
        return Err(format!(
            "the window is {span} days wide; the Model Connector accepts at most \
             {MAX_WINDOW_DAYS}. Narrow it with --since / --until."
        ));
    }

    Ok(UsageWindow {
        since: format_date(since_days),
        until: format_date(until_days),
    })
}

/// One printed line of the report: everything charged on a single UTC day.
#[derive(Debug, Clone, PartialEq)]
pub struct DayTotal {
    pub date: String,
    pub requests: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
}

/// The folded report: one [`DayTotal`] per day in ascending date order, plus
/// the grand total across the window.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageReport {
    pub days: Vec<DayTotal>,
    pub total: DayTotal,
}

/// Fold the per-(connector, model, day) rows into one line per day.
#[must_use]
pub fn fold_by_day(rows: &[DailyUsageRow]) -> UsageReport {
    let mut by_day: std::collections::BTreeMap<&str, DayTotal> = std::collections::BTreeMap::new();
    for row in rows {
        let entry = by_day.entry(row.date()).or_insert_with(|| DayTotal {
            date: row.date().to_owned(),
            requests: 0,
            total_tokens: 0,
            cost_usd: 0.0,
        });
        entry.requests += row.requests;
        entry.total_tokens += row.total_tokens;
        entry.cost_usd += row.cost_usd;
    }
    let mut total = DayTotal {
        date: "TOTAL".to_owned(),
        requests: 0,
        total_tokens: 0,
        cost_usd: 0.0,
    };
    let days: Vec<DayTotal> = by_day.into_values().collect();
    for day in &days {
        total.requests += day.requests;
        total.total_tokens += day.total_tokens;
        total.cost_usd += day.cost_usd;
    }
    UsageReport { days, total }
}

/// `arcana usage` — report what the connector has recorded.
///
/// Returns a process exit code. Reports the connector's numbers or an error;
/// it never falls back to a local tally, because a locally-computed figure
/// presented next to a balance would look authoritative while disagreeing with
/// what was actually charged.
#[must_use]
pub fn run_usage(since: Option<&str>, until: Option<&str>) -> i32 {
    let window = match resolve_window(since, until, today_utc_days()) {
        Ok(window) => window,
        Err(message) => {
            eprintln!("arcana usage: {message}");
            return 2;
        }
    };
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
    runtime.block_on(usage_async(&window))
}

async fn usage_async(window: &UsageWindow) -> i32 {
    // CONN-0272 follow-up: this route is purpose-scoped. `StatsReadGuard` reads
    // only `x-stats-token` and its docstring is explicit that it must never
    // accept ADMIN_TOKEN or an inference ApiKey — so `ARCANA_MC_TOKEN`, which is
    // an inference key sent as a bearer token, was refused twice over.
    let Ok(token) = std::env::var("ARCANA_STATS_TOKEN") else {
        eprintln!(
            "arcana usage: ARCANA_STATS_TOKEN is not set. Usage is read from the Model \
             Connector, which is where spend is measured and charged — there is no local \
             figure to show instead. This route is purpose-scoped and accepts only that \
             token; an inference key (ARCANA_MC_TOKEN) is refused by design."
        );
        return 1;
    };
    if token.trim().is_empty() {
        eprintln!("arcana usage: ARCANA_STATS_TOKEN is empty");
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
    // `since` and `until` are REQUIRED by the route. Omitting them — which this
    // command did for its whole life — is an unconditional HTTP 400.
    //
    // Interpolated rather than form-encoded: `resolve_window` has already
    // proved both values are exactly `YYYY-MM-DD`, ten ASCII characters with no
    // byte that means anything in a query string, so there is nothing to escape.
    let requested = format!("{url}?since={}&until={}", window.since, window.until);
    let resp = match client
        .get(&requested)
        .header("x-stats-token", &token)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("arcana usage: cannot reach the Model Connector at {base}: {err}");
            return 1;
        }
    };
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let described = crate::http_error::describe(&requested, resp).await;
        eprintln!(
            "arcana usage: {described} (since={}, until={})",
            window.since, window.until
        );
        if code == 403 {
            // The guard denies before reading the request when the server has no
            // token configured, so a correct client still sees 403. Saying so
            // saves the next reader from debugging their own credential.
            eprintln!(
                "  403 here means either ARCANA_STATS_TOKEN does not match the \
server's STATS_READ_TOKEN, or the server has none configured at all (the guard \
denies with reason=no-expected-token before reading the request)."
            );
        }
        return 1;
    }
    let rows: Vec<DailyUsageRow> = match resp.json().await {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("arcana usage: the usage response could not be read: {err}");
            return 1;
        }
    };

    let report = fold_by_day(&rows);

    // One checked write for the same reason `models` does it: a 30-day table is
    // long enough to pipe, and `println!` panics on a closed reader.
    let mut page = String::new();
    let _ = writeln!(
        page,
        "Usage from {} to {} (UTC).",
        window.since, window.until
    );
    if report.days.is_empty() {
        let _ = writeln!(page, "No recorded usage in this window.");
        return crate::out::write_all(&page);
    }

    let _ = writeln!(
        page,
        "{:<12} {:>9} {:>12} {:>12}",
        "DATE", "REQUESTS", "TOKENS", "COST USD"
    );
    for day in &report.days {
        let _ = writeln!(
            page,
            "{:<12} {:>9} {:>12} {:>12.6}",
            day.date, day.requests, day.total_tokens, day.cost_usd
        );
    }
    let _ = writeln!(
        page,
        "{:<12} {:>9} {:>12} {:>12.6}",
        report.total.date, report.total.requests, report.total.total_tokens, report.total.cost_usd
    );
    let _ = writeln!(
        page,
        "\nSource: Model Connector — the same records the account is charged against."
    );
    crate::out::write_all(&page)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        civil_from_days, days_from_civil, fold_by_day, resolve_window, turn_line, DailyUsageRow,
        TurnSpend,
    };
    use arcana_core::cost::CostSnapshot;

    /// 2026-08-31, as days since the epoch. Fixed so the default-window tests
    /// do not change meaning tomorrow.
    const TODAY: i64 = 20_696;

    fn row(day: &str, model: &str, requests: u64, tokens: u64, cost: f64) -> DailyUsageRow {
        DailyUsageRow {
            connector: "orq".to_owned(),
            model: Some(model.to_owned()),
            day: day.to_owned(),
            requests,
            total_tokens: tokens,
            cost_usd: cost,
        }
    }

    #[test]
    fn the_fixed_today_constant_is_the_date_it_claims() {
        assert_eq!(civil_from_days(TODAY), (2026, 8, 31));
        assert_eq!(days_from_civil(2026, 8, 31), TODAY);
    }

    #[test]
    fn civil_date_conversion_round_trips_across_boundaries() {
        // Epoch, a leap day, a century non-leap year, and a 400-year leap year.
        for (y, m, d) in [
            (1970, 1, 1),
            (2024, 2, 29),
            (1900, 3, 1),
            (2000, 2, 29),
            (2026, 12, 31),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "round trip {y}-{m}-{d}");
        }
    }

    #[test]
    fn the_default_window_is_thirty_days_ending_today() {
        // The whole defect: this command sent no window at all, and the route
        // requires one. The default has to be a real, inclusive 30 days.
        let window = resolve_window(None, None, TODAY).expect("defaults are valid");
        assert_eq!(window.until, "2026-08-31");
        assert_eq!(window.since, "2026-08-02");
        assert_eq!(
            days_from_civil(2026, 8, 31) - days_from_civil(2026, 8, 2) + 1,
            30
        );
    }

    #[test]
    fn an_explicit_since_keeps_until_at_today() {
        let window = resolve_window(Some("2026-08-29"), None, TODAY).expect("valid");
        assert_eq!(window.since, "2026-08-29");
        assert_eq!(window.until, "2026-08-31");
    }

    #[test]
    fn a_backwards_window_is_refused_before_the_request_is_sent() {
        let err = resolve_window(Some("2026-08-31"), Some("2026-08-01"), TODAY)
            .expect_err("backwards window must be refused");
        assert!(err.contains("runs backwards"), "{err}");
    }

    #[test]
    fn a_window_wider_than_the_server_cap_is_refused_locally() {
        // The server caps at 92 days. Refusing here turns a bare HTTP 400 into
        // a sentence that names the limit.
        let err = resolve_window(Some("2026-01-01"), Some("2026-08-31"), TODAY)
            .expect_err("over-wide window must be refused");
        assert!(err.contains("92"), "{err}");
    }

    #[test]
    fn exactly_the_cap_is_allowed() {
        let since = super::format_date(TODAY - 92);
        resolve_window(Some(&since), None, TODAY).expect("92 days is within the cap");
    }

    #[test]
    fn a_date_that_does_not_exist_is_refused() {
        // Shape-valid but not a real day. The server rejects it, so the client
        // must too, and must say which flag.
        let err = resolve_window(Some("2026-02-30"), None, TODAY).expect_err("Feb 30 is not real");
        assert!(err.contains("--since"), "{err}");
        assert!(err.contains("not a real calendar date"), "{err}");
    }

    #[test]
    fn a_malformed_date_names_the_flag_it_came_from() {
        let err = resolve_window(None, Some("31/08/2026"), TODAY).expect_err("wrong format");
        assert!(err.contains("--until"), "{err}");
        assert!(err.contains("YYYY-MM-DD"), "{err}");
    }

    #[test]
    fn rows_are_deserialized_from_the_shape_the_route_actually_sends() {
        // Captured from GET /stats/requests/daily. The previous struct read
        // `date`/`total_tokens`/`cost_usd` against this body and, because every
        // field defaulted, decoded "successfully" into all zeroes.
        let body = r#"[{"connector":"orq","model":"grok-3-latest",
            "day":"2026-08-31T00:00:00.000Z","requests":8,"inputTokens":1629,
            "outputTokens":168,"totalTokens":1797,"costUsd":0.007407}]"#;
        let rows: Vec<DailyUsageRow> = serde_json::from_str(body).expect("real body must decode");
        assert_eq!(rows[0].requests, 8);
        assert_eq!(rows[0].total_tokens, 1797);
        assert!((rows[0].cost_usd - 0.007_407).abs() < 1e-9);
        assert_eq!(rows[0].date(), "2026-08-31");
    }

    #[test]
    fn a_body_missing_a_report_field_fails_loudly_instead_of_reading_as_zero() {
        // The regression guard. `costUsd` renamed or dropped must be an error,
        // never a table showing $0.000000.
        let body = r#"[{"connector":"orq","model":"m","day":"2026-08-31T00:00:00.000Z",
            "requests":1,"totalTokens":10}]"#;
        assert!(serde_json::from_str::<Vec<DailyUsageRow>>(body).is_err());
    }

    #[test]
    fn many_model_rows_fold_into_one_line_per_day() {
        // The route aggregates by (connector, model, day), so one day arrives
        // as many rows. Printing them raw would show the same date repeatedly
        // and no day total.
        let rows = vec![
            row("2026-08-30T00:00:00.000Z", "grok-3-latest", 2, 100, 0.001),
            row("2026-08-31T00:00:00.000Z", "grok-3-latest", 3, 200, 0.002),
            row(
                "2026-08-31T00:00:00.000Z",
                "deepseek-v4-flash",
                5,
                300,
                0.004,
            ),
        ];
        let report = fold_by_day(&rows);
        assert_eq!(report.days.len(), 2, "two distinct days");
        assert_eq!(report.days[0].date, "2026-08-30");
        assert_eq!(report.days[1].date, "2026-08-31");
        assert_eq!(report.days[1].requests, 8);
        assert_eq!(report.days[1].total_tokens, 500);
        assert!((report.days[1].cost_usd - 0.006).abs() < 1e-9);
        assert_eq!(report.total.requests, 10);
        assert_eq!(report.total.total_tokens, 600);
        assert!((report.total.cost_usd - 0.007).abs() < 1e-9);
    }

    #[test]
    fn folding_nothing_yields_no_days_and_zero_totals() {
        let report = fold_by_day(&[]);
        assert!(report.days.is_empty());
        assert_eq!(report.total.requests, 0);
        assert_eq!(report.total.total_tokens, 0);
        assert!(report.total.cost_usd.abs() < f64::EPSILON);
    }

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
