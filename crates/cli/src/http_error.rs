//! One place that turns a non-2xx Model Connector response into something a
//! user can act on.
//!
//! `models` and `usage` each carry their own `reqwest` client, separate from
//! `ModelConnectorClient`, and each collapsed every failure into the numeric
//! status alone. A 401, a 402, a 429 and a 503 rendered identically apart from
//! the number, while the body — which said things like `Insufficient credit:
//! balance 0.00 USD` — was read and discarded, and `Retry-After` was never
//! looked at.
//!
//! Two commands doing this the same wrong way is why it lives here rather than
//! being fixed twice: the next command to grow its own client gets the
//! behaviour for free.

/// Longest body excerpt echoed back. Enough for a sentence; short enough that
/// an HTML error page or a stack trace cannot flood the terminal.
const MAX_BODY_CHARS: usize = 300;

/// Render a non-2xx response as `HTTP <code> for <url>: <detail>`.
///
/// Consumes the response because the body has to be read to be reported — the
/// discarding of which is the defect this exists to fix.
pub async fn describe(url: &str, resp: reqwest::Response) -> String {
    let code = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = resp.text().await.unwrap_or_default();
    let detail = detail_from_body(&body);

    let mut out = format!("the Model Connector returned HTTP {code} for {url}");
    if let Some(detail) = detail {
        out.push_str(": ");
        out.push_str(&detail);
    }
    if let Some(retry) = retry_after {
        // Surfaced explicitly: a 429 whose Retry-After is dropped leaves the
        // caller guessing at the one number the server actually supplied.
        use std::fmt::Write as _;
        let _ = write!(out, " (retry after {}s)", retry.trim());
    }
    out
}

/// Pull the human-readable part out of a response body.
///
/// Two shapes matter here, and the difference is not cosmetic.
///
/// `NestJS` answers `{"message": ..., "error": ..., "statusCode": N}`, where
/// `message` is a string for most failures and an ARRAY of strings for a
/// validation failure.
///
/// The Model Connector's own validation pipe answers
/// `{"message": "Validation failed", "errors": [...]}` — a summary string plus
/// a SEPARATE array. Reading only `message` there yields "Validation failed"
/// and silently drops the list naming which parameters were wrong, which is the
/// entire actionable content. Both are handled, and both are joined on.
fn detail_from_body(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    let text = serde_json::from_str::<serde_json::Value>(trimmed)
        .ok()
        .and_then(|v| message_field(&v))
        .unwrap_or_else(|| trimmed.to_owned());
    Some(truncate(&collapse_whitespace(&text)))
}

fn message_field(value: &serde_json::Value) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(text) = string_or_array(value.get("message")) {
        parts.push(text);
    }
    // The Model Connector puts the per-field detail here, beside a generic
    // `message`. Appended rather than preferred, so the summary keeps its
    // context and the specifics are not lost.
    if let Some(text) = string_or_array(value.get("errors")) {
        parts.push(text);
    }
    (!parts.is_empty()).then(|| parts.join(": "))
}

fn string_or_array(value: Option<&serde_json::Value>) -> Option<String> {
    match value {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(serde_json::Value::Array(items)) => {
            let joined: Vec<String> = items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect();
            (!joined.is_empty()).then(|| joined.join("; "))
        }
        _ => None,
    }
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_BODY_CHARS {
        return text.to_owned();
    }
    let head: String = text.chars().take(MAX_BODY_CHARS).collect();
    format!("{head}…")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{collapse_whitespace, detail_from_body, truncate, MAX_BODY_CHARS};

    #[test]
    fn a_nest_envelope_yields_its_message() {
        let body = r#"{"message":"Insufficient credit: balance 0.00 USD","error":"Payment Required","statusCode":402}"#;
        assert_eq!(
            detail_from_body(body).unwrap(),
            "Insufficient credit: balance 0.00 USD"
        );
    }

    #[test]
    fn a_validation_array_keeps_every_field_it_names() {
        // The array form is the one that says WHICH parameters were wrong.
        // Dropping it is how a 400 becomes an unactionable number.
        let body =
            r#"{"message":["since must not be empty","until must not be empty"],"statusCode":400}"#;
        let detail = detail_from_body(body).unwrap();
        assert!(detail.contains("since must not be empty"), "{detail}");
        assert!(detail.contains("until must not be empty"), "{detail}");
    }

    #[test]
    fn the_connectors_separate_errors_array_is_not_dropped() {
        // The real 400 from the stats route: a generic `message` beside an
        // `errors` array that names the parameters. Reading only `message`
        // yields "Validation failed" and loses everything actionable.
        let body = r#"{"message":"Validation failed","errors":["since: Invalid input: expected string, received undefined","until: Invalid input: expected string, received undefined"]}"#;
        let detail = detail_from_body(body).unwrap();
        assert!(detail.contains("Validation failed"), "{detail}");
        assert!(detail.contains("since: Invalid input"), "{detail}");
        assert!(detail.contains("until: Invalid input"), "{detail}");
    }

    #[test]
    fn a_non_json_body_is_reported_verbatim() {
        assert_eq!(
            detail_from_body("upstream connect error").unwrap(),
            "upstream connect error"
        );
    }

    #[test]
    fn an_empty_body_adds_nothing() {
        assert!(detail_from_body("").is_none());
        assert!(detail_from_body("   \n ").is_none());
    }

    #[test]
    fn an_html_error_page_cannot_flood_the_terminal() {
        let body = format!("<html>{}</html>", "x".repeat(5_000));
        let detail = detail_from_body(&body).unwrap();
        assert!(
            detail.chars().count() <= MAX_BODY_CHARS + 1,
            "{}",
            detail.len()
        );
        assert!(detail.ends_with('…'));
    }

    #[test]
    fn multiline_bodies_are_flattened_onto_one_line() {
        assert_eq!(collapse_whitespace("a\n  b\t c"), "a b c");
    }

    #[test]
    fn truncate_leaves_short_text_alone() {
        assert_eq!(truncate("short"), "short");
    }
}
