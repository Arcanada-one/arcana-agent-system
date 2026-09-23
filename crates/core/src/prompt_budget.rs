//! The Model Connector request contract, written down once, in the unit the
//! server counts in.
//!
//! Model Connector validates `/execute` with Zod
//! (`model-connector src/connectors/dto/execute.dto.ts:53,55`):
//!
//! ```text
//! prompt:       z.string().min(1).max(100_000)
//! systemPrompt: z.string().max(100_000).optional()
//! ```
//!
//! Two independent ceilings, and the count is JavaScript's `String.length` —
//! **UTF-16 code units**, neither bytes nor Unicode scalar values. Measured
//! live against `connector.arcanada.ai` on 2026-09-23 (A2-205): a
//! `systemPrompt` of 50 001 `U+1F600` (50 001 scalar values, 100 002 UTF-16
//! units, 200 004 bytes) is rejected, while 34 000 `U+4E2D` (34 000 units,
//! 102 000 bytes) is accepted and generates. A budget kept in bytes is wrong
//! by a factor of three on Russian or Chinese text; a budget kept in `char`s
//! is wrong by a factor of two on emoji.
//!
//! Everything here is a pure function over a string so the guard that decides
//! what to drop and the code that fills the wire field measure the same thing.

/// Per-field ceiling Model Connector enforces on `prompt` and, separately, on
/// `systemPrompt`.
///
/// Exceeding it is an `HTTP 400 {"message":"Validation failed","errors":
/// ["prompt: Too big: expected string to have <=100000 characters"]}` — the
/// model is never reached and the run pays nothing but its own death. That is
/// what ended the 2026-09-23 pilot run at turn 10 with five tool calls of real
/// work already done.
pub const MC_FIELD_MAX_UTF16_UNITS: usize = 100_000;

/// The working ceiling the agent loop keeps a serialized transcript under.
///
/// Ten percent below the wall on purpose. The loop compacts down to this,
/// and [`MC_FIELD_MAX_UTF16_UNITS`] is then a wall nothing is expected to
/// touch — so a dispatch that does touch it is a defect in the guard, not a
/// budget that was set a little too high.
pub const DEFAULT_CONTEXT_BUDGET_UTF16_UNITS: usize = 90_000;

/// The most one tool result may contribute to the transcript.
///
/// Roughly 9% of the default window, which is the point: a single `git clone`,
/// `cargo test` or `find /` must not be able to evict the whole history that
/// explains why it was run. The output is not lost — it is spilled to disk and
/// the elision marker names the file, so a model that needs the rest asks for
/// the part of it that it needs.
pub const DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS: usize = 8_000;

/// Smallest elision this module will perform. Below it the marker would be a
/// larger share of the result than the text it introduces.
///
/// Public because a caller that lets an operator choose the tool-result budget
/// has to be able to refuse a number below it before the run starts:
/// [`elide_middle`] honours a smaller budget by returning the marker ALONE,
/// which is a silently useless setting rather than an error.
pub const MIN_ELISION_BUDGET: usize = 240;

/// Length of `text` in the unit Model Connector counts in.
#[must_use]
pub fn utf16_units(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// True when `text` fits a field of `limit` UTF-16 units.
///
/// Short-circuits: a 40 MB tool output must not be walked in full to learn
/// that its first 100 001 units already overflow.
#[must_use]
pub fn fits(text: &str, limit: usize) -> bool {
    let mut units = 0usize;
    for ch in text.chars() {
        units += ch.len_utf16();
        if units > limit {
            return false;
        }
    }
    true
}

/// The longest prefix of `text` that fits `units` UTF-16 units, cut on a
/// character boundary.
#[must_use]
pub fn prefix_within(text: &str, units: usize) -> &str {
    let mut used = 0usize;
    for (offset, ch) in text.char_indices() {
        let next = used + ch.len_utf16();
        if next > units {
            return &text[..offset];
        }
        used = next;
    }
    text
}

/// The longest suffix of `text` that fits `units` UTF-16 units, cut on a
/// character boundary.
#[must_use]
pub fn suffix_within(text: &str, units: usize) -> &str {
    let mut used = 0usize;
    let mut start = text.len();
    for (offset, ch) in text.char_indices().rev() {
        let next = used + ch.len_utf16();
        if next > units {
            break;
        }
        used = next;
        start = offset;
    }
    &text[start..]
}

/// Keep the head and the tail of `text` and say, in the middle, exactly how
/// much was removed and where the rest still is.
///
/// Head and tail rather than a plain truncation because the two ends are what
/// a tool result is read for: the command and its first lines at the top, the
/// error and the exit status at the bottom. Cutting only the tail throws away
/// the half that usually decides the next move.
///
/// `source`, when given, is the path — relative to the workspace, so the model
/// may open it — where the untouched output was kept. The marker is written as
/// a fact about the machine, not as an apology, and it names a next action,
/// because a model that is not told the output still exists will re-run the
/// command instead.
///
/// The returned string is guaranteed to fit `budget` UTF-16 units whenever
/// `budget >= MIN_ELISION_BUDGET`; below that the marker alone is returned,
/// because a smaller result could not honestly describe itself.
#[must_use]
pub fn elide_middle(text: &str, budget: usize, source: Option<&str>) -> String {
    if fits(text, budget) {
        return text.to_owned();
    }
    let total = utf16_units(text);
    // The marker states the elided count, and its own length depends on that
    // count, which depends on how much the marker leaves room for. Two rounds
    // settle it: the second is computed from the first round's real marker.
    let mut keep = budget.saturating_sub(marker(total, source).len());
    for _ in 0..3 {
        if keep < MIN_ELISION_BUDGET {
            break;
        }
        let head = prefix_within(text, keep * 2 / 3);
        let tail = suffix_within(text, keep - utf16_units(head));
        let elided = total.saturating_sub(utf16_units(head) + utf16_units(tail));
        let note = marker(elided, source);
        let assembled = utf16_units(head) + utf16_units(&note) + utf16_units(tail);
        if assembled <= budget {
            return format!("{head}{note}{tail}");
        }
        keep = keep.saturating_sub(assembled - budget);
    }
    let note = marker(total, source);
    if fits(&note, budget) {
        note
    } else {
        prefix_within(&note, budget).to_owned()
    }
}

/// The elision marker. One line, addressed to the model.
fn marker(elided: usize, source: Option<&str>) -> String {
    match source {
        Some(path) => format!(
            "\n[... {elided} characters (UTF-16 units) elided by the runner to fit the request \
budget. The COMPLETE output of this call is on disk at `{path}` — read the part of it you need \
with a tool call rather than running the command again ...]\n"
        ),
        None => format!(
            "\n[... {elided} characters (UTF-16 units) elided by the runner to fit the request \
budget. Re-run a narrower version of this call if you need the part that is missing ...]\n"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn units_are_utf16_not_bytes_and_not_scalar_values() {
        // The three probes A2-205 ran against production, as arithmetic.
        let emoji = "\u{1F600}".repeat(50_001);
        assert_eq!(emoji.chars().count(), 50_001, "scalar values");
        assert_eq!(utf16_units(&emoji), 100_002, "UTF-16 units — over the wall");
        assert_eq!(emoji.len(), 200_004, "bytes");
        assert!(!fits(&emoji, MC_FIELD_MAX_UTF16_UNITS));

        let han = "\u{4E2D}".repeat(34_000);
        assert_eq!(utf16_units(&han), 34_000);
        assert_eq!(han.len(), 102_000, "over 100 000 bytes, and accepted live");
        assert!(fits(&han, MC_FIELD_MAX_UTF16_UNITS));
    }

    #[test]
    fn prefix_and_suffix_never_split_a_character() {
        let text = "a\u{1F600}b";
        // 1 + 2 + 1 units: a two-unit boundary cannot be half-taken.
        assert_eq!(prefix_within(text, 2), "a");
        assert_eq!(prefix_within(text, 3), "a\u{1F600}");
        assert_eq!(suffix_within(text, 2), "b");
        assert_eq!(suffix_within(text, 3), "\u{1F600}b");
    }

    #[test]
    fn an_elided_result_fits_its_budget_and_keeps_both_ends() {
        let text = format!("HEAD-MARKER{}TAIL-MARKER", "x".repeat(60_000));
        let out = elide_middle(&text, 4_000, Some(".arcana/tool-output/007-bash.txt"));
        assert!(
            utf16_units(&out) <= 4_000,
            "elided result is {} units",
            utf16_units(&out)
        );
        assert!(out.starts_with("HEAD-MARKER"), "the head is kept");
        assert!(out.ends_with("TAIL-MARKER"), "the tail is kept");
        assert!(out.contains("characters (UTF-16 units) elided"));
        assert!(
            out.contains(".arcana/tool-output/007-bash.txt"),
            "the marker names where the full output still is"
        );
    }

    #[test]
    fn text_within_budget_is_returned_untouched() {
        assert_eq!(elide_middle("short", 4_000, None), "short");
    }

    #[test]
    fn a_multibyte_result_is_elided_to_a_valid_string_within_budget() {
        let text = "\u{1F600}".repeat(50_000);
        let out = elide_middle(&text, 1_000, None);
        assert!(utf16_units(&out) <= 1_000);
        assert!(out.contains("elided"));
    }

    #[test]
    fn a_budget_too_small_for_a_marker_still_fits() {
        let text = "y".repeat(10_000);
        let out = elide_middle(&text, 40, None);
        assert!(utf16_units(&out) <= 40, "got {} units", utf16_units(&out));
    }
}
