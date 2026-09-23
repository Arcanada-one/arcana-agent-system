//! Recognising a tool call the model did not write in this runner's format.
//!
//! The driver publishes exactly one encoding — a fenced ```` ```tool_call ````
//! block (see [`crate::agent_loop::interpret`]) — and every model is told so in
//! the system prompt. Models trained to emit a native tool-call markup do not
//! always comply. Measured 2026-09-23 on `deepseek-v4-flash` through Model
//! Connector, the first turn of a real task came back as `DeepSeek`'s own
//! markup:
//!
//! ```text
//! <｜｜`DSML`｜｜ calls>
//! <｜｜`DSML`｜｜ invoke name="bash">
//! <｜｜`DSML`｜｜ parameter name="command" string="true">ls -la</｜｜`DSML`｜｜ parameter>
//! </｜｜`DSML`｜｜ invoke>
//! </｜｜`DSML`｜｜ calls>
//! ```
//!
//! The loop read that as prose and ended the run `{"completed":true,
//! "reason":"Completed","tool_calls":2}` — a success receipt for a task where
//! nothing ran (`/home/dev/aup/arc2/runs/A2-204c/log`). The model asked for a
//! shell command in the only way it knew; the runner answered by calling the
//! job finished.
//!
//! This module is the second reader: whatever the canonical fence did not
//! yield, it inspects for a tool-call attempt in a dialect we know about, and
//! reports one of two things.
//!
//! * [`DialectMatch::Call`] — the attempt is unambiguous and complete, so it is
//!   translated into the canonical call. Only `DSML`/`invoke` markup reaches this
//!   arm: its tags exist for no other purpose, so finding a closed one is not a
//!   guess about intent.
//! * [`DialectMatch::Attempt`] — the attempt is recognisable but not something
//!   we are willing to dispatch. The driver folds a correction back to the
//!   model naming the expected format, bounded, and nothing executes.
//!
//! The split is deliberate and conservative: translating is a decision to run a
//! command on the operator's machine, so it is reserved for markup that cannot
//! plausibly be prose. A bare JSON object shaped like an `OpenAI` tool call is
//! the other common near-miss, and it *can* appear inside an explanation of
//! tool calling — so it is corrected, never executed.

use serde_json::{Map, Value};

/// Keys a model may put its arguments under, in the order they are believed.
///
/// `input` is this runner's own name. `arguments` is `OpenAI`'s (and therefore
/// nearly every `OpenAI`-compatible provider's), `parameters` is what the JSON
/// Schema word for the same thing leaks into, and `args` is the short form
/// smaller models fall back on. They are alternatives for one slot, so the
/// first one actually present wins rather than being merged.
const INPUT_KEYS: [&str; 4] = ["input", "arguments", "parameters", "args"];

/// Label for the `DSML` / `invoke` markup dialect, used in operator output and
/// in the correction handed back to the model.
pub const DSML_DIALECT: &str = "DeepSeek `invoke` markup";
/// Label for a bare JSON object shaped like an `OpenAI` tool call.
pub const OPENAI_JSON_DIALECT: &str = "a bare OpenAI-style JSON tool call";

/// The sentinel `DeepSeek` wraps its markup tag names in.
///
/// Fullwidth vertical lines (U+FF5C), not ASCII pipes — the point of the
/// sentinel is that it cannot occur in ordinary text or in a shell command.
/// Stripping it turns `<｜｜`DSML`｜｜ invoke name="bash">` into `<invoke
/// name="bash">`, which is also exactly the markup Anthropic-trained models
/// emit, so one parser serves both dialects.
const DSML_SENTINEL: &str = "｜｜DSML｜｜ ";

/// What a scan for a non-canonical tool call found.
#[derive(Debug, Clone, PartialEq)]
pub enum DialectMatch {
    /// A complete call in a dialect unambiguous enough to translate and run.
    Call {
        /// Human-readable dialect name, for operator output.
        dialect: &'static str,
        /// The tool the model named.
        name: String,
        /// The arguments, as this runner's `input` object.
        input: Value,
    },
    /// A recognisable attempt that is NOT dispatched: the model is told the
    /// expected format instead.
    Attempt {
        /// Human-readable dialect name, for the correction and the log line.
        dialect: &'static str,
        /// What specifically made it uncallable, phrased for the model.
        detail: String,
    },
}

/// Scan a reply for a tool-call attempt outside the canonical fence.
///
/// `None` means nothing in the reply looks like a tool call, and the caller
/// should treat it as an ordinary answer. This function never executes
/// anything; a returned [`DialectMatch::Call`] still goes through the whole
/// permission cascade downstream, exactly like a canonical one.
#[must_use]
pub fn recognise(reply: &str) -> Option<DialectMatch> {
    invoke_markup(reply).or_else(|| openai_style_json(reply))
}

/// Read the arguments out of a parsed tool-call object.
///
/// Returns `None` only when the object carries no argument key at all. The
/// former reader was `value.get("input").cloned().unwrap_or(Value::Null)`,
/// which silently turned an `OpenAI`-shaped `{"name": …, "arguments": {…}}` into
/// a call with **no arguments** — a `bash` with no command, dispatched and
/// refused, with the model never told that what it sent had been thrown away.
#[must_use]
pub fn arguments_of(value: &Value) -> Option<Value> {
    for key in INPUT_KEYS {
        match value.get(key) {
            // An explicit `null` is not an answer; keep looking for a key that
            // carries something, and fall through to `None` if none does.
            None | Some(Value::Null) => {}
            Some(found) => return Some(decode_arguments(found)),
        }
    }
    None
}

/// Unwrap the `OpenAI` convention of sending arguments as a JSON-encoded string.
///
/// `{"arguments": "{\"command\":\"ls\"}"}` is what the `OpenAI` wire format
/// specifies, and models that learned it write it here too. Only an object
/// survives the unwrap: a string that happens to parse as `5` or `true` is far
/// more likely to be the argument itself than an encoded payload.
fn decode_arguments(value: &Value) -> Value {
    if let Value::String(text) = value {
        if let Ok(decoded) = serde_json::from_str::<Value>(text) {
            if decoded.is_object() {
                return decoded;
            }
        }
    }
    value.clone()
}

// ---------------------------------------------------------------------------
// DSML / `invoke` markup
// ---------------------------------------------------------------------------

/// Parse `DeepSeek` `DSML` markup, or the sentinel-less `<invoke>` form.
fn invoke_markup(reply: &str) -> Option<DialectMatch> {
    // Strip the sentinel first so one parser covers both spellings. The
    // replacement only ever shortens the text, and every value we return is
    // owned, so no offset from here escapes into the caller's string.
    let text = reply.replace(DSML_SENTINEL, "");
    let open = text.find("<invoke")?;
    let block = text.get(open..)?;
    let attempt = |detail: &str| {
        Some(DialectMatch::Attempt {
            dialect: DSML_DIALECT,
            detail: detail.to_owned(),
        })
    };
    let Some(head_end) = block.find('>') else {
        return attempt("the `invoke` tag was opened and never closed");
    };
    // The head is searched for `name=` rather than the whole block, so a
    // parameter value containing `name="…"` cannot be mistaken for the tool.
    let Some(head) = block.get(..head_end) else {
        return attempt("the `invoke` tag could not be read");
    };
    let Some(name) = attribute(head, "name") else {
        return attempt("the `invoke` tag carried no `name` attribute, so no tool was named");
    };
    let Some(close) = block.find("</invoke>") else {
        return attempt(
            "the `invoke` block was never closed with `</invoke>`, so the call is incomplete",
        );
    };
    // `close` indexes the same slice as `head_end`; an end tag that precedes
    // the head's own `>` means the markup is tangled, not a call.
    let Some(body) = block.get(head_end + 1..close) else {
        return attempt("the `invoke` block is malformed and its parameters could not be read");
    };
    Some(DialectMatch::Call {
        dialect: DSML_DIALECT,
        name,
        input: Value::Object(parameters(body)),
    })
}

/// Collect `<parameter name="…">value</parameter>` pairs into an input object.
fn parameters(body: &str) -> Map<String, Value> {
    const CLOSE: &str = "</parameter>";
    let mut out = Map::new();
    let mut cursor = body;
    while let Some(open) = cursor.find("<parameter") {
        let Some(tag) = cursor.get(open..) else { break };
        let Some(head_end) = tag.find('>') else { break };
        let (Some(head), Some(rest)) = (tag.get(..head_end), tag.get(head_end + 1..)) else {
            break;
        };
        let Some(close) = rest.find(CLOSE) else { break };
        let Some(raw) = rest.get(..close) else { break };
        if let Some(name) = attribute(head, "name") {
            out.insert(name, parameter_value(head, raw));
        }
        let Some(next) = rest.get(close + CLOSE.len()..) else {
            break;
        };
        cursor = next;
    }
    out
}

/// Type a single parameter value.
///
/// `string="true"` is `DeepSeek`'s own marker for "this is literal text", so it
/// is honoured exactly — not trimmed, not parsed — because the value it marks
/// is typically a shell command or a file body where whitespace is content.
/// Without the marker, only a value that opens with `{` or `[` is read as
/// JSON: `true` and `5` are far more often a command word or a string argument
/// than a boolean or a number, and a wrongly-typed argument is rejected by the
/// schema layer with the model given no clue why.
fn parameter_value(head: &str, raw: &str) -> Value {
    if head.contains("string=\"true\"") {
        return Value::String(raw.to_owned());
    }
    let trimmed = raw.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            return parsed;
        }
    }
    Value::String(trimmed.to_owned())
}

/// Read `name="value"` out of a tag head; `None` when the attribute is absent
/// or unterminated.
fn attribute(head: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = head.find(&needle)? + needle.len();
    let rest = head.get(start..)?;
    let end = rest.find('"')?;
    let value = rest.get(..end)?;
    if value.is_empty() {
        return None;
    }
    Some(value.to_owned())
}

// ---------------------------------------------------------------------------
// Bare OpenAI-style JSON
// ---------------------------------------------------------------------------

/// Recognise a JSON object shaped like an `OpenAI` tool call, written without
/// the canonical fence.
///
/// Only a *whole* candidate counts — the entire trimmed reply, or the entire
/// body of one fenced block. A JSON object lifted out of the middle of a
/// paragraph would make an explanation of tool calling indistinguishable from
/// a request to run one.
fn openai_style_json(reply: &str) -> Option<DialectMatch> {
    for candidate in json_candidates(reply) {
        let Ok(value) = serde_json::from_str::<Value>(candidate) else {
            continue;
        };
        let Some(name) = value.get("name").and_then(Value::as_str) else {
            continue;
        };
        if arguments_of(&value).is_none() {
            continue;
        }
        return Some(DialectMatch::Attempt {
            dialect: OPENAI_JSON_DIALECT,
            detail: format!(
                "the call to `{name}` was written as a plain JSON object with no \
                 ```tool_call fence around it"
            ),
        });
    }
    None
}

/// The whole trimmed reply, then each fenced block body, as parse candidates.
fn json_candidates(reply: &str) -> Vec<&str> {
    let mut out = vec![reply.trim()];
    // Odd segments of a split on the fence are the insides of blocks. An
    // unterminated final block yields a last odd segment too, which is exactly
    // the fragment we want to look at anyway.
    for (index, segment) in reply.split("```").enumerate() {
        if index % 2 == 1 {
            out.push(strip_language_tag(segment).trim());
        }
    }
    out
}

/// Drop the ```` ```json ```` style language tag from a fenced block body.
fn strip_language_tag(block: &str) -> &str {
    match block.split_once('\n') {
        // A first line with no whitespace and no `{` is a language tag, not
        // JSON: `json`, `javascript`, `tool_code`. A body that starts with the
        // object itself has none.
        Some((first, rest))
            if !first.trim().is_empty()
                && !first.contains(char::is_whitespace)
                && !first.contains('{') =>
        {
            rest
        }
        _ => block,
    }
}
