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
//!   translated into the canonical call. Two markups reach this arm —
//!   `DSML`/`invoke`, and the `<tool_call>` XML wrapper — because their tags
//!   exist for no other purpose, so finding a closed one whose body names a
//!   tool is not a guess about intent.
//! * [`DialectMatch::Attempt`] — the attempt is recognisable but not something
//!   we are willing to dispatch. The driver folds a correction back to the
//!   model naming the expected format, bounded, and nothing executes.
//!
//! The split is deliberate and conservative: translating is a decision to run a
//! command on the operator's machine, so it is reserved for markup that cannot
//! plausibly be prose. A bare JSON object shaped like an `OpenAI` tool call is
//! the other common near-miss, and it *can* appear inside an explanation of
//! tool calling — so it is corrected, never executed.
//!
//! # The `<tool_call>` XML wrapper (A2-218)
//!
//! The second dialect measured in the field, and it cost a run the same way.
//! On 2026-09-23, again on `deepseek-flash` through Model Connector, the last
//! reply of a long task was
//!
//! ```text
//! <tool_call>
//! {"name":"bash","input":{"command":"cd aras && cat rust-toolchain.toml; …","timeout_seconds":120}}
//! </tool_call>
//! </tool_call>
//! ```
//!
//! — a complete call, correct tool, correct arguments, in the wrapper instead
//! of the fence. The scan for the canonical fence found nothing, nothing here
//! knew the tags, and the run ended `Completed` with that text delivered to
//! the operator as the answer (`/home/dev/aup/arc2/runs/A2-216/live.log:9-12`,
//! ARAS `92a4a7a`).
//!
//! The wrapper is not this model's invention. It is what the Hermes/Qwen
//! function-calling chat template instructs: *"For each function call, return
//! a json object with function name and arguments within
//! `<tool_call></tool_call>` XML tags"*, followed by the literal shape
//! `{"name": <function-name>, "arguments": <args-json-object>}`
//! (`Qwen/Qwen2.5-7B-Instruct`, `tokenizer_config.json` → `chat_template`,
//! read 2026-09-23). So both spellings of the argument key occur in the wild —
//! the template's `arguments`, and this runner's own `input` when the system
//! prompt has taught it that name — and [`arguments_of`] already accepts
//! either.
//!
//! Dispatching it is safe for the same reason `<invoke>` is: the tag pair
//! exists only to carry a tool call. The bar is not the tag alone but a
//! *closed* wrapper whose body is a JSON object naming a tool — an unclosed
//! one, or one wrapped around an apology, is an
//! [`DialectMatch::Attempt`] and costs a correction instead. A `<tool_call>`
//! written inside backticks is prose about the format, and is skipped: a model
//! explaining the encoding it was told to use has answered, and an answer must
//! not cost a turn.

//! # Arguments written as siblings of `name` (A2-219)
//!
//! The third shape measured in the field, and the first one that reached this
//! runner's OWN fence. On 2026-09-23, `deepseek-flash` through Model Connector
//! opened a canonical ```` ```tool_call ```` block and wrote
//!
//! ```text
//! {"name": "bash", "command": "git clone … && git log --oneline -3", "timeout_seconds": 600}
//! ```
//!
//! — the fence it was told to use, the right tool, the right arguments, and no
//! wrapper object around them (`/home/dev/aup/arc2/wt/A2-219-repro/.arcana/
//! rejected/0001-turn1.txt`, kept by the save this card added). [`arguments_of`]
//! looks only for a key holding the arguments, found none, and the reply became
//! a correction. The same shape is what ended the A2-204c3 pilot at turn 34 on
//! the one `edit` call that was about to write the patch.
//!
//! [`flat_arguments`] accepts it, and [`declared_call_arguments`] is where the
//! two readers are combined. The form is unambiguous *inside markup that
//! exists only to carry a tool call* — this runner's fence, or the
//! `<tool_call>` wrapper — because there the model has already said the object
//! is a call, so its remaining keys cannot be anything but the call's
//! arguments. It is deliberately NOT accepted for a bare JSON object found in
//! prose: `{"name": "Alice", "age": 30}` is a plausible answer, and reading it
//! as a call to `Alice` would charge a correction turn to a model that
//! answered the question.

use serde_json::{Map, Value};

/// Keys a model may put its arguments under, in the order they are believed.
///
/// `input` is this runner's own name. `arguments` is `OpenAI`'s (and therefore
/// nearly every `OpenAI`-compatible provider's), `parameters` is what the JSON
/// Schema word for the same thing leaks into, and `args` is the short form
/// smaller models fall back on. They are alternatives for one slot, so the
/// first one actually present wins rather than being merged.
pub const INPUT_KEYS: [&str; 4] = ["input", "arguments", "parameters", "args"];

/// Label for the `DSML` / `invoke` markup dialect, used in operator output and
/// in the correction handed back to the model.
pub const DSML_DIALECT: &str = "DeepSeek `invoke` markup";
/// Label for a bare JSON object shaped like an `OpenAI` tool call.
pub const OPENAI_JSON_DIALECT: &str = "a bare OpenAI-style JSON tool call";
/// Label for the Hermes/Qwen `<tool_call>` XML wrapper.
pub const TOOL_CALL_TAG_DIALECT: &str = "a `<tool_call>` XML wrapper";

/// Opening tag of the `<tool_call>` wrapper.
const TAG_OPEN: &str = "<tool_call>";
/// Closing tag of the `<tool_call>` wrapper.
const TAG_CLOSE: &str = "</tool_call>";

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
    invoke_markup(reply)
        .or_else(|| tool_call_wrapper(reply))
        .or_else(|| openai_style_json(reply))
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
            Some(found) => return Some(unwrap_repeated_envelope(decode_arguments(found))),
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
        if let Some(decoded) = object_from_json_text(text) {
            return decoded;
        }
    }
    value.clone()
}

/// The JSON **object** `text` encodes, or `None`.
///
/// Surplus closing punctuation at the end is tolerated by the same licence
/// [`value_before_surplus_closers`] states, and for the same measured reason:
/// every one of the four string-valued envelopes pilot A2-240c sent carried a
/// complete arguments object followed by one extra `}`
/// (`/home/dev/aup/arc2/wt/A2-240c/.arcana/denied/{0004,0006,0007,0008}-turn*.json`
/// — each inner string parses after dropping exactly one trailing character).
/// A strict `from_str` reads those as "not JSON at all" and leaves the whole
/// envelope in place, so the surplus brace decided four of the seven repeats.
fn object_from_json_text(text: &str) -> Option<Value> {
    let decoded = serde_json::from_str::<Value>(text)
        .ok()
        .or_else(|| value_before_surplus_closers(text))?;
    decoded.is_object().then_some(decoded)
}

/// Strip one repetition of the runner's own wrapper key from an arguments
/// object: `{"input": {"command": "ls"}}` is the call `{"command": "ls"}`.
///
/// # Why this is a reading and not a guess (A2-253)
///
/// Pilot A2-240c (arcana `17cffe0`, 68 turns, 63 attempted calls, 13 denied)
/// spent **7** of its 13 denials on this one shape — every one of them a
/// `bash` call whose command was already correct, refused at the `schema`
/// layer with `Additional properties are not allowed ('input' was
/// unexpected); "command" is a required property`
/// (`/home/dev/aup/arc2/wt/A2-240c/.arcana/denied/`, turns 11, 25, 30, 42, 43,
/// 54, 65). The system prompt tells the model the call is `{"name": …,
/// "input": {…}}`; the model applied the `input` key twice, to the object it
/// had already put under it.
///
/// A correction is what the runner already did, and the measurement is that it
/// does not work for this class: the model was told, in those exact words,
/// seven times across the run, and wrote the envelope again each time. The
/// contrast inside the same pilot is the argument — a quoted integer
/// (`"timeout_seconds": "400"`, turn 52) was refused once and the very next
/// call carried an unquoted `300`. One class the model can act on; this one it
/// cannot.
///
/// The licence is the narrowest that covers it, and it is a property of the
/// shipped tool set rather than a guess about intent: **no tool declares a
/// property named `input`, `arguments`, `parameters` or `args`, and every tool
/// schema sets `additionalProperties: false`**, so an arguments object whose
/// ONLY key is one of those spellings cannot be a call to anything — it is
/// invalid for every tool in the registry, and unwrapping it therefore cannot
/// change which call runs. `crates/cli/tests/run_tool_execution.rs` pins that
/// premise against the registry the CLI actually assembles, so a future tool
/// with an `input` argument turns this licence red instead of silent.
///
/// Everything wider stays a correction:
///
/// * More than one key (`{"input": {…}, "command": "ls"}`) is not an envelope;
///   it is a call with an extra argument, and dropping either half would be
///   choosing for the model.
/// * An inner value that is not an object — `{"input": 5}`, `{"input": null}`
///   — carries no call to unwrap.
/// * One level only. A second envelope is not a spelling of the format the
///   prompt states, it is a model that has lost the shape, and nothing in this
///   pilot measured it.
fn unwrap_repeated_envelope(value: Value) -> Value {
    let unwrapped = {
        let Some(object) = value.as_object() else {
            return value;
        };
        if object.len() != 1 {
            return value;
        }
        let Some((key, inner)) = object.iter().next() else {
            return value;
        };
        if !INPUT_KEYS.contains(&key.as_str()) {
            return value;
        }
        match inner {
            Value::Object(_) => Some(inner.clone()),
            Value::String(text) => object_from_json_text(text),
            _ => None,
        }
    };
    unwrapped.unwrap_or(value)
}

/// Read arguments a model wrote as siblings of `name` rather than inside a
/// wrapper object.
///
/// `{"name": "bash", "command": "ls", "timeout_seconds": 60}` yields
/// `{"command": "ls", "timeout_seconds": 60}`. `None` when `name` is the only
/// key there is — then the call really does carry no arguments, and the model
/// is told so rather than dispatched empty.
///
/// The wrapper spellings are filtered out alongside `name`, so a reply that
/// sent `{"name": …, "input": null, "command": "ls"}` does not smuggle a
/// literal `input: null` into the tool's arguments: [`arguments_of`] already
/// declined that `null`, and repeating it here would hand the schema layer a
/// key the model never meant as an argument.
///
/// A metadata key that is not an argument — an `id` on an `OpenAI`-shaped
/// object, say — does end up in the object and is then refused by the schema
/// layer. That is not a regression: before this reader such a reply carried no
/// arguments at all, so it was refused too, for a reason the model could do
/// nothing with.
#[must_use]
pub fn flat_arguments(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    let rest: Map<String, Value> = object
        .iter()
        .filter(|(key, _)| key.as_str() != "name" && !INPUT_KEYS.contains(&key.as_str()))
        .map(|(key, found)| (key.clone(), found.clone()))
        .collect();
    if rest.is_empty() {
        return None;
    }
    Some(Value::Object(rest))
}

/// The arguments of an object the model has already declared to be a tool
/// call: a wrapper key if there is one, otherwise the siblings of `name`.
///
/// Only for markup that cannot plausibly be prose — the canonical fence and
/// the `<tool_call>` wrapper. A bare JSON object keeps [`arguments_of`] alone.
#[must_use]
pub fn declared_call_arguments(value: &Value) -> Option<Value> {
    arguments_of(value).or_else(|| flat_arguments(value))
}

/// The JSON value at the front of `body`, when the only thing behind it is
/// surplus closing punctuation.
///
/// # Why a repair is admissible here at all (A2-248)
///
/// It lives in this module rather than in `agent_loop` because it is one
/// reading rule with two callers: the canonical fence body (A2-248) and the
/// JSON-encoded arguments string (A2-253). Two copies would be free to drift,
/// and this one decides what runs on the operator's machine.
///
/// Turn 62 of pilot A2-240b opened this runner's own fence and wrote a
/// complete `write` call — right tool, right path, whole file content — and
/// then one more `}` (`crates/core/tests/fixtures/
/// a2-248-surplus-brace-reply.txt`, the reply as the model sent it).
/// `serde_json::from_str` refuses trailing data, so the call became "not valid
/// JSON", nothing ran, and one of that run's hundred turns went on a
/// correction for a character that carried no information.
///
/// The licence is deliberately the narrowest one that covers it, and it is a
/// property of the text rather than a guess about the model: **`}`, `]` and
/// whitespace cannot name a tool, introduce an argument, or change a value.**
/// A remainder made only of those has exactly one reading once it is dropped,
/// so taking the prefix cannot dispatch anything other than what was written.
///
/// Everything else keeps costing a correction, because everything else could
/// change what runs:
///
/// * A second JSON object is a second call. Executing the first and discarding
///   the rest silently is a different run, not a repaired one.
/// * A trailing comma (`{"name":"bash",}`) never reaches here: it fails
///   *inside* the braces, so there is no complete prefix to take. That is the
///   line — a parser that truncates a suffix is reading; a parser that edits
///   between the braces is guessing at intent.
/// * A prefix that parses but names no tool falls through to the ordinary
///   `name` check in [`crate::agent_loop`], and is refused for the reason it
///   actually has.
///
/// Returns `None` whenever the licence does not apply, so the caller's
/// fail-closed path is unchanged.
#[must_use]
pub fn value_before_surplus_closers(body: &str) -> Option<Value> {
    let mut stream = serde_json::Deserializer::from_str(body).into_iter::<Value>();
    let value = stream.next()?.ok()?;
    let remainder = body.get(stream.byte_offset()..)?;
    remainder
        .chars()
        .all(|ch| ch == '}' || ch == ']' || ch.is_whitespace())
        .then_some(value)
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
// `<tool_call>` XML wrapper
// ---------------------------------------------------------------------------

/// Read a call out of a Hermes/Qwen `<tool_call>…</tool_call>` wrapper.
///
/// Only the first wrapper is read. This runner dispatches one call per turn,
/// and a model that emitted several has already been answered by the first —
/// silently running the rest would execute commands no turn ever reported.
fn tool_call_wrapper(reply: &str) -> Option<DialectMatch> {
    let attempt = |detail: &str| {
        Some(DialectMatch::Attempt {
            dialect: TOOL_CALL_TAG_DIALECT,
            detail: detail.to_owned(),
        })
    };
    let open = unquoted_open_tag(reply)?;
    let rest = reply.get(open + TAG_OPEN.len()..)?;
    let Some(close) = rest.find(TAG_CLOSE) else {
        return attempt(
            "your `<tool_call>` was never closed with `</tool_call>`, so the call is incomplete",
        );
    };
    let Some(body) = rest.get(..close) else {
        return attempt("the `<tool_call>` wrapper is malformed and its body could not be read");
    };
    // The body is usually bare JSON, but a model that reaches for the wrapper
    // sometimes also fences the object inside it; `json_candidates` covers
    // both without letting an object buried in a paragraph count.
    for candidate in json_candidates(body) {
        let Ok(value) = serde_json::from_str::<Value>(candidate) else {
            continue;
        };
        let Some(name) = value.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(input) = declared_call_arguments(&value) else {
            return Some(DialectMatch::Attempt {
                dialect: TOOL_CALL_TAG_DIALECT,
                detail: format!(
                    "your `<tool_call>` wrapper named `{name}` but carried no arguments; put \
                     them in an `input` object (send `\"input\": {{}}` if the tool genuinely \
                     takes none)"
                ),
            });
        };
        return Some(DialectMatch::Call {
            dialect: TOOL_CALL_TAG_DIALECT,
            name: name.to_owned(),
            input,
        });
    }
    attempt(
        "the body of your `<tool_call>` wrapper is not a JSON object with a `name` string, \
         so no tool was named",
    )
}

/// Offset of the first `<tool_call>` that is not quoted as inline code.
///
/// The negative control lives here. `` `<tool_call>` `` inside a sentence is a
/// model talking *about* the format — typically because the system prompt just
/// taught it a different one — and reading that as a call would charge an
/// answer a correction turn. A backtick immediately before the tag is the
/// whole test: it is how Markdown marks the tag as a name rather than a use.
fn unquoted_open_tag(reply: &str) -> Option<usize> {
    let mut from = 0;
    loop {
        let found = reply.get(from..)?.find(TAG_OPEN)? + from;
        if !reply
            .get(..found)
            .is_some_and(|before| before.ends_with('`'))
        {
            return Some(found);
        }
        from = found + TAG_OPEN.len();
    }
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
