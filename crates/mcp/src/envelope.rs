//! The extended MCP response envelope.
//!
//! Vanilla MCP `CallToolResult` cannot express two facts the arcana capability
//! core produces: the post-`ReplaceInput` `effective_args`, and an
//! `InteractionRequired` suspend/resume handle for a `Defer` decision. Both
//! ride two vanilla-compatible extension points — `structured_content.arcana`
//! and the `_meta` fast-flags — so a plain MCP client still parses `content`
//! while an arcana-aware client reads the structured extension.

use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Meta};
use serde_json::{Value, json};

/// Status of a capability attempt as seen at the MCP boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeStatus {
    /// The tool executed and returned output.
    Completed,
    /// A `Defer` decision suspended the call; a resume token is carried.
    InteractionRequired,
    /// The cascade (or execution) denied/failed the call.
    Denied,
}

impl EnvelopeStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnvelopeStatus::Completed => "completed",
            EnvelopeStatus::InteractionRequired => "interaction_required",
            EnvelopeStatus::Denied => "denied",
        }
    }
}

/// A suspend token plus the context a caller needs to resume the round-trip.
#[derive(Debug, Clone)]
pub struct InteractionRequired {
    /// Server-minted uuid v4; the resume handle the caller returns.
    pub token: String,
    /// The tool whose call is suspended.
    pub tool: String,
    /// Human-facing prompt describing what is being asked.
    pub prompt: String,
    /// Current (pre-resolution) input; the final `effective_args` arrives on resume.
    pub pending_input: Value,
}

/// Build the `structured_content` extension object.
fn structured(
    status: EnvelopeStatus,
    effective_args: Option<&Value>,
    interaction: Option<&InteractionRequired>,
) -> Value {
    let interaction_json = interaction.map_or(Value::Null, |ir| {
        json!({
            "token": ir.token,
            "tool": ir.tool,
            "prompt": ir.prompt,
            "pending_input": ir.pending_input,
        })
    });
    json!({
        "arcana": {
            "status": status.as_str(),
            "effective_args": effective_args.cloned().unwrap_or(Value::Null),
            "interaction_required": interaction_json,
        }
    })
}

/// Build the `_meta` fast-routing flags.
fn fast_meta(status: EnvelopeStatus, token: Option<&str>) -> Meta {
    let mut obj = JsonObject::new();
    obj.insert("arcana.status".to_owned(), json!(status.as_str()));
    if let Some(token) = token {
        obj.insert("arcana.interaction_token".to_owned(), json!(token));
    }
    Meta(obj)
}

/// Completed call: `content` carries the tool output, `effective_args` the
/// cascade-authorized input the tool actually executed on.
#[must_use]
pub fn map_completed(output_text: String, effective_args: &Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(output_text)]);
    result.structured_content = Some(structured(
        EnvelopeStatus::Completed,
        Some(effective_args),
        None,
    ));
    result.is_error = None;
    result.meta = Some(fast_meta(EnvelopeStatus::Completed, None));
    result
}

/// Suspended call: a valid state (not an error). `content` carries the prompt;
/// the resume token rides both the structured extension and `_meta`.
#[must_use]
pub fn map_interaction_required(interaction: &InteractionRequired) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(interaction.prompt.clone())]);
    result.structured_content = Some(structured(
        EnvelopeStatus::InteractionRequired,
        None,
        Some(interaction),
    ));
    result.is_error = None;
    result.meta = Some(fast_meta(
        EnvelopeStatus::InteractionRequired,
        Some(&interaction.token),
    ));
    result
}

/// Denied/failed call: surfaced as a tool-level error carrying only the
/// cascade layer + reason already exposed by `CapabilityError` — no new
/// disclosure beyond what the audit log already records.
#[must_use]
pub fn map_denied(reason: String) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(reason)]);
    result.structured_content = Some(structured(EnvelopeStatus::Denied, None, None));
    result.is_error = Some(true);
    result.meta = Some(fast_meta(EnvelopeStatus::Denied, None));
    result
}
