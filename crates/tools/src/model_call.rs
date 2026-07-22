//! `ModelCallTool` — "call an LLM" as a cascade-gated capability.
//!
//! Registering model invocation as a [`Tool`] routes every LLM call through
//! the sealed `CapabilityExecutor` cascade (`Schema → Hook(audit) → Rule →
//! Interactive` → dispatch), exactly like `bash` / `webfetch` /
//! `arcana_search`. The vendor credential never appears in the tool input
//! schema: the token resolves only inside the Rust connector
//! (`ARCANA_MC_TOKEN`, redacted `ApiKey`), so a model-steered payload can never
//! inject, redirect, or exfiltrate it. Covers **D-REQ-04**.
//!
//! Thin by design: parse/validate the input, hand a typed [`ExecuteRequest`]
//! to the injected [`ModelConnector`], record the call against the shared
//! [`CostTracker`], and render the response into a [`ToolOutput`].

use std::sync::Arc;

use arcana_core::connector::{ExecuteRequest, ModelConnector};
use arcana_core::cost::CostTracker;
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

/// Parsed, schema-validated `model_call` input. Carries **no** credential
/// field by construction — the secret lives only inside the connector.
#[derive(Debug, Deserialize)]
struct ModelCallInput {
    prompt: String,
    model: String,
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    max_turns: Option<u32>,
}

/// Agent-callable capability that turns "call an LLM" into a registered
/// [`Tool`].
///
/// Holds the [`ModelConnector`] trait object (so a fake is injectable in
/// tests), the shared [`CostTracker`] (the single cost choke-point once model
/// calls are a tool), and a fixed `connector_id` — a deployment/capability
/// constant, never model-steered.
pub struct ModelCallTool {
    connector: Arc<dyn ModelConnector>,
    cost: Arc<CostTracker>,
    connector_id: String,
}

impl ModelCallTool {
    /// Build the tool over an explicit connector, cost tracker, and connector
    /// id. `connector_id` (e.g. `"claude-code"`) is fixed at construction; the
    /// model cannot override it.
    #[must_use]
    pub fn new(
        connector: Arc<dyn ModelConnector>,
        cost: Arc<CostTracker>,
        connector_id: impl Into<String>,
    ) -> Self {
        Self {
            connector,
            cost,
            connector_id: connector_id.into(),
        }
    }
}

#[async_trait]
impl Tool for ModelCallTool {
    fn name(&self) -> &'static str {
        "model_call"
    }

    fn description(&self) -> &'static str {
        "Call an upstream LLM through the Arcanada Model Connector. The vendor \
         credential is resolved inside the connector and is never part of this \
         tool's input."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["prompt", "model"],
            "properties": {
                "prompt": { "type": "string", "minLength": 1 },
                "model": { "type": "string", "minLength": 1 },
                "system_prompt": { "type": "string" },
                "max_turns": { "type": "integer", "minimum": 1 }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        let parsed: ModelCallInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;

        let mut request = ExecuteRequest::new(self.connector_id.clone(), parsed.prompt);
        request.model = Some(parsed.model);
        request.system_prompt = parsed.system_prompt;
        request.max_turns = parsed.max_turns;

        let response = self
            .connector
            .execute(request)
            .await
            .map_err(|err| ToolError::ExecutionFailed(err.to_string()))?;

        // The cost line: when "call an LLM" is a tool, the tool is the single
        // cost choke-point. Token counts are `u64` on the wire; saturate on the
        // (unreachable, >4.2 B tokens/call) narrowing cast.
        self.cost.record_llm_call(
            &response.model,
            u32::try_from(response.usage.input_tokens).unwrap_or(u32::MAX),
            u32::try_from(response.usage.output_tokens).unwrap_or(u32::MAX),
            response.usage.cost_usd,
        );

        Ok(ToolOutput {
            content: response.result,
            metadata: Some(json!(response.usage)),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use arcana_core::connector::{ConnectorError, ConnectorResponse};

    /// Never-dispatched connector: the schema tests exercise `input_schema` /
    /// `validate_input` only, so `execute` must not run.
    struct NullConnector;

    #[async_trait]
    impl ModelConnector for NullConnector {
        async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
            Err(ConnectorError::Transport(
                "schema tests must never dispatch".into(),
            ))
        }
    }

    fn tool() -> ModelCallTool {
        ModelCallTool::new(
            Arc::new(NullConnector),
            Arc::new(CostTracker::new()),
            "claude-code",
        )
    }

    #[tokio::test]
    async fn schema_rejects_unknown_field() {
        let err = tool()
            .validate_input(&json!({ "prompt": "hi", "model": "m", "token": "leak" }))
            .await
            .expect_err("additionalProperties:false must reject an unknown field");
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn schema_rejects_missing_model() {
        let err = tool()
            .validate_input(&json!({ "prompt": "hi" }))
            .await
            .expect_err("missing required `model` must be rejected");
        assert!(
            err.to_string().to_lowercase().contains("model"),
            "error should name the missing field: {err}"
        );
    }

    /// Secret-invariant guard: the input schema exposes no credential/redirect
    /// field, and forbids extra properties.
    #[test]
    fn schema_has_no_credential_or_redirect_property() {
        let schema = tool().input_schema();
        let props = schema["properties"]
            .as_object()
            .expect("schema has a properties object");
        for forbidden in [
            "token",
            "api_key",
            "apikey",
            "secret",
            "bearer",
            "key",
            "url",
            "base_url",
            "connector",
        ] {
            assert!(
                !props.contains_key(forbidden),
                "schema must not expose `{forbidden}`"
            );
        }
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "schema must forbid additional properties"
        );
    }
}
