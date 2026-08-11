//! `arcana demo` — the Phase-C vertical-prototype composition root (ARAS-0032).
//!
//! Assembles the SAME real capability core the `DoD` integration test uses —
//! the [`Driver`](arcana_core::agent_loop::Driver) (ARAS-0030), the multi-model
//! [`ModelPolicy`](arcana_core::dispatch::ModelPolicy) (ARAS-0031), and the
//! fused [`CapabilityExecutor`](arcana_core::execution::CapabilityExecutor)
//! (ARAS-0033) that owns the `ToolDispatcher`, the `PermissionCascade`, an empty
//! post-cascade `HookChain`, and the `AuditLog` (audit is a field of the fused
//! authorize→audit→execute transaction — single audit by construction) — and
//! drives one attempt → check → conclusion loop, printing three labelled phases.
//!
//! ## Demo-only scaffolding (NOT capability core)
//!
//! Two pieces in THIS module are deliberately demo-only composition-root
//! fixtures, explicitly permitted by ARAS-0032 V-AC-5 (which forbids *new*
//! `Tool`/`ModelConnector` impls only in `arcana-core` / `arcana-connectors`
//! `src`):
//!
//! - [`DemoConnector`] — a canned, offline [`ModelConnector`] that replays two
//!   fixed turns so the default demo path is deterministic and needs no network
//!   or `ARCANA_MC_TOKEN`. It is NOT a capability-core connector and does not
//!   reimplement `arcana-connectors`.
//! - [`DemoEchoTool`] — a minimal real [`Tool`] (the core `EchoTool` lives in
//!   `crates/core/tests/` and is unreachable from `src`), so a genuine tool
//!   dispatch occurs through the real `ToolDispatcher` in the demo.
//!
//! The optional `--live` path swaps [`DemoConnector`] for the real
//! [`ModelConnectorClient`](arcana_connectors::ModelConnectorClient) when
//! `ARCANA_MC_TOKEN` is present, and falls back to the offline path otherwise.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, FirstDispatchPromptV0, TerminalReason};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, FirstDispatchMeasurementV0, ModelConnector,
    PromptVariantV0, Usage,
};
use arcana_core::cost::CostTracker;
use arcana_core::dispatch::ModelPolicy;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

/// Default small real task when the operator does not pass one. Carries a code
/// signal ("implement"/"rust") so turn-0 classifies as `Code` (expensive model)
/// and the post-tool turn as `Summarize` (cheap model) — two distinct ids.
const DEFAULT_TASK: &str = "implement a greeting in rust: echo the world back";

/// Entry point for the `arcana demo` subcommand. Assembles the full vertical
/// loop, prints the three labelled phases, and returns a process exit code
/// (`0` on `Completed`, non-zero otherwise — honest exit code).
#[must_use]
pub fn run_demo(
    task: Option<String>,
    live: bool,
    first_dispatch_measurement_json: Option<&str>,
    first_dispatch_connector: Option<&str>,
    first_dispatch_model: Option<&str>,
    first_dispatch_prompt: Option<String>,
) -> i32 {
    let task = task.unwrap_or_else(|| DEFAULT_TASK.to_owned());
    let measurement = match first_dispatch_measurement_json
        .map(parse_first_dispatch_measurement)
        .transpose()
    {
        Ok(measurement) => measurement,
        Err(err) => {
            eprintln!("arcana demo: invalid first-dispatch measurement: {err}");
            return 1;
        }
    };
    let route = match parse_first_dispatch_route(
        measurement.is_some(),
        first_dispatch_connector,
        first_dispatch_model,
    ) {
        Ok(route) => route,
        Err(err) => {
            eprintln!("arcana demo: invalid first-dispatch route: {err}");
            return 1;
        }
    };
    let Ok(prompt) = first_dispatch_prompt
        .map(FirstDispatchPromptV0::try_new)
        .transpose()
    else {
        eprintln!("arcana demo: invalid first-dispatch prompt");
        return 1;
    };
    if prompt.is_some() && measurement.is_none() {
        eprintln!("arcana demo: first-dispatch prompt requires measurement metadata");
        return 1;
    }
    if measurement.is_some() && !live {
        eprintln!("arcana demo: first-dispatch measurement requires --live");
        return 1;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana demo: failed to start async runtime: {err}");
            return 1;
        }
    };
    runtime.block_on(run_demo_async(&task, live, measurement, route, prompt))
}

/// Async body: build the components, run the driver, print the phases.
async fn run_demo_async(
    task: &str,
    live: bool,
    measurement: Option<FirstDispatchMeasurementV0>,
    route: Option<FirstDispatchRoute>,
    first_dispatch_prompt: Option<FirstDispatchPromptV0>,
) -> i32 {
    // Isolated audit sink under the system temp dir; `AuditHook::new` creates it.
    let audit_dir: PathBuf = std::env::temp_dir().join("arcana-demo");

    let measurement_requested = measurement.is_some();
    let expected_measurement = measurement.clone();
    let Some(connector) = select_connector(live, measurement_requested) else {
        return 1;
    };

    let mut dispatcher = ToolDispatcher::new();
    if let Err(err) = dispatcher.register(Arc::new(DemoEchoTool)) {
        eprintln!("arcana demo: tool registration failed: {err}");
        return 1;
    }

    // Empty (always-allow) cascade + an executor-OWNED AuditLog: in the C4
    // CapabilityExecutor the audit is a field of the fused
    // authorize→audit→execute transaction (single audit by construction), not a
    // composable ToolHook.
    let cascade = PermissionCascade::new(vec![]);
    let audit = match AuditLog::new(&audit_dir) {
        Ok(log) => log,
        Err(err) => {
            eprintln!("arcana demo: audit log setup failed: {err}");
            return 1;
        }
    };
    let cost = Arc::new(CostTracker::new());

    // Fuse the capability core: the executor takes ownership of the dispatcher,
    // the cascade, an empty post-cascade HookChain, and the AuditLog. The driver
    // dispatches every tool THROUGH this executor.
    let executor = CapabilityExecutor::new(dispatcher, cascade, HookChain::new(), audit);

    // Default ModelPolicy maps Code→"arcana-code-strong" and
    // Summarize→"arcana-cheap-fast" (distinct ids) — reused verbatim.
    let out = {
        let driver = Driver::new(
            connector.as_ref(),
            &executor,
            cost,
            CancellationToken::new(),
            driver_config(measurement, route.as_ref(), first_dispatch_prompt),
        );
        driver.run(task).await
    };

    if measurement_requested {
        let Some(observation) = out.first_dispatch_observation.as_ref() else {
            eprintln!(
                "arcana demo: Model Connector returned no first-dispatch observation; measurement is unproven"
            );
            return 1;
        };
        let Some(expected_measurement) = expected_measurement.as_ref() else {
            eprintln!("arcana demo: missing expected first-dispatch measurement");
            return 1;
        };
        let Some(expected_route) = route.as_ref() else {
            eprintln!("arcana demo: missing expected first-dispatch route");
            return 1;
        };
        match measurement_evidence_json(
            &format!("{:?}", out.reason),
            out.turns,
            observation,
            expected_measurement,
            expected_route,
        ) {
            Ok(encoded) => println!("{encoded}"),
            Err(err) => {
                eprintln!("arcana demo: invalid first-dispatch observation: {err}");
                return 1;
            }
        }
        return i32::from(out.reason != TerminalReason::Completed);
    }

    // --- attempt → check → conclusion --------------------------------------
    let models = if out.selected_models.is_empty() {
        "<none>".to_owned()
    } else {
        out.selected_models.join(", ")
    };
    println!("=== ATTEMPT ===");
    println!("task: {task}");
    println!("models selected (in order): {models}");
    println!();
    println!("=== CHECK ===");
    println!("tool turns: {}", out.turns);
    println!("terminal verdict: {:?}", out.reason);
    println!();
    println!("=== CONCLUSION ===");
    println!(
        "final: {}",
        out.final_text.as_deref().unwrap_or("<no final text>")
    );
    println!("audit log: {}", audit_dir.join("audit.log").display());

    // `AuditLog` appends synchronously and flushes per record; the executor owns
    // it and drops at function scope end, so no explicit flush is required.

    i32::from(out.reason != TerminalReason::Completed)
}

/// Select the offline demo or real production connector. Measurement mode is
/// deliberately fail-closed: it never converts a missing live dependency into
/// a plausible-looking offline receipt.
fn select_connector(live: bool, measurement_requested: bool) -> Option<Box<dyn ModelConnector>> {
    let live_active = live && std::env::var("ARCANA_MC_TOKEN").is_ok();
    if live_active {
        return match arcana_connectors::ModelConnectorClient::try_from_env() {
            Ok(client) => {
                if !measurement_requested {
                    println!("(live path: routing through the real Model Connector)");
                }
                Some(Box::new(client))
            }
            Err(err) if measurement_requested => {
                eprintln!(
                    "arcana demo: first-dispatch measurement requires the live Model Connector: {err}"
                );
                None
            }
            Err(err) => {
                println!("(live requested but unavailable: {err}; using offline demo)");
                Some(Box::new(DemoConnector::new()))
            }
        };
    }
    if measurement_requested {
        eprintln!(
            "arcana demo: first-dispatch measurement requires ARCANA_MC_TOKEN and never falls back offline"
        );
        return None;
    }
    if live {
        println!("(live requested but ARCANA_MC_TOKEN unset; using offline demo)");
    }
    Some(Box::new(DemoConnector::new()))
}

const MEASUREMENT_INPUT_KEYS: [&str; 7] = [
    "caseId",
    "commandId",
    "corpusId",
    "replayIndex",
    "roleId",
    "taskClassId",
    "variant",
];

fn parse_first_dispatch_measurement(
    serialized: &str,
) -> Result<FirstDispatchMeasurementV0, String> {
    let value: Value = serde_json::from_str(serialized).map_err(|_| "invalid JSON".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "root must be an object".to_owned())?;
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    if keys != MEASUREMENT_INPUT_KEYS {
        return Err("unexpected or missing field".to_owned());
    }
    let text = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{key} must be a string"))
    };
    let replay_index = object
        .get("replayIndex")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| matches!(value, 1 | 2))
        .ok_or_else(|| "replayIndex must be 1 or 2".to_owned())?;
    let variant = match text("variant")? {
        "baseline" => PromptVariantV0::Baseline,
        "compiled" => PromptVariantV0::Compiled,
        _ => return Err("variant must be baseline or compiled".to_owned()),
    };
    FirstDispatchMeasurementV0::try_new(
        text("corpusId")?,
        text("caseId")?,
        text("roleId")?,
        text("taskClassId")?,
        text("commandId")?,
        replay_index,
        variant,
    )
    .map_err(|err| err.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstDispatchRoute {
    connector_id: String,
    model_id: String,
}

fn parse_first_dispatch_route(
    measurement_requested: bool,
    connector_id: Option<&str>,
    model_id: Option<&str>,
) -> Result<Option<FirstDispatchRoute>, String> {
    match (measurement_requested, connector_id, model_id) {
        (false, None, None) => Ok(None),
        (false, _, _) => Err("route identifiers require a measurement".to_owned()),
        (true, Some(connector_id), Some(model_id))
            if is_identifier_text(connector_id, 50) && is_identifier_text(model_id, 100) =>
        {
            Ok(Some(FirstDispatchRoute {
                connector_id: connector_id.to_owned(),
                model_id: model_id.to_owned(),
            }))
        }
        (true, None, _) => Err("missing --first-dispatch-connector".to_owned()),
        (true, _, None) => Err("missing --first-dispatch-model".to_owned()),
        (true, _, _) => Err("connector or model is not a closed identifier".to_owned()),
    }
}

fn driver_config(
    measurement: Option<FirstDispatchMeasurementV0>,
    route: Option<&FirstDispatchRoute>,
    first_dispatch_prompt: Option<FirstDispatchPromptV0>,
) -> DriverConfig {
    let mut config = DriverConfig::new(route.map_or("arcana-demo", |measurement_route| {
        measurement_route.connector_id.as_str()
    }));
    if let Some(measurement_route) = route {
        config.policy = ModelPolicy::single_model(&measurement_route.model_id);
    }
    config.first_dispatch_measurement = measurement;
    config.first_dispatch_prompt = first_dispatch_prompt;
    config
}

const OBSERVATION_KEYS: [&str; 16] = [
    "authorization",
    "connector",
    "connectorResponseId",
    "evidenceStatus",
    "latencyMs",
    "measurement",
    "model",
    "observationBoundary",
    "observationId",
    "outcome",
    "persistence",
    "receiptDigestSha256",
    "requestPayloadBytes",
    "requestPayloadDigestSha256",
    "usage",
    "version",
];
const USAGE_KEYS: [&str; 6] = [
    "cachedInputTokens",
    "costUsd",
    "inputTokens",
    "outputTokens",
    "source",
    "totalTokens",
];

fn exact_object<'a>(value: &'a Value, expected_keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    if object.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !object.contains_key(*key))
    {
        return None;
    }
    Some(object)
}

fn is_lower_sha256(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_uuid(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        let bytes = text.as_bytes();
        bytes.len() == 36
            && [8, 13, 18, 23]
                .into_iter()
                .all(|index| bytes[index] == b'-')
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
            && matches!(bytes[14], b'1'..=b'5')
            && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
    })
}

fn is_identifier_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':' | b'/')
        })
}

fn is_identifier(value: &Value, max_bytes: usize) -> bool {
    value
        .as_str()
        .is_some_and(|text| is_identifier_text(text, max_bytes))
}

fn canonical_receipt_digest(value: &Value) -> Result<String, String> {
    let mut claims = value.clone();
    let object = claims
        .as_object_mut()
        .ok_or_else(|| "observation must be an object".to_owned())?;
    object.remove("receiptDigestSha256");
    let encoded = serde_json_canonicalizer::to_vec(&claims)
        .map_err(|_| "canonicalization failed".to_owned())?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn validated_observation(
    observation: &arcana_core::connector::UnverifiedFirstDispatchObservationV0,
    expected_measurement: &FirstDispatchMeasurementV0,
    expected_route: &FirstDispatchRoute,
) -> Result<Value, String> {
    let value = observation.as_value();
    let object = exact_object(value, &OBSERVATION_KEYS)
        .ok_or_else(|| "unexpected or missing observation field".to_owned())?;
    let expected = serde_json::to_value(expected_measurement)
        .map_err(|_| "expected measurement serialization failed".to_owned())?;
    let usage = exact_object(&object["usage"], &USAGE_KEYS)
        .ok_or_else(|| "unexpected or missing usage field".to_owned())?;
    let outcome_valid = object["outcome"]
        .as_str()
        .is_some_and(|status| matches!(status, "success" | "error" | "timeout" | "rate_limited"));
    let usage_numbers_valid = ["inputTokens", "outputTokens", "totalTokens"]
        .into_iter()
        .all(|key| usage[key].as_u64().is_some())
        && usage["cachedInputTokens"].is_null()
        && usage["costUsd"]
            .as_f64()
            .is_some_and(|cost| cost.is_finite() && cost >= 0.0);
    if object["version"] != "first-dispatch-observation/v0"
        || !is_uuid(&object["observationId"])
        || object["measurement"] != expected
        || !is_identifier(&object["connector"], 256)
        || !is_identifier(&object["model"], 256)
        || object["connector"].as_str() != Some(expected_route.connector_id.as_str())
        || object["model"].as_str() != Some(expected_route.model_id.as_str())
        || !is_uuid(&object["connectorResponseId"])
        || !is_lower_sha256(&object["requestPayloadDigestSha256"])
        || object["requestPayloadBytes"]
            .as_u64()
            .is_none_or(|bytes| bytes == 0)
        || object["observationBoundary"] != "model-connector/service/pre-adapter-v0"
        || !usage_numbers_valid
        || usage["source"] != "CONNECTOR_RESPONSE_UNVERIFIED"
        || object["latencyMs"].as_u64().is_none()
        || !outcome_valid
        || object["persistence"] != "MODEL_CONNECTOR_POSTGRESQL"
        || object["evidenceStatus"] != "PERSISTED_PRE_ADAPTER_OBSERVATION"
        || object["authorization"] != "NOT_AUTHORIZED"
        || !is_lower_sha256(&object["receiptDigestSha256"])
        || object["receiptDigestSha256"].as_str() != Some(&canonical_receipt_digest(value)?)
    {
        return Err("observation does not match the closed receipt contract".to_owned());
    }
    Ok(value.clone())
}

fn measurement_evidence_json(
    terminal_reason: &str,
    turns: u32,
    observation: &arcana_core::connector::UnverifiedFirstDispatchObservationV0,
    expected_measurement: &FirstDispatchMeasurementV0,
    expected_route: &FirstDispatchRoute,
) -> Result<String, String> {
    let receipt = validated_observation(observation, expected_measurement, expected_route)?;
    serde_json::to_string(&json!({
        "terminalReason": terminal_reason,
        "turns": turns,
        "firstDispatchObservation": receipt,
    }))
    .map_err(|_| "evidence serialization failed".to_owned())
}

// ---------------------------------------------------------------------------
// Demo scaffolding — offline canned connector (NOT a capability-core connector)
// ---------------------------------------------------------------------------

/// Demo-only, offline [`ModelConnector`]: replays a fixed two-turn script — a
/// tool-call turn (Code step) then a final answer (Summarize step) — so the
/// default demo path is deterministic with no network and no `ARCANA_MC_TOKEN`.
///
/// This is composition-root scaffolding permitted by ARAS-0032 V-AC-5; it is
/// NOT part of the capability core and does not reimplement `arcana-connectors`.
struct DemoConnector {
    turns: Vec<ConnectorResponse>,
    idx: AtomicUsize,
}

impl DemoConnector {
    fn new() -> Self {
        Self {
            turns: vec![
                canned_response(&tool_call_fence("echo", &json!({ "text": "world" })), 0.001),
                canned_response("greeting complete: hello world", 0.001),
            ],
            idx: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ModelConnector for DemoConnector {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let i = self.idx.fetch_add(1, Ordering::Relaxed);
        // Bounded to the last turn so any extra loop iteration re-emits the
        // final answer (never out-of-range, never a panic).
        let last = self.turns.len().saturating_sub(1);
        match self.turns.get(i.min(last)) {
            Some(resp) => Ok(resp.clone()),
            None => Err(ConnectorError::Transport(
                "demo connector has no scripted turns".to_owned(),
            )),
        }
    }
}

/// Build a canned success [`ConnectorResponse`] carrying `result` and `cost`.
fn canned_response(result: &str, cost_usd: f64) -> ConnectorResponse {
    ConnectorResponse {
        id: "demo-id".to_owned(),
        connector: "arcana-demo".to_owned(),
        model: "demo-model".to_owned(),
        result: result.to_owned(),
        usage: Usage {
            input_tokens: 3,
            output_tokens: 5,
            total_tokens: 8,
            cost_usd,
        },
        latency_ms: 1,
        status: "success".to_owned(),
        error: None,
        first_dispatch_observation: None,
    }
}

/// Render the driver-recognised `tool_call` fenced block for the demo script.
fn tool_call_fence(name: &str, input: &Value) -> String {
    let payload = json!({ "name": name, "input": input });
    format!("```tool_call\n{payload}\n```")
}

// ---------------------------------------------------------------------------
// Demo scaffolding — a minimal real tool (core EchoTool is not reachable here)
// ---------------------------------------------------------------------------

/// Demo-only minimal real [`Tool`]: echoes its input back as content, so a
/// genuine dispatch occurs through the real `ToolDispatcher`. The core
/// `EchoTool` lives in `crates/core/tests/` and is unreachable from `src`, so
/// this equivalent demo fixture is defined in the CLI composition root
/// (permitted by ARAS-0032 V-AC-5). It is NOT a capability-core tool.
struct DemoEchoTool;

#[async_trait]
impl Tool for DemoEchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "demo fixture: echoes its input back as content"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        Ok(ToolOutput {
            content: format!("echo:{input}"),
            metadata: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const INPUT: &str = r#"{
        "corpusId":"corpus-v0",
        "caseId":"case-007",
        "roleId":"developer",
        "taskClassId":"code-change",
        "commandId":"implement",
        "replayIndex":2,
        "variant":"compiled"
    }"#;

    fn observation_value(measurement: &FirstDispatchMeasurementV0) -> Value {
        let mut value = json!({
            "version": "first-dispatch-observation/v0",
            "observationId": "00000000-0000-4000-8000-000000000001",
            "measurement": serde_json::to_value(measurement).expect("serialize measurement"),
            "connector": "claude-code",
            "model": "sonnet-4.6",
            "connectorResponseId": "10000000-0000-4000-8000-000000000001",
            "requestPayloadDigestSha256": "a".repeat(64),
            "requestPayloadBytes": 128,
            "observationBoundary": "model-connector/service/pre-adapter-v0",
            "usage": {
                "inputTokens": 10,
                "cachedInputTokens": null,
                "outputTokens": 2,
                "totalTokens": 12,
                "costUsd": 0.001,
                "source": "CONNECTOR_RESPONSE_UNVERIFIED"
            },
            "latencyMs": 42,
            "outcome": "success",
            "persistence": "MODEL_CONNECTOR_POSTGRESQL",
            "evidenceStatus": "PERSISTED_PRE_ADAPTER_OBSERVATION",
            "authorization": "NOT_AUTHORIZED",
            "receiptDigestSha256": "0".repeat(64)
        });
        let digest = canonical_receipt_digest(&value).expect("digest receipt");
        value["receiptDigestSha256"] = Value::String(digest);
        value
    }

    fn observation_from(
        value: Value,
    ) -> arcana_core::connector::UnverifiedFirstDispatchObservationV0 {
        serde_json::from_value(value).expect("deserialize opaque observation")
    }

    #[test]
    fn parses_the_closed_identifier_only_measurement_input() {
        let measurement = parse_first_dispatch_measurement(INPUT).expect("valid input");
        let value = serde_json::to_value(measurement).expect("serialize measurement");

        assert_eq!(value["version"], "first-dispatch-measurement/v0");
        assert_eq!(
            value["adapterBoundary"],
            "arcana-agent-system/driver/first-dispatch-v0"
        );
        assert_eq!(value["variant"], "compiled");
        assert_eq!(value["replayIndex"], 2);
        assert!(value.get("prompt").is_none());
        assert!(value.get("token").is_none());
        assert!(value.get("authorization").is_none());
    }

    #[test]
    fn rejects_an_invented_field_and_out_of_manifest_replays() {
        let invented = INPUT.replace(
            "\"variant\":\"compiled\"",
            "\"variant\":\"compiled\",\"prompt\":\"not allowed\"",
        );
        let zero = INPUT.replace("\"replayIndex\":2", "\"replayIndex\":0");
        let third = INPUT.replace("\"replayIndex\":2", "\"replayIndex\":3");

        assert!(parse_first_dispatch_measurement(&invented).is_err());
        assert!(parse_first_dispatch_measurement(&zero).is_err());
        assert!(parse_first_dispatch_measurement(&third).is_err());
    }

    #[test]
    fn driver_config_carries_the_parsed_measurement_to_the_real_driver_seam() {
        let measurement = parse_first_dispatch_measurement(INPUT).expect("valid input");
        let expected = serde_json::to_value(&measurement).expect("serialize expected");
        let route = FirstDispatchRoute {
            connector_id: "claude-code".to_owned(),
            model_id: "sonnet-4.6".to_owned(),
        };
        let config = driver_config(Some(measurement), Some(&route), None);
        let actual = serde_json::to_value(config.first_dispatch_measurement)
            .expect("serialize configured measurement");

        assert_eq!(actual, expected);
        assert_eq!(config.connector_id, "claude-code");
        assert_eq!(
            config
                .policy
                .select(arcana_core::dispatch::TaskType::Code)
                .model_id,
            "sonnet-4.6"
        );
    }

    #[test]
    fn emits_one_validated_json_record_for_a_closed_receipt() {
        let measurement = parse_first_dispatch_measurement(INPUT).expect("valid input");
        let observation = observation_from(observation_value(&measurement));
        let route = FirstDispatchRoute {
            connector_id: "claude-code".to_owned(),
            model_id: "sonnet-4.6".to_owned(),
        };

        let encoded = measurement_evidence_json("Completed", 1, &observation, &measurement, &route)
            .expect("valid receipt emits");
        let value: Value = serde_json::from_str(&encoded).expect("single JSON record");

        assert_eq!(value["terminalReason"], "Completed");
        assert_eq!(
            value["firstDispatchObservation"]["authorization"],
            "NOT_AUTHORIZED"
        );
        assert!(value.get("finalText").is_none());
    }

    #[test]
    fn rejects_malformed_mismatched_or_leaky_receipts() {
        let measurement = parse_first_dispatch_measurement(INPUT).expect("valid input");
        let route = FirstDispatchRoute {
            connector_id: "claude-code".to_owned(),
            model_id: "sonnet-4.6".to_owned(),
        };
        let empty = observation_from(json!({}));
        let mut leaky_value = observation_value(&measurement);
        leaky_value["prompt"] = json!("secret-sentinel");
        leaky_value["receiptDigestSha256"] =
            Value::String(canonical_receipt_digest(&leaky_value).expect("digest leaky receipt"));
        let leaky = observation_from(leaky_value);
        let mut mismatched_value = observation_value(&measurement);
        mismatched_value["measurement"]["caseId"] = json!("different-case");
        mismatched_value["receiptDigestSha256"] = Value::String(
            canonical_receipt_digest(&mismatched_value).expect("digest mismatched receipt"),
        );
        let mismatched = observation_from(mismatched_value);
        let mut bad_digest_value = observation_value(&measurement);
        bad_digest_value["receiptDigestSha256"] = Value::String("f".repeat(64));
        let bad_digest = observation_from(bad_digest_value);
        let mut poisoned_identifier_value = observation_value(&measurement);
        poisoned_identifier_value["connectorResponseId"] =
            json!("secret model output is printable but not an identifier");
        poisoned_identifier_value["receiptDigestSha256"] = Value::String(
            canonical_receipt_digest(&poisoned_identifier_value)
                .expect("digest poisoned identifier receipt"),
        );
        let poisoned_identifier = observation_from(poisoned_identifier_value);
        let mut wrong_connector_value = observation_value(&measurement);
        wrong_connector_value["connector"] = json!("openrouter");
        wrong_connector_value["receiptDigestSha256"] = Value::String(
            canonical_receipt_digest(&wrong_connector_value).expect("digest wrong connector"),
        );
        let wrong_connector = observation_from(wrong_connector_value);
        let mut wrong_model_value = observation_value(&measurement);
        wrong_model_value["model"] = json!("another-model");
        wrong_model_value["receiptDigestSha256"] = Value::String(
            canonical_receipt_digest(&wrong_model_value).expect("digest wrong model"),
        );
        let wrong_model = observation_from(wrong_model_value);

        for observation in [
            &empty,
            &leaky,
            &mismatched,
            &bad_digest,
            &poisoned_identifier,
            &wrong_connector,
            &wrong_model,
        ] {
            assert!(
                measurement_evidence_json("Completed", 1, observation, &measurement, &route)
                    .is_err()
            );
        }
    }

    #[test]
    fn canonical_receipt_numbers_match_ecmascript_json_stringify() {
        let value = json!({
            "costUsd": 0.000_003,
            "large": 100_000_000_000_000_000_000_f64,
            "receiptDigestSha256": "not-part-of-the-preimage"
        });
        let encoded = serde_json_canonicalizer::to_string(&value).expect("canonical JSON");

        assert_eq!(
            encoded,
            r#"{"costUsd":0.000003,"large":100000000000000000000,"receiptDigestSha256":"not-part-of-the-preimage"}"#
        );
        assert_eq!(
            canonical_receipt_digest(&value).expect("receipt digest"),
            "a5886e750a52e7959d64996b7fe7dc7abbc6d6c38a3774c71d5b6890dfbe8d89"
        );
    }
}
