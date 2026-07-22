//! Fail-closed one-shot KB agent loop.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::connector::ModelConnector;
use arcana_core::cost::CostTracker;
use arcana_core::dispatch::ModelPolicy;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::{HookChain, HookContext, HookError, HookResult, ToolHook};
use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
use arcana_core::tool::{ToolDispatcher, ToolOutput};
use arcana_tools::arcana_search::ArcanaSearchTool;
use async_trait::async_trait;
use serde_json::{json, Value};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const KB_MODEL_CONNECTOR: &str = "orq";
const KB_MODEL: &str = "deepseek-v4-flash";
const KB_NAMESPACE: &str = "wiki";
const KB_LIMIT: u64 = 5;
const MAX_QUERY_CHARS: usize = 2_000;

#[derive(Debug, Error)]
enum KbReadError {
    #[error("query must be non-empty, single-line, control-free, and at most 2000 characters")]
    InvalidQuery,
    #[error("KB read composition failed: {0}")]
    Composition(String),
    #[error("agent loop did not complete: {0:?}")]
    Loop(TerminalReason),
    #[error("grounding proof requires exactly one successful search (observed {0})")]
    SearchCount(usize),
    #[error("grounding proof requires exactly one search attempt (observed {0})")]
    AttemptCount(usize),
    #[error("grounding proof requires nonzero grounded hits")]
    NoHits,
    #[error("grounding proof requires the final response to cite a returned source_path")]
    MissingCitation,
}

#[derive(Debug)]
struct KbReadReport {
    final_text: String,
    attempts: usize,
    searches: usize,
    hits: u64,
    sources: Vec<String>,
}

#[derive(Default)]
struct Evidence {
    attempts: usize,
    searches: usize,
    hits: u64,
    sources: Vec<String>,
}

struct GroundingEvidenceHook {
    evidence: Arc<Mutex<Evidence>>,
}

#[async_trait]
impl ToolHook for GroundingEvidenceHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        if tool == "arcana_search" {
            let mut evidence = self.evidence.lock().map_err(|_| {
                HookError::ExecutionFailed("grounding evidence lock poisoned".into())
            })?;
            if evidence.attempts >= 1 {
                return Ok(HookResult::StopExecution(
                    "kb-read permits exactly one arcana_search attempt".into(),
                ));
            }
            evidence.attempts = evidence.attempts.saturating_add(1);
            Ok(HookResult::Continue)
        } else {
            Ok(HookResult::StopExecution(
                "kb-read permits only arcana_search".into(),
            ))
        }
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        tool: &str,
        output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        if tool != "arcana_search" {
            return Ok(HookResult::StopExecution(
                "kb-read permits only arcana_search".into(),
            ));
        }
        let metadata = output.metadata.as_ref().ok_or_else(|| {
            HookError::ExecutionFailed("arcana_search output has no metadata".into())
        })?;
        let count = metadata
            .get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                HookError::ExecutionFailed("arcana_search count is missing or invalid".into())
            })?;
        let results = metadata
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                HookError::ExecutionFailed("arcana_search results are missing or invalid".into())
            })?;
        if usize::try_from(count).ok() != Some(results.len()) {
            return Err(HookError::ExecutionFailed(
                "arcana_search count does not match results".into(),
            ));
        }
        let mut sources = Vec::with_capacity(results.len());
        for result in results {
            let source = result
                .get("source_path")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    HookError::ExecutionFailed("search hit has no source_path".into())
                })?;
            sources.push(source.to_owned());
        }
        let mut evidence = self
            .evidence
            .lock()
            .map_err(|_| HookError::ExecutionFailed("grounding evidence lock poisoned".into()))?;
        evidence.searches = evidence.searches.saturating_add(1);
        evidence.hits = evidence.hits.saturating_add(count);
        evidence.sources.extend(sources);
        Ok(HookResult::Continue)
    }
}

struct CanonicalKbInput {
    input: Value,
}

#[async_trait]
impl PermissionLayer for CanonicalKbInput {
    fn name(&self) -> &'static str {
        "kb-read-canonical-input"
    }

    async fn evaluate(&self, tool: &str, _input: &Value) -> LayerDecision {
        if tool == "arcana_search" {
            LayerDecision::ReplaceInput(self.input.clone())
        } else {
            LayerDecision::Deny("kb-read permits only arcana_search".into())
        }
    }
}

struct ExactKbAllow {
    input: Value,
}

#[async_trait]
impl PermissionLayer for ExactKbAllow {
    fn name(&self) -> &'static str {
        "kb-read-exact-allow"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        if tool == "arcana_search" && input == &self.input {
            LayerDecision::Allow
        } else {
            LayerDecision::Deny("capability does not match the fixed KB read grant".into())
        }
    }
}

fn canonical_query(query: &str) -> Result<String, KbReadError> {
    let canonical = query.trim();
    if canonical.is_empty()
        || canonical.chars().count() > MAX_QUERY_CHARS
        || canonical.chars().any(char::is_control)
    {
        return Err(KbReadError::InvalidQuery);
    }
    Ok(canonical.to_owned())
}

async fn run_kb_read_with(
    query: &str,
    connector: &dyn ModelConnector,
    search_tool: ArcanaSearchTool,
    audit_dir: &Path,
) -> Result<KbReadReport, KbReadError> {
    let query = canonical_query(query)?;
    let fixed_input = json!({
        "query": query,
        "namespace": KB_NAMESPACE,
        "limit": KB_LIMIT,
    });

    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(search_tool))
        .map_err(|error| KbReadError::Composition(error.to_string()))?;
    let cascade = PermissionCascade::new(vec![
        Arc::new(CanonicalKbInput {
            input: fixed_input.clone(),
        }),
        Arc::new(ExactKbAllow {
            input: fixed_input.clone(),
        }),
    ]);
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let mut hooks = HookChain::new();
    hooks.push(Arc::new(GroundingEvidenceHook {
        evidence: evidence.clone(),
    }));
    let audit =
        AuditLog::new(audit_dir).map_err(|error| KbReadError::Composition(error.to_string()))?;
    let executor = CapabilityExecutor::new(registry, cascade, hooks, audit);

    let mut config = DriverConfig::new(KB_MODEL_CONNECTOR);
    config.policy = ModelPolicy::single_model(KB_MODEL);
    config.max_turns = 3;
    config.max_cost_usd = Some(0.10);
    let encoded_query = serde_json::to_string(&query)
        .map_err(|error| KbReadError::Composition(error.to_string()))?;
    config.system_prompt = Some(format!(
        "You are a read-only KB agent. On the first turn, emit exactly one tool request and no \
         prose, using this driver-owned wire format:\n```tool_call\n{{\"name\":\"arcana_search\",\
         \"input\":{{\"query\":{encoded_query},\"namespace\":\"wiki\",\"limit\":5}}}}\n```\n\
         After the tool result, answer only from its hits and cite at least one returned \
         source_path verbatim. Never request another tool."
    ));
    let cost = Arc::new(CostTracker::new());
    let driver = Driver::new(connector, &executor, cost, CancellationToken::new(), config);
    let output = driver.run(&query).await;
    if output.reason != TerminalReason::Completed {
        return Err(KbReadError::Loop(output.reason));
    }
    let final_text = output
        .final_text
        .ok_or_else(|| KbReadError::Composition("completed loop returned no final text".into()))?;
    let evidence = evidence
        .lock()
        .map_err(|_| KbReadError::Composition("grounding evidence lock poisoned".into()))?;
    if evidence.attempts != 1 {
        return Err(KbReadError::AttemptCount(evidence.attempts));
    }
    if evidence.searches != 1 {
        return Err(KbReadError::SearchCount(evidence.searches));
    }
    if evidence.hits == 0 || evidence.sources.is_empty() {
        return Err(KbReadError::NoHits);
    }
    if !evidence
        .sources
        .iter()
        .any(|source| final_text.contains(source))
    {
        return Err(KbReadError::MissingCitation);
    }
    Ok(KbReadReport {
        final_text,
        attempts: evidence.attempts,
        searches: evidence.searches,
        hits: evidence.hits,
        sources: evidence.sources.clone(),
    })
}

/// Run one real Model Connector → `arcana_search` → grounded-answer loop.
///
/// There is deliberately no offline connector or unauthenticated Scrutator
/// fallback. Any missing credential, denied capability, audit failure, empty
/// result, repeated search, or uncited source returns a non-zero exit code.
#[must_use]
pub fn run_kb_read(query: String) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("arcana kb-read: runtime initialization failed: {error}");
            return 1;
        }
    };
    runtime.block_on(async move {
        let connector = match arcana_connectors::ModelConnectorClient::try_from_env() {
            Ok(connector) => connector,
            Err(error) => {
                eprintln!("arcana kb-read: Model Connector unavailable: {error}");
                return 1;
            }
        };
        let search_tool = match ArcanaSearchTool::from_env() {
            Ok(tool) => tool,
            Err(error) => {
                eprintln!("arcana kb-read: authenticated Scrutator unavailable: {error}");
                return 1;
            }
        };
        let audit_dir: PathBuf = xdg::BaseDirectories::with_prefix("arcana").map_or_else(
            |_| PathBuf::from(".arcana-state"),
            |base| base.get_state_home(),
        );
        match run_kb_read_with(&query, &connector, search_tool, &audit_dir).await {
            Ok(report) => {
                println!("{}", report.final_text);
                println!(
                    "grounding: attempts={} searches={} hits={} sources={}",
                    report.attempts,
                    report.searches,
                    report.hits,
                    report.sources.join(",")
                );
                println!("audit log: {}", audit_dir.join("audit.log").display());
                0
            }
            Err(error) => {
                eprintln!("arcana kb-read: {error}");
                1
            }
        }
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
    use arcana_connectors::ScrutatorClient;
    use arcana_core::connector::{
        ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
    };
    use arcana_tools::arcana_search::ArcanaSearchTool;
    use async_trait::async_trait;
    use secrecy::SecretString;
    use serde_json::json;
    use tempfile::tempdir;
    use url::Url;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::run_kb_read_with;

    struct StaticToken;

    #[async_trait]
    impl BearerTokenProvider for StaticToken {
        async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
            Ok(SecretString::from("reader-jwt"))
        }
    }

    struct ScriptedConnector {
        responses: Mutex<VecDeque<ConnectorResponse>>,
        requests: Mutex<Vec<ExecuteRequest>>,
    }

    impl ScriptedConnector {
        fn new(results: &[&str]) -> Self {
            Self {
                responses: Mutex::new(
                    results
                        .iter()
                        .map(|result| response(result))
                        .collect::<VecDeque<_>>(),
                ),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ExecuteRequest> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    #[async_trait]
    impl ModelConnector for ScriptedConnector {
        async fn execute(
            &self,
            request: ExecuteRequest,
        ) -> Result<ConnectorResponse, ConnectorError> {
            self.requests.lock().expect("requests lock").push(request);
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .ok_or_else(|| ConnectorError::Transport("script exhausted".into()))
        }
    }

    fn response(result: &str) -> ConnectorResponse {
        ConnectorResponse {
            id: "test-id".into(),
            connector: "orq".into(),
            model: "deepseek-v4-flash".into(),
            result: result.into(),
            usage: Usage {
                input_tokens: 10,
                output_tokens: 10,
                total_tokens: 20,
                cost_usd: 0.001,
            },
            latency_ms: 1,
            status: "success".into(),
            error: None,
        }
    }

    fn tool_call(name: &str, input: serde_json::Value) -> String {
        format!(
            "```tool_call\n{}\n```",
            json!({ "name": name, "input": input })
        )
    }

    fn search_tool(server: &MockServer) -> ArcanaSearchTool {
        let client = ScrutatorClient::new(
            Url::parse(&server.uri()).expect("mock URL"),
            Arc::new(StaticToken),
        )
        .expect("Scrutator client");
        ArcanaSearchTool::with_client(client)
    }

    async fn mount_hit(server: &MockServer, expected_query: &str, expected_calls: u64) {
        Mock::given(method("POST"))
            .and(path("/v1/search"))
            .and(header("authorization", "Bearer reader-jwt"))
            .and(body_json(json!({
                "query": expected_query,
                "namespace": "wiki",
                "limit": 5
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "chunk_id": "wiki-1",
                    "content": "Scrutator provides grounded hybrid search.",
                    "source_path": "wiki/services/scrutator.md",
                    "source_type": "markdown",
                    "chunk_index": 0,
                    "score": 0.91,
                    "namespace": "wiki",
                    "project": "Scrutator",
                    "metadata": null
                }]
            })))
            .expect(expected_calls)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn grounded_loop_fixes_query_and_namespace_and_cites_a_source() {
        let server = MockServer::start().await;
        mount_hit(&server, "What is Scrutator?", 1).await;
        let connector = ScriptedConnector::new(&[
            &tool_call(
                "arcana_search",
                json!({ "query": "model override", "namespace": "private", "limit": 50 }),
            ),
            "Scrutator is the hybrid search service [wiki/services/scrutator.md].",
        ]);
        let audit = tempdir().expect("audit dir");

        let report = run_kb_read_with(
            "  What is Scrutator?  ",
            &connector,
            search_tool(&server),
            audit.path(),
        )
        .await
        .expect("grounded loop succeeds");

        assert_eq!(report.searches, 1);
        assert_eq!(report.attempts, 1);
        assert_eq!(report.hits, 1);
        assert_eq!(report.sources, ["wiki/services/scrutator.md"]);
        assert!(report.final_text.contains("wiki/services/scrutator.md"));
        let requests = connector.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.connector == "orq"));
        assert!(requests
            .iter()
            .all(|request| request.model.as_deref() == Some("deepseek-v4-flash")));
        let system_prompt = requests[0]
            .system_prompt
            .as_deref()
            .expect("KB loop has a fixed system prompt");
        assert!(system_prompt.contains("```tool_call"));
        assert!(system_prompt.contains(
            r#"{"name":"arcana_search","input":{"query":"What is Scrutator?","namespace":"wiki","limit":5}}"#
        ));
        let audit_text = std::fs::read_to_string(audit.path().join("audit.log")).unwrap();
        assert_eq!(audit_text.matches("\"tool\":\"arcana_search\"").count(), 2);
        assert!(audit_text.contains("\"outcome\":\"success\""));
    }

    #[tokio::test]
    async fn rejects_any_capability_except_arcana_search() {
        let server = MockServer::start().await;
        let connector = ScriptedConnector::new(&[&tool_call("bash", json!({ "command": "true" }))]);
        let audit = tempdir().expect("audit dir");

        let error = run_kb_read_with(
            "safe question",
            &connector,
            search_tool(&server),
            audit.path(),
        )
        .await
        .expect_err("unregistered capability must fail closed");

        assert!(error.to_string().to_lowercase().contains("permission"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_completed_loop_without_nonzero_hits_and_source_citation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
            .mount(&server)
            .await;
        let connector = ScriptedConnector::new(&[
            &tool_call("arcana_search", json!({ "query": "q" })),
            "I found nothing but will answer anyway.",
        ]);
        let audit = tempdir().expect("audit dir");

        let error = run_kb_read_with("question", &connector, search_tool(&server), audit.path())
            .await
            .expect_err("zero-hit completion must not report readiness");

        assert!(error.to_string().contains("nonzero grounded hits"));
    }

    #[tokio::test]
    async fn rejects_more_than_one_successful_search() {
        let server = MockServer::start().await;
        mount_hit(&server, "question", 1).await;
        let connector = ScriptedConnector::new(&[
            &tool_call("arcana_search", json!({ "query": "first" })),
            &tool_call("arcana_search", json!({ "query": "second" })),
            "Answer [wiki/services/scrutator.md].",
        ]);
        let audit = tempdir().expect("audit dir");

        let error = run_kb_read_with("question", &connector, search_tool(&server), audit.path())
            .await
            .expect_err("multiple searches must not report readiness");

        assert!(error.to_string().contains("AbortedByHook"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_first_search_still_consumes_the_only_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/search"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .expect(1)
            .mount(&server)
            .await;
        let connector = ScriptedConnector::new(&[
            &tool_call("arcana_search", json!({ "query": "first" })),
            &tool_call("arcana_search", json!({ "query": "retry" })),
        ]);
        let audit = tempdir().expect("audit dir");

        let error = run_kb_read_with("question", &connector, search_tool(&server), audit.path())
            .await
            .expect_err("second attempt after failure must be denied");

        assert!(error.to_string().contains("AbortedByHook"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejects_grounded_hits_when_final_answer_omits_source_path() {
        let server = MockServer::start().await;
        mount_hit(&server, "question", 1).await;
        let connector = ScriptedConnector::new(&[
            &tool_call("arcana_search", json!({ "query": "q" })),
            "Answer without a source citation.",
        ]);
        let audit = tempdir().expect("audit dir");

        let error = run_kb_read_with("question", &connector, search_tool(&server), audit.path())
            .await
            .expect_err("uncited completion must not report readiness");

        assert!(error.to_string().contains("source_path"));
    }
}
