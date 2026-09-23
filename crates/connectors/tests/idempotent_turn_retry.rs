//! A2-234: a re-dispatched turn is free, because it carries the same
//! `Idempotency-Key`.
//!
//! A2-230 gave a turn cut off by the network edge up to five re-dispatches
//! (report `/home/dev/aup/arc2/runs/A2-230/report.md` §1) and, in the same
//! breath, measured what each of them cost: Model Connector settles the charge
//! in the same transaction as the request row **before** the response reaches
//! the socket, so a request the edge cut may already have been executed and
//! billed — and `arcana` sent no key, so the re-dispatch was a second provider
//! call and a second charge. The retry was honest and not free. Raising the
//! budget from two to five raised the worst case with it.
//!
//! The server side was already built for this (`ARAS-0058`): `Idempotency-Key`
//! is lifted onto the request in `src/connectors/connectors.controller.ts`,
//! and `src/billing/billing.service.ts` answers a repeat of a claimed key with
//! one of four honest outcomes. This suite drives the real
//! [`ModelConnectorClient`] and the real [`Driver`] against a stub that
//! implements those four outcomes, and judges by **how many times the provider
//! was called**, never by what any layer says it did.
//!
//! What is faked here is the server. The client, the driver, the retry
//! schedule, the key minting and the HTTP round trip are production code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_connectors::{ApiKey, ModelConnectorClient};
use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ---------------------------------------------------------------------------
// The stub: Model Connector's intent store, as its own source describes it
// ---------------------------------------------------------------------------

/// What the stub does with the NEXT request that reaches the provider.
#[derive(Clone, Debug)]
enum Behaviour {
    /// The pilot's failure, and the expensive one: the provider ran, the
    /// charge settled, and the edge in front of Model Connector ate the
    /// response. The intent is `completed` with a stored body, so a repeat of
    /// the key replays it — `resolveReplay`, state `completed`.
    ChargedThenCutByTheEdge,
    /// The client's own clock ran out while the request was still running
    /// upstream. The intent stays `held`, so a repeat of the key is answered
    /// `idempotency_conflict` — until the first request settles, after
    /// `conflicts_before_settling` of them.
    StillRunning { conflicts_before_settling: usize },
    /// A clean answer.
    Answer(&'static str),
}

/// One row of the `request_intent` table.
struct Intent {
    fingerprint: String,
    /// `None` while `held`; the stored response once `completed`.
    response: Option<Value>,
    conflicts_left: usize,
    settled_body: Option<&'static str>,
}

/// A stub that keys on `Idempotency-Key` exactly as Model Connector does.
///
/// It counts PROVIDER calls separately from HTTP requests, because that is the
/// number the customer pays for and the only number this suite trusts.
#[derive(Clone)]
struct FakeModelConnector {
    inner: Arc<FakeState>,
}

struct FakeState {
    provider_calls: AtomicUsize,
    conflicts_answered: AtomicUsize,
    /// Every `Idempotency-Key` seen, in request order. `None` records a
    /// request that carried no key at all.
    keys: Mutex<Vec<Option<String>>>,
    intents: Mutex<HashMap<String, Intent>>,
    script: Mutex<VecDeque<Behaviour>>,
}

impl FakeModelConnector {
    fn new(script: Vec<Behaviour>) -> Self {
        Self {
            inner: Arc::new(FakeState {
                provider_calls: AtomicUsize::new(0),
                conflicts_answered: AtomicUsize::new(0),
                keys: Mutex::new(Vec::new()),
                intents: Mutex::new(HashMap::new()),
                script: Mutex::new(script.into()),
            }),
        }
    }

    /// Times the provider actually ran — i.e. times the customer was charged.
    fn provider_calls(&self) -> usize {
        self.inner.provider_calls.load(Ordering::SeqCst)
    }

    fn conflicts_answered(&self) -> usize {
        self.inner.conflicts_answered.load(Ordering::SeqCst)
    }

    fn keys(&self) -> Vec<Option<String>> {
        self.inner.keys.lock().unwrap().clone()
    }
}

impl Respond for FakeModelConnector {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let key = request
            .headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.inner.keys.lock().unwrap().push(key.clone());

        // `requestFingerprint` excludes `idempotencyKey` and
        // `firstDispatchMeasurement`; everything else in the body is the
        // identity of the intent.
        let mut body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        if let Some(object) = body.as_object_mut() {
            object.remove("firstDispatchMeasurement");
        }
        let fingerprint = body.to_string();

        let mut intents = self.inner.intents.lock().unwrap();
        if let Some(key) = key.as_deref() {
            if let Some(intent) = intents.get_mut(key) {
                // `resolveReplay`: the fingerprint is checked BEFORE the state.
                if intent.fingerprint != fingerprint {
                    return ResponseTemplate::new(422).set_body_json(error_envelope(
                        "idempotency_key_reused",
                        "This Idempotency-Key was already used for a DIFFERENT request.",
                        false,
                        "abort",
                    ));
                }
                if let Some(stored) = intent.response.clone() {
                    // One provider call and one ledger row, however many times
                    // the client re-POSTs. Nothing is incremented here.
                    return ResponseTemplate::new(201).set_body_json(stored);
                }
                if intent.conflicts_left > 0 {
                    intent.conflicts_left -= 1;
                    self.inner.conflicts_answered.fetch_add(1, Ordering::SeqCst);
                    return ResponseTemplate::new(409).set_body_json(error_envelope(
                        "idempotency_conflict",
                        "A request with this Idempotency-Key is still in flight.",
                        true,
                        "wait",
                    ));
                }
                // The first request finished while we were waiting on it.
                let stored = success_body(intent.settled_body.unwrap_or("done"));
                intent.response = Some(stored.clone());
                return ResponseTemplate::new(201).set_body_json(stored);
            }
        }

        let behaviour = self
            .inner
            .script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Behaviour::Answer("out of script"));
        match behaviour {
            Behaviour::ChargedThenCutByTheEdge => {
                self.inner.provider_calls.fetch_add(1, Ordering::SeqCst);
                if let Some(key) = key {
                    intents.insert(
                        key,
                        Intent {
                            fingerprint,
                            response: Some(success_body("the answer the edge ate")),
                            conflicts_left: 0,
                            settled_body: None,
                        },
                    );
                }
                // Cloudflare's 16 bytes, from pilot A2-204c5 — neither the
                // connector envelope nor a NestJS one.
                ResponseTemplate::new(502).set_body_string("error code: 502")
            }
            Behaviour::StillRunning {
                conflicts_before_settling,
            } => {
                self.inner.provider_calls.fetch_add(1, Ordering::SeqCst);
                if let Some(key) = key {
                    intents.insert(
                        key,
                        Intent {
                            fingerprint,
                            response: None,
                            conflicts_left: conflicts_before_settling,
                            settled_body: Some("the answer the first attempt was still writing"),
                        },
                    );
                }
                ResponseTemplate::new(504).set_body_string("error code: 504")
            }
            Behaviour::Answer(text) => {
                self.inner.provider_calls.fetch_add(1, Ordering::SeqCst);
                let stored = success_body(text);
                if let Some(key) = key {
                    intents.insert(
                        key,
                        Intent {
                            fingerprint,
                            response: Some(stored.clone()),
                            conflicts_left: 0,
                            settled_body: None,
                        },
                    );
                }
                ResponseTemplate::new(201).set_body_json(stored)
            }
        }
    }
}

fn success_body(result: &str) -> Value {
    json!({
        "id": "req-1",
        "connector": "deepseek",
        "model": "deepseek-v4-flash",
        "result": result,
        "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15, "costUsd": 0.001},
        "latencyMs": 12,
        "status": "success",
    })
}

fn error_envelope(kind: &str, message: &str, retryable: bool, recommendation: &str) -> Value {
    json!({
        "id": "",
        "connector": "deepseek",
        "model": "deepseek-v4-flash",
        "result": "",
        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "costUsd": 0.0},
        "latencyMs": 0,
        "status": "error",
        "error": {
            "type": kind,
            "message": message,
            "retryable": retryable,
            "recommendation": recommendation,
        },
    })
}

// ---------------------------------------------------------------------------
// The measurements
// ---------------------------------------------------------------------------

/// The pilot's failure, priced. The edge cuts a request that was executed and
/// charged; the driver re-dispatches; the stub replays the stored answer
/// because the key is the same. One provider call for one turn.
#[tokio::test]
async fn a_turn_cut_by_the_edge_after_it_was_charged_is_replayed_not_paid_for_twice() {
    let fake = FakeModelConnector::new(vec![Behaviour::ChargedThenCutByTheEdge]);
    let (out, _audit) = drive(&fake, "answer the question").await;

    assert_eq!(
        fake.provider_calls(),
        1,
        "the cut request was executed and charged once; the re-dispatch bought it again"
    );
    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?}",
        out.terminal_detail
    );
    assert_eq!(out.final_text.as_deref(), Some("the answer the edge ate"));

    let keys = fake.keys();
    assert_eq!(
        keys.len(),
        2,
        "one cut attempt and one re-dispatch: {keys:?}"
    );
    assert!(
        keys.iter().all(Option::is_some),
        "a request went out with no key: {keys:?}"
    );
    assert_eq!(
        keys[0], keys[1],
        "the re-dispatch of one turn must reuse the turn's key: {keys:?}"
    );
}

/// The in-flight path. The first attempt is still running upstream when the
/// client's clock runs out, so Model Connector answers `idempotency_conflict`
/// — 409, `retryable`, recommendation `wait`. Its own message says what NOT to
/// do: "do not reissue it under a new key or it will be dispatched and charged
/// twice." The driver waits on the same key and collects the answer it has
/// already paid for.
#[tokio::test]
async fn an_in_flight_conflict_is_waited_out_on_the_same_key_and_charged_once() {
    let fake = FakeModelConnector::new(vec![Behaviour::StillRunning {
        conflicts_before_settling: 2,
    }]);
    let (out, _audit) = drive(&fake, "answer the question").await;

    assert_eq!(
        fake.provider_calls(),
        1,
        "waiting on an in-flight request must not dispatch a second one"
    );
    assert!(
        fake.conflicts_answered() >= 1,
        "the conflict path was never exercised"
    );
    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?}",
        out.terminal_detail
    );
    assert_eq!(
        out.final_text.as_deref(),
        Some("the answer the first attempt was still writing")
    );

    let keys = fake.keys();
    assert!(keys.iter().all(Option::is_some), "{keys:?}");
    assert!(
        keys.windows(2).all(|pair| pair[0] == pair[1]),
        "a conflict must be retried under the SAME key, never a new one: {keys:?}"
    );
}

/// The other half of "stable per attempt-series": a key that never changed
/// would make the SECOND turn a replay of the first, and the run would answer
/// its own opening question forever.
#[tokio::test]
async fn the_next_turn_of_the_same_run_gets_a_new_key() {
    let fake = FakeModelConnector::new(vec![
        Behaviour::Answer(
            "```tool_call\n{\"name\": \"echo\", \"input\": {\"value\": \"hi\"}}\n```",
        ),
        Behaviour::Answer("done"),
    ]);
    let (out, _audit) = drive(&fake, "use the echo tool, then answer").await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?}",
        out.terminal_detail
    );
    assert_eq!(out.tool_calls, 1, "the tool turn did not happen");
    assert_eq!(fake.provider_calls(), 2, "two turns, two provider calls");

    let keys = fake.keys();
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert_ne!(
        keys[0], keys[1],
        "a second turn reusing the first turn's key would replay the first answer: {keys:?}"
    );
}

/// The key has to be a key Model Connector will accept, or the header turns
/// the retry it exists to save into a transport failure:
/// `normalizeIdempotencyKey` takes printable ASCII with no spaces, at most 255
/// characters, and rejects rather than sanitises.
#[tokio::test]
async fn every_key_sent_is_one_model_connector_will_accept() {
    let fake = FakeModelConnector::new(vec![Behaviour::ChargedThenCutByTheEdge]);
    let (_out, _audit) = drive(&fake, "answer the question").await;

    for key in fake.keys().into_iter().flatten() {
        assert!(!key.is_empty() && key.len() <= 255, "bad length: {key:?}");
        assert!(
            key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            "not printable ASCII without spaces: {key:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Harness — everything below the stub is production code
// ---------------------------------------------------------------------------

async fn drive(fake: &FakeModelConnector, task: &str) -> (RunOutput, TempDir) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(fake.clone())
        .mount(&server)
        .await;

    let client =
        ModelConnectorClient::new(Url::parse(&server.uri()).unwrap(), ApiKey::new("mc-test"))
            .unwrap();

    let mut registry = ToolDispatcher::new();
    registry.register(Arc::new(EchoTool)).unwrap();
    let dir = TempDir::new().unwrap();
    let audit = AuditLog::new(dir.path()).unwrap();
    let executor = CapabilityExecutor::new(
        registry,
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        HookChain::new(),
        audit,
    );

    let mut config = DriverConfig::new("deepseek");
    // Real sleeping is dead time here; the schedule's arithmetic is pinned by
    // the unit tests in `agent_loop.rs`, not by waiting through it.
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 16;

    let driver = Driver::new(
        &client,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    (driver.run(task).await, dir)
}

struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "echoes its input back as content"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: format!("echo:{}", invocation.into_input()),
            metadata: None,
        })
    }
}

struct AllowLayer;

#[async_trait]
impl PermissionLayer for AllowLayer {
    fn name(&self) -> &'static str {
        "test-allow"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Allow
    }
}
