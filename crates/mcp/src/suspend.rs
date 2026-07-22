//! In-process suspend/resume for `Defer` decisions — tokio channels only.
//!
//! No queue, no broker. A `Defer` reaches the cascade's terminal layer; the
//! adapter installs [`SuspendLayer`] there instead of the CLI's interactive
//! tail. On evaluation the layer mints a token, announces the suspension to
//! the `call_tool` handler, and parks awaiting a resolution. The handler
//! records the pending interaction keyed by token; `arcana.resume` feeds the
//! resolution back. Suspended state is a parked in-process task — it dies with
//! the process (Tier-1, single operator, non-durable by design).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arcana_core::execution::{CapabilityError, CapabilityOutput};
use arcana_core::permission::interactive::InteractiveLayer;
use arcana_core::permission::{LayerDecision, PermissionLayer};
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::oneshot;

/// The caller's answer to a suspended interaction.
#[derive(Debug)]
pub enum InteractionResolution {
    /// Proceed with the pending input unchanged.
    Allow,
    /// Reject the call with a reason.
    Deny(String),
    /// Proceed, replacing the input with the supplied value.
    ReplaceInput(Value),
}

/// Message sent from [`SuspendLayer`] to the `call_tool` handler when a call
/// suspends: "I suspended; here is the token + prompt + current input".
#[derive(Debug)]
pub struct InteractionAnnounce {
    pub token: String,
    pub tool: String,
    pub prompt: String,
    pub pending_input: Value,
}

/// A parked capability call awaiting a resume, keyed by token.
pub struct PendingInteraction {
    /// Feeds the caller's resolution back into the parked `SuspendLayer`.
    pub resolution_tx: oneshot::Sender<InteractionResolution>,
    /// Delivers the final execution result once the parked task completes.
    pub result_rx: oneshot::Receiver<Result<CapabilityOutput, CapabilityError>>,
}

/// Shared registry of suspended calls. `Mutex<HashMap>` — no broadcast, no broker.
pub type PendingInteractions = Arc<Mutex<HashMap<String, PendingInteraction>>>;

/// Terminal cascade layer that suspends a `Defer`'d call instead of resolving
/// it against the terminal. One instance per call (fresh channels); reuse is
/// refused.
pub struct SuspendLayer {
    announce_tx: Mutex<Option<oneshot::Sender<InteractionAnnounce>>>,
    resolution_rx: Mutex<Option<oneshot::Receiver<InteractionResolution>>>,
    token: String,
    prompt: String,
}

impl SuspendLayer {
    /// Build a per-call layer wired to the handler's channels.
    #[must_use]
    pub fn new(
        token: String,
        prompt: String,
        announce_tx: oneshot::Sender<InteractionAnnounce>,
        resolution_rx: oneshot::Receiver<InteractionResolution>,
    ) -> Self {
        Self {
            announce_tx: Mutex::new(Some(announce_tx)),
            resolution_rx: Mutex::new(Some(resolution_rx)),
            token,
            prompt,
        }
    }
}

#[async_trait]
impl PermissionLayer for SuspendLayer {
    fn name(&self) -> &'static str {
        "suspend"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        // Take the one-shot ends out of their guards *before* any await so no
        // std Mutex guard is ever held across a suspension point.
        let announce_tx = self
            .announce_tx
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        let resolution_rx = self
            .resolution_rx
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());

        let (Some(announce_tx), Some(resolution_rx)) = (announce_tx, resolution_rx) else {
            return LayerDecision::Deny("suspend layer already consumed".to_owned());
        };

        let announce = InteractionAnnounce {
            token: self.token.clone(),
            tool: tool.to_owned(),
            prompt: self.prompt.clone(),
            pending_input: input.clone(),
        };
        if announce_tx.send(announce).is_err() {
            return LayerDecision::Deny("interaction handler dropped".to_owned());
        }

        match resolution_rx.await {
            Ok(InteractionResolution::Allow) => LayerDecision::Allow,
            Ok(InteractionResolution::Deny(reason)) => LayerDecision::Deny(reason),
            Ok(InteractionResolution::ReplaceInput(value)) => LayerDecision::ReplaceInput(value),
            Err(_) => LayerDecision::Deny("interaction channel dropped".to_owned()),
        }
    }
}

impl InteractiveLayer for SuspendLayer {}
