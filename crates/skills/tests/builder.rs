//! P6 / V-AC-6 — `SkillBuilder::draft_stub` emits a schema-valid Draft/Template
//! plan; once instantiated + promoted to Production it runs through the
//! interpreter.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::dispatch::ModelPolicy;
use arcana_core::tool::Tool;
use arcana_skills::{Maturity, PlanKind, SkillBuilder, SkillInterpreter};
use arcana_tools::model_call::ModelCallTool;

use common::{executor_with, hook_ctx, FakeConnector};

#[tokio::test]
async fn skill_builder_draft_stub() {
    // A drafted stub is a schema-valid Draft template.
    let stub = SkillBuilder::draft_stub("demo");
    assert_eq!(stub.name, "demo");
    assert_eq!(stub.maturity, Maturity::Draft);
    assert_eq!(stub.kind, PlanKind::Template);
    assert!(stub.validate().is_ok(), "draft stub must pass validate()");

    // The run path refuses the raw template stub (Template + Draft).
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir(&audit_dir).unwrap();
    let plan_path = dir.path().join("plan.json");

    let model_call: Arc<dyn Tool> = Arc::new(ModelCallTool::new(
        Arc::new(FakeConnector),
        Arc::new(CostTracker::new()),
        "test-connector",
    ));
    let executor = executor_with(vec![model_call], &audit_dir);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    std::fs::write(&plan_path, serde_json::to_vec(&stub).unwrap()).unwrap();
    assert!(
        interpreter.run(&plan_path, &ctx).await.is_err(),
        "raw draft template must not run"
    );

    // Instantiated + promoted to Production, it runs.
    let runnable = stub.instantiate().promote(Maturity::Production);
    assert_eq!(runnable.kind, PlanKind::Instance);
    assert_eq!(runnable.maturity, Maturity::Production);
    std::fs::write(&plan_path, serde_json::to_vec(&runnable).unwrap()).unwrap();
    let out = interpreter
        .run(&plan_path, &ctx)
        .await
        .expect("runnable ok");
    assert_eq!(out.stages.len(), 1);
}
