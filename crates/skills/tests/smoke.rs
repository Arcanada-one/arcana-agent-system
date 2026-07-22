//! P8 / V-AC-8 — the crate loads and a trivial plan validates. The full
//! Rust-only / no-broker / non-regression gate is enforced at the workspace
//! level (cargo build/test/clippy + grep), this test is the crate's entry
//! smoke.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::pedantic)]

use arcana_skills::{Maturity, PlanKind, SkillBuilder};

#[test]
fn skill_smoke() {
    // The crate loads and a builder-emitted plan validates.
    let plan = SkillBuilder::draft_stub("smoke");
    assert_eq!(plan.kind, PlanKind::Template);
    assert_eq!(plan.maturity, Maturity::Draft);
    assert!(plan.validate().is_ok(), "a trivial plan must validate");

    // A round-trip through JSON is lossless (data, not code).
    let text = serde_json::to_string(&plan).unwrap();
    let back: arcana_skills::SkillPlan = serde_json::from_str(&text).unwrap();
    assert_eq!(plan, back);
}
