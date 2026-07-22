#![allow(clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn kb_read_has_no_offline_model_fallback() {
    let mut command = Command::cargo_bin("arcana").expect("arcana binary");
    command
        .env_remove("ARCANA_MC_TOKEN")
        .args(["kb-read", "What is Scrutator?"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Model Connector unavailable"))
        .stderr(predicate::str::contains("offline").not());
}

#[test]
fn kb_read_requires_a_query() {
    let mut command = Command::cargo_bin("arcana").expect("arcana binary");
    command
        .arg("kb-read")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}
