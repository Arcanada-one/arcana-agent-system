//! The lane's model choice must survive an isolated `XDG_STATE_HOME`.
//!
//! Measured on pilot A2-272 (2026-09-24): `arcana run` read its model from
//! `$XDG_STATE_HOME/arcana/model.json`, every isolated runner overrides that
//! directory, and so the run fell through to the tiered policy — its receipt
//! recorded one `grok-3-latest` dispatch followed by five `deepseek-v4-flash`
//! while the lane had pinned a single model. A model choice is operator
//! configuration, not the residue of a run.
//!
//! Every case here runs the real binary in a subprocess with BOTH XDG homes
//! pointed at temporary directories, which is the only way to assert anything
//! about where the choice is read from: an in-process test shares the host's
//! home and would pass against an implementation that ignored the environment
//! entirely.
//!
//! No case here dispatches. `ARCANA_MC_TOKEN` is removed, so the run prints the
//! model it resolved and then refuses to start for want of a key — which is
//! also the proof that the line is printed BEFORE anything is bought.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Homes for one case. Separate directories on purpose: pointing both at one
/// path would put the config file and the legacy state file at the same
/// location and quietly erase the distinction the whole card is about.
struct Homes {
    config: TempDir,
    state: TempDir,
}

impl Homes {
    fn new() -> Self {
        Self {
            config: TempDir::new().unwrap(),
            state: TempDir::new().unwrap(),
        }
    }

    fn config_preference(&self) -> std::path::PathBuf {
        self.config.path().join("arcana").join("model.json")
    }

    fn state_preference(&self) -> std::path::PathBuf {
        self.state.path().join("arcana").join("model.json")
    }
}

fn write_preference(path: &Path, model: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::json!({ "model": model }).to_string()).unwrap();
}

/// A run that resolves a model and then stops, having bought nothing.
///
/// `ARCANA_MODEL` is set or removed EXPLICITLY on every invocation: the test
/// binary inherits the developer's environment, and a case that silently
/// borrowed a real `ARCANA_MODEL` would assert nothing.
fn run(homes: &Homes, work: &TempDir, env_model: Option<&str>) -> Command {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env_remove("ARCANA_MC_TOKEN")
        .env("XDG_CONFIG_HOME", homes.config.path())
        .env("XDG_STATE_HOME", homes.state.path())
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--prompt", "do nothing"]);
    match env_model {
        Some(model) => cmd.env("ARCANA_MODEL", model),
        None => cmd.env_remove("ARCANA_MODEL"),
    };
    cmd
}

#[test]
fn the_environment_carries_the_model_into_an_isolated_state_dir() {
    // The regression, stated as a test: an empty state home is exactly what a
    // runner hands the binary, and the lane's model must still arrive.
    let homes = Homes::new();
    let work = TempDir::new().unwrap();

    run(&homes, &work, Some("lane-model"))
        .assert()
        .failure()
        .stdout(predicate::str::contains("model: lane-model (source: env)"))
        // and it was resolved before the first paid thing was even built.
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN"));
}

#[test]
fn the_config_file_survives_an_isolated_state_dir() {
    let homes = Homes::new();
    let work = TempDir::new().unwrap();
    write_preference(&homes.config_preference(), "configured-model");

    run(&homes, &work, None)
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "model: configured-model (source: config)",
        ));
}

#[test]
fn the_flag_beats_the_environment() {
    let homes = Homes::new();
    let work = TempDir::new().unwrap();

    let mut cmd = run(&homes, &work, Some("from-env"));
    cmd.args(["--model", "from-flag"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("model: from-flag (source: flag)"));
}

#[test]
fn the_environment_beats_the_config_file() {
    let homes = Homes::new();
    let work = TempDir::new().unwrap();
    write_preference(&homes.config_preference(), "configured-model");

    run(&homes, &work, Some("from-env"))
        .assert()
        .failure()
        .stdout(predicate::str::contains("model: from-env (source: env)"));
}

#[test]
fn a_legacy_state_choice_is_still_honoured_and_reported_as_deprecated() {
    // The old file keeps working — an operator's saved choice is not something
    // to delete to make a point — but the run says where it came from, because
    // that file is the one that vanishes under a runner.
    let homes = Homes::new();
    let work = TempDir::new().unwrap();
    write_preference(&homes.state_preference(), "legacy-model");

    run(&homes, &work, None)
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "model: legacy-model (source: legacy-state)",
        ))
        .stderr(predicate::str::contains("deprecated"))
        .stderr(predicate::str::contains("configuration, not run state"));
}

#[test]
fn the_config_file_beats_the_legacy_state_file() {
    let homes = Homes::new();
    let work = TempDir::new().unwrap();
    write_preference(&homes.config_preference(), "configured-model");
    write_preference(&homes.state_preference(), "legacy-model");

    run(&homes, &work, None)
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "model: configured-model (source: config)",
        ))
        .stdout(predicate::str::contains("legacy-model").not());
}

#[test]
fn with_nothing_configured_the_run_says_the_tier_policy_will_choose() {
    // The honest report of a gap. Before this the run said nothing at all, and
    // a receipt listing two different models was the first hint that no choice
    // had reached it.
    let homes = Homes::new();
    let work = TempDir::new().unwrap();

    run(&homes, &work, None)
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "model: tiered dispatch policy — no model configured (source: tier-policy)",
        ));
}

#[test]
fn the_tier_policy_can_be_asked_for_on_purpose() {
    let homes = Homes::new();
    let work = TempDir::new().unwrap();
    write_preference(&homes.config_preference(), "configured-model");

    run(&homes, &work, Some("tier"))
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "tiered dispatch policy — selected explicitly (source: env)",
        ));
}

#[test]
fn models_use_writes_configuration_and_not_run_state() {
    // Where the choice is written is the fix. A `models use` that still wrote
    // to the state home would pass every resolution test above and lose the
    // choice in production exactly as before.
    let homes = Homes::new();

    Command::cargo_bin("arcana")
        .unwrap()
        .env("XDG_CONFIG_HOME", homes.config.path())
        .env("XDG_STATE_HOME", homes.state.path())
        .env_remove("ARCANA_MODEL")
        .args(["models", "use", "chosen-by-operator"])
        .assert()
        .success();

    assert!(
        homes.config_preference().is_file(),
        "the choice belongs in the config home"
    );
    assert!(
        !homes.state_preference().exists(),
        "a model choice must not be written into run state"
    );
}
