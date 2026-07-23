//! ARAS-0051 — offline coverage for the production skills-store cutover helper
//! (`skill_store_from_env`, `V-AC-13`): the `ARCANA_SKILLS_SOURCE` selector maps
//! to the right backend, the bootstrap arm builds **no** network client
//! (offline-safe → trusted `FileStore`), an unrecognised selector is a hard
//! error, and production mode fails closed (never a silent `FileStore`) when the
//! live Scrutator client cannot be constructed.
//!
//! Env-var reads are process-global, so every case serialises on a single mutex
//! and restores the prior values. This is the only test binary that mutates
//! these vars, so it cannot race a sibling binary (separate process).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;

use arcana_connectors::{skill_store_from_env, SkillStoreInitError};
use arcana_skills::StoreKind;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Snapshot + clear the vars `skill_store_from_env` consults, restoring them on
/// drop so cases don't leak state into one another.
struct EnvScope {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvScope {
    fn new() -> Self {
        let keys = [
            "ARCANA_SKILLS_SOURCE",
            "ARCANA_SCRUTATOR_URL",
            "ARCANA_AUTH_TOKEN_URL",
            "ARCANA_KB_CLIENT_SECRET_FILE",
            "CREDENTIALS_DIRECTORY",
        ];
        let saved = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect::<Vec<_>>();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }
        Self { saved }
    }
    fn set(key: &str, value: &str) {
        std::env::set_var(key, value);
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// Bootstrap mode resolves to the trusted `FileStore` and constructs no network
/// client — so it works with **no** OAuth/Scrutator env set (offline-safe).
#[test]
fn bootstrap_selector_yields_file_store_offline() {
    let _guard = ENV_LOCK.lock().unwrap();
    let _env = EnvScope::new();
    EnvScope::set("ARCANA_SKILLS_SOURCE", "bootstrap");

    let store = skill_store_from_env().expect("bootstrap must build offline");
    assert_eq!(store.kind(), StoreKind::File);

    // The `file` alias behaves identically.
    EnvScope::set("ARCANA_SKILLS_SOURCE", "file");
    assert_eq!(
        skill_store_from_env().expect("file alias builds").kind(),
        StoreKind::File
    );
}

/// An unrecognised selector is a hard error — never a silent backend choice.
#[test]
fn unknown_selector_is_a_hard_error() {
    let _guard = ENV_LOCK.lock().unwrap();
    let _env = EnvScope::new();
    EnvScope::set("ARCANA_SKILLS_SOURCE", "filestore-please");

    match skill_store_from_env() {
        Err(SkillStoreInitError::Selector(err)) => {
            assert_eq!(err.value, "filestore-please");
        }
        Err(SkillStoreInitError::Client(err)) => {
            panic!("expected a Selector error, got a Client error: {err:?}")
        }
        Ok(store) => panic!("expected a Selector error, got a {:?} store", store.kind()),
    }
}

/// Production mode (the fail-closed default for an unset selector) with no
/// Scrutator/OAuth credentials configured must FAIL — not silently degrade to
/// the trusted local `FileStore`.
#[test]
fn production_default_fails_closed_without_credentials() {
    let _guard = ENV_LOCK.lock().unwrap();
    let _env = EnvScope::new(); // all relevant vars cleared → no credentials

    match skill_store_from_env() {
        Err(SkillStoreInitError::Client(_)) => { /* fail-closed as required */ }
        Ok(store) => panic!(
            "production mode must fail closed without credentials, got a {:?} store",
            store.kind()
        ),
        Err(other) => panic!("expected a Client error, got {other:?}"),
    }
}
