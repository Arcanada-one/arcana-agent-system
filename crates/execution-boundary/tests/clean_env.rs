//! Clean-environment falsification floor (V-AC-2).
//!
//! Uses a synthetic sentinel only. No real credential is read or written.

use arcana_execution_boundary::env_policy::looks_like_credential_name;
use arcana_execution_boundary::{CleanEnv, ALLOWLIST};
use std::path::Path;

const SENTINEL: &str = "SYNTHETIC-SEC0030-ENV-SENTINEL-0123456789";

/// A deliberately contaminated source environment, shaped like the real one on
/// the incident host: real provider variable *names*, synthetic values.
fn contaminated() -> Vec<(String, String)> {
    [
        ("PATH", "/usr/bin:/bin"),
        ("HOME", "/home/dev"),
        ("TERM", "xterm-256color"),
        ("LANG", "en_US.UTF-8"),
        ("DEEPSEEK_API_KEY", SENTINEL),
        ("GROQ_API_KEY", SENTINEL),
        ("MOONSHOT_API_KEY", SENTINEL),
        ("OPENROUTER_API_KEY", SENTINEL),
        ("KIMI_API_KEY", SENTINEL),
        ("VAULT_TOKEN", SENTINEL),
        ("AWS_SECRET_ACCESS_KEY", SENTINEL),
        ("GH_TOKEN", SENTINEL),
        ("SOME_FUTURE_PROVIDER_CREDENTIAL", SENTINEL),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

fn reconstructed() -> CleanEnv {
    CleanEnv::reconstruct(contaminated(), Path::new("/run/arcana/sandbox"))
}

#[test]
fn no_sentinel_survives_reconstruction() {
    let env = reconstructed();
    for (name, value) in env.vars() {
        assert!(
            !value.contains(SENTINEL),
            "variable `{name}` leaked the sentinel into the child environment"
        );
    }
}

/// The allowlist is closed: nothing outside it may appear, whatever its name.
#[test]
fn only_allowlisted_names_plus_home_survive() {
    let env = reconstructed();
    for (name, _) in env.vars() {
        assert!(
            ALLOWLIST.contains(&name) || name == "HOME",
            "unexpected variable `{name}` reached the child"
        );
    }
}

/// A *newly invented* credential variable is excluded without anyone updating a
/// denylist — the property that makes this an allowlist rather than a filter.
#[test]
fn unknown_future_credential_is_excluded_by_default() {
    let env = reconstructed();
    assert!(env.get("SOME_FUTURE_PROVIDER_CREDENTIAL").is_none());
    assert!(env.get("DEEPSEEK_API_KEY").is_none());
    assert!(env.get("VAULT_TOKEN").is_none());
}

/// `HOME` is reconstructed to the sandbox, never inherited: a vendor CLI must
/// not be able to reach a credential-bearing config home.
#[test]
fn home_is_reconstructed_to_sandbox() {
    let env = reconstructed();
    assert_eq!(env.home(), Path::new("/run/arcana/sandbox"));
    assert_ne!(env.get("HOME"), Some("/home/dev"));
}

/// The allowlist itself must never contain a credential-shaped name.
#[test]
fn allowlist_contains_no_credential_shaped_name() {
    for name in ALLOWLIST {
        assert!(
            !looks_like_credential_name(name),
            "allowlisted name `{name}` is credential-shaped"
        );
    }
}

#[test]
fn credential_name_heuristic_covers_observed_shapes() {
    for name in [
        "DEEPSEEK_API_KEY",
        "VAULT_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "GH_TOKEN",
        "SOME_FUTURE_PROVIDER_CREDENTIAL",
        "db_password",
    ] {
        assert!(looks_like_credential_name(name), "missed `{name}`");
    }
    for name in ALLOWLIST {
        assert!(!looks_like_credential_name(name));
    }
}

/// An empty source environment still yields a usable, credential-free child env.
#[test]
fn empty_source_yields_safe_defaults() {
    let env = CleanEnv::reconstruct(Vec::<(String, String)>::new(), Path::new("/tmp/sbx"));
    assert_eq!(env.get("PATH"), Some("/usr/bin:/bin"));
    assert_eq!(env.get("HOME"), Some("/tmp/sbx"));
    assert_eq!(env.len(), 2);
}
