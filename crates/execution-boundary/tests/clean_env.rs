//! Clean-environment falsification floor (V-AC-2).
//!
//! Uses a synthetic sentinel only. No real credential is read or written.
//!
//! Tests marked REGRESSION correspond to defects found by the independent
//! adversarial review and confirmed before being fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_execution_boundary::env_policy::looks_like_credential_name;
use arcana_execution_boundary::{CleanEnv, EnvError, ALLOWED_TERMS, ALLOWLIST};
use std::path::Path;

const SENTINEL: &str = "SYNTHETIC-SEC0030-ENV-SENTINEL-0123456789";
const SANDBOX: &str = "/run/arcana/sandbox/exec-1";
const SAFE_PATH: &str = "/usr/bin:/bin";

fn built() -> CleanEnv {
    CleanEnv::build(Path::new(SANDBOX), SAFE_PATH).expect("clean env")
}

/// REGRESSION: the previous API allowlisted variable *names* and copied their
/// *values* through unexamined, so `TERM`, `LANG`, `LC_ALL`, `TZ`, `COLORTERM`
/// and `PATH` were six unconstrained channels out of the contaminated parent.
///
/// The fix is structural: there is no longer any way to hand a source
/// environment in. This test pins the *values*, which is what the old fixture
/// failed to do — it only ever placed the sentinel in non-allowlisted names, so
/// it could not have failed.
#[test]
fn all_values_are_constructed_not_inherited() {
    let env = built();
    assert_eq!(env.get("LANG"), Some("C.UTF-8"));
    assert_eq!(env.get("LC_ALL"), Some("C.UTF-8"));
    assert_eq!(env.get("TZ"), Some("UTC"));
    assert_eq!(env.get("TERM"), Some("dumb"));
    assert_eq!(env.get("HOME"), Some(SANDBOX));
    assert_eq!(env.get("PATH"), Some(SAFE_PATH));
    // Exactly the six names, nothing else.
    assert_eq!(env.len(), 6);
    for (name, _) in env.vars() {
        assert!(ALLOWLIST.contains(&name), "unexpected variable `{name}`");
    }
}

/// Even a caller who puts a sentinel in the two caller-supplied values cannot
/// place it anywhere else, and the constructed values are unaffected.
#[test]
fn no_sentinel_reaches_a_constructed_value() {
    let env = built();
    for (name, value) in env.vars() {
        assert!(
            !value.contains(SENTINEL),
            "variable `{name}` carried the sentinel"
        );
    }
}

/// REGRESSION: `CleanEnv` derived `Debug`, so one `debug!(?env)` printed every
/// value it held.
#[test]
fn debug_redacts_values() {
    let rendered = format!("{:?}", built());
    assert!(rendered.contains("redacted"), "values must be redacted");
    assert!(
        !rendered.contains(SANDBOX),
        "Debug must not print variable values"
    );
    assert!(
        rendered.contains("PATH"),
        "names remain useful for debugging"
    );
}

// --- validation: every rejection is fail-closed ---------------------------

/// REGRESSION: `sandbox_home` was accepted unvalidated, including the
/// operator's real home — the exact thing the design says must never happen.
#[test]
fn real_user_home_is_rejected() {
    for home in ["/home/dev", "/Users/dev"] {
        assert_eq!(
            CleanEnv::build(Path::new(home), SAFE_PATH).err(),
            Some(EnvError::HomeIsRealUserHome),
            "`{home}` must not be usable as a sandbox home"
        );
    }
}

#[test]
fn relative_and_traversing_homes_are_rejected() {
    assert_eq!(
        CleanEnv::build(Path::new("relative/path"), SAFE_PATH).err(),
        Some(EnvError::HomeNotAbsolute)
    );
    assert_eq!(
        CleanEnv::build(Path::new(""), SAFE_PATH).err(),
        Some(EnvError::HomeNotAbsolute)
    );
    assert_eq!(
        CleanEnv::build(Path::new("/run/arcana/../../home/dev"), SAFE_PATH).err(),
        Some(EnvError::HomeHasParentComponent)
    );
}

/// REGRESSION: `PATH` was inherited verbatim, so an agent-writable directory
/// could shadow every helper a vendor CLI invokes — a code-execution channel.
#[test]
fn path_components_must_be_absolute_and_non_empty() {
    assert_eq!(
        CleanEnv::build(Path::new(SANDBOX), "").err(),
        Some(EnvError::PathEmpty)
    );
    assert_eq!(
        CleanEnv::build(Path::new(SANDBOX), "/usr/bin::/bin").err(),
        Some(EnvError::PathComponentNotAbsolute)
    );
    assert_eq!(
        CleanEnv::build(Path::new(SANDBOX), "relative/bin:/usr/bin").err(),
        Some(EnvError::PathComponentNotAbsolute)
    );
    assert_eq!(
        CleanEnv::build(Path::new(SANDBOX), ".:/usr/bin").err(),
        Some(EnvError::PathComponentNotAbsolute)
    );
}

/// `TERM` steers terminfo resolution, so it is a closed set rather than a
/// pass-through string.
#[test]
fn term_must_be_in_the_allowed_set() {
    assert_eq!(
        CleanEnv::build_with_term(Path::new(SANDBOX), SAFE_PATH, SENTINEL).err(),
        Some(EnvError::TermNotAllowed)
    );
    for term in ALLOWED_TERMS {
        assert!(CleanEnv::build_with_term(Path::new(SANDBOX), SAFE_PATH, term).is_ok());
    }
}

/// `apply` performs the clear itself, so a caller cannot layer clean variables
/// on top of a full inherited environment by forgetting `env_clear`.
#[test]
fn apply_clears_before_setting() {
    let env = built();
    let mut cmd = std::process::Command::new("/bin/echo");
    env.apply(&mut cmd);
    let names: Vec<String> = cmd
        .get_envs()
        .filter_map(|(k, v)| v.map(|_| k.to_string_lossy().into_owned()))
        .collect();
    for name in &names {
        assert!(
            ALLOWLIST.contains(&name.as_str()),
            "`{name}` reached the command"
        );
    }
    assert_eq!(names.len(), 6);
}

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
        "AWS_ACCESS_KEY_ID",
        "GH_TOKEN",
        "SOME_FUTURE_PROVIDER_CREDENTIAL",
        "db_password",
    ] {
        assert!(looks_like_credential_name(name), "missed `{name}`");
    }
}
