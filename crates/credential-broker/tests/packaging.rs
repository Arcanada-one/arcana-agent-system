//! Platform packaging contract (D-REQ-08 / V-AC-7, V-AC-10).
//!
//! These assert the *shipped assets*, which is what an operator actually
//! installs. A hardening directive that is documented but absent from the unit
//! file protects nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn packaging_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging")
}

fn read(rel: &str) -> String {
    let path = packaging_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Credential-shaped assignments that must never appear in a shipped asset.
fn assert_no_credential_shaped_value(text: &str, label: &str) {
    let lower = text.to_ascii_lowercase();
    for marker in [
        "api_key =",
        "api_key=",
        "apikey=",
        "secret =",
        "secret=",
        "token =",
        "token=",
        "password=",
        "bearer ",
        "sk-",
    ] {
        assert!(
            !lower.contains(marker),
            "{label} contains a credential-shaped value (`{marker}`)"
        );
    }
}

#[test]
fn policy_example_contains_no_credential() {
    let policy = read("policy/capability-policy.example.toml");
    assert_no_credential_shaped_value(&policy, "capability policy example");
    // It must still be a usable policy, not an empty file.
    assert!(policy.contains("generation ="));
    assert!(policy.contains("[providers."));
    assert!(policy.contains("executor_uid ="));
}

/// The systemd unit must carry every isolation directive the design depends on.
#[test]
fn systemd_unit_declares_required_isolation() {
    let unit = read("linux/arcana-credential-broker.service");
    for directive in [
        "Type=simple",
        "User=arcana-broker",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        // A core dump would contain the credential in plaintext.
        "LimitCORE=0",
        // Blocks /proc/<pid>/environ inspection of other processes.
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "MemoryDenyWriteExecute=yes",
        "RestrictSUIDSGID=yes",
        "ProtectSystem=strict",
        "RuntimeDirectory=arcana-credential-broker",
    ] {
        assert!(
            unit.contains(directive),
            "systemd unit is missing `{directive}`"
        );
    }
    assert_no_credential_shaped_value(&unit, "systemd unit");
}

/// The credential must never travel through the unit's environment.
#[test]
fn systemd_unit_declares_no_environment_secret() {
    let unit = read("linux/arcana-credential-broker.service");
    for line in unit.lines() {
        let l = line.trim_start();
        if l.starts_with('#') {
            continue;
        }
        assert!(
            !l.starts_with("Environment=") && !l.starts_with("EnvironmentFile="),
            "systemd unit must not set an environment for the broker: `{l}`"
        );
    }
}

#[test]
fn systemd_socket_is_group_scoped_not_world() {
    let sock = read("linux/arcana-credential-broker.socket");
    assert!(sock.contains("SocketMode=0660"), "socket must be 0660");
    assert!(sock.contains("SocketGroup=arcana-executor"));
    assert!(
        !sock.contains("SocketMode=0666") && !sock.contains("SocketMode=0777"),
        "socket must never be world-accessible"
    );
    // A unix socket, not a TCP port: no network exposure surface.
    assert!(sock.contains("ListenStream=/run/"));
}

#[test]
fn tmpfiles_requires_restrictive_credential_source() {
    let tf = read("linux/arcana-credential-broker.tmpfiles.conf");
    assert!(
        tf.contains("/etc/arcana/credential-broker 0700"),
        "credential source directory must be 0700"
    );
    assert!(
        tf.contains("provider.key 0600"),
        "credential file must be 0600"
    );
}

/// The launchd service must be separately accounted, dump-disabled, and must
/// not reintroduce an environment channel.
#[test]
fn launchd_plist_is_separately_accounted_and_env_free() {
    let plist = read("macos/one.arcanada.credential-broker.plist");
    assert!(plist.contains("<key>UserName</key>"));
    assert!(
        plist.contains("_arcanabroker"),
        "launchd service must run as its own account"
    );
    // Match the actual plist element, not a prose mention of it: the asset's
    // own explanatory comment legitimately names the key it refuses to set.
    assert!(
        !plist.contains("<key>EnvironmentVariables</key>"),
        "launchd service must not pass the credential through the environment"
    );
    assert!(
        plist.contains("<key>Core</key>"),
        "core dumps must be disabled"
    );
    // Ships disabled: deployment is an explicit, separate act.
    assert!(plist.contains("<key>Disabled</key>"));
    assert_no_credential_shaped_value(&plist, "launchd plist");
}

/// Both platforms must ship, and an absent platform asset is a hard gate.
#[test]
fn both_platform_assets_exist() {
    for asset in [
        "linux/arcana-credential-broker.service",
        "linux/arcana-credential-broker.socket",
        "linux/arcana-credential-broker.tmpfiles.conf",
        "macos/one.arcanada.credential-broker.plist",
        "policy/capability-policy.example.toml",
    ] {
        let path: &Path = &packaging_root().join(asset);
        assert!(path.exists(), "missing platform asset: {asset}");
    }
}

/// The installer/rollback script must exist and be executable-shaped.
#[test]
fn lifecycle_script_covers_install_verify_disable_rollback() {
    let script = read("broker-lifecycle.sh");
    for verb in ["install", "activate", "verify", "disable", "rollback"] {
        assert!(
            script.contains(&format!("{verb})")),
            "lifecycle script does not handle `{verb}`"
        );
    }
    assert!(script.starts_with("#!"), "lifecycle script needs a shebang");
    assert!(
        script.contains("set -euo pipefail"),
        "lifecycle script must fail closed"
    );
    assert!(
        script.contains("generation_policy")
            && script.contains("install -m 0644 \"$policy\" \"$POLICY_FILE\""),
        "rollback must version and restore deploy-time policy as well as the binary"
    );
}
