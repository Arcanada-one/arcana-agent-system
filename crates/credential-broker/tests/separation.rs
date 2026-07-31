//! Identity- and linkage-separation proofs (D-REQ-01 / V-AC-2, V-AC-5, V-AC-12).
//!
//! Repository co-location must not merge the process or identity boundaries.
//! These tests assert that mechanically, rather than trusting a convention.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_credential_broker::audit::{AuditRecord, CausalIds, EventKind};
use arcana_credential_broker::protocol::{Generation, Operation};
use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_root().join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The library must contain no credential-reading code. Only the binary may.
#[test]
fn library_contains_no_secret_loading_code() {
    let src = crate_root().join("src");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&src).expect("src dir").flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = read(&path);
        for (n, line) in text.lines().enumerate() {
            let l = line.trim_start();
            if l.starts_with("//") || l.starts_with('*') {
                continue;
            }
            // Any filesystem read or environment read in the library would be a
            // route to the credential source.
            for marker in [
                "read_to_string",
                "std::env::var",
                "env::var",
                "File::open",
                "fs::read",
            ] {
                if l.contains(marker) {
                    offenders.push(format!("{}:{} {marker}", path.display(), n + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "credential-broker library must contain no secret-loading path; found: {offenders:?}"
    );
}

/// The execution boundary must not link the broker: an agent-side crate that
/// depends on the broker could be built into the same address space.
#[test]
fn execution_boundary_does_not_depend_on_broker() {
    let manifest = read(&workspace_root().join("crates/execution-boundary/Cargo.toml"));
    assert!(
        !manifest.contains("credential-broker"),
        "execution-boundary must not depend on the credential broker"
    );
}

/// The broker binary is a distinct compilation unit, declared as its own bin.
#[test]
fn broker_binary_is_declared_separately() {
    let manifest = read(&crate_root().join("Cargo.toml"));
    assert!(manifest.contains("[[bin]]"));
    assert!(manifest.contains("arcana-credential-broker"));
    assert!(
        crate_root()
            .join("src/bin/arcana-credential-broker.rs")
            .exists(),
        "broker binary source must exist"
    );
}

/// A lease is a permission, not a secret: no field can carry credential material.
#[test]
fn lease_carries_no_credential_field() {
    let protocol = read(&crate_root().join("src/protocol.rs"));
    // Locate the Lease struct body and assert it declares no secret-shaped field.
    let start = protocol.find("pub struct Lease").expect("Lease struct");
    let body = &protocol[start..];
    let end = body.find("\n}").expect("struct end");
    let body = &body[..end].to_ascii_lowercase();
    for forbidden in ["key", "secret", "token", "credential", "authorization"] {
        assert!(
            !body.contains(forbidden),
            "Lease must not declare a `{forbidden}`-shaped field"
        );
    }
}

// --- audit secret-safety ---------------------------------------------------

/// The audit record has no free-form payload field, so there is structurally
/// nowhere to put a credential, a response body, or transcript content.
#[test]
fn audit_record_has_no_free_form_payload() {
    let audit = read(&crate_root().join("src/audit.rs"));
    let start = audit.find("pub struct AuditRecord").expect("AuditRecord");
    let body = &audit[start..];
    let end = body.find("\n}").expect("struct end");
    let body = &body[..end].to_ascii_lowercase();
    for forbidden in ["payload", "body", "content", "message", "raw", "excerpt"] {
        assert!(
            !body.contains(forbidden),
            "AuditRecord must not declare a `{forbidden}` field"
        );
    }
}

/// A fully-populated record renders every required causal ID and no content.
#[test]
fn audit_record_renders_required_causal_ids() {
    let mut rec = AuditRecord::new(1_700_000_000, EventKind::PolicyAllow);
    rec.ids = CausalIds {
        incident: Some("SEC-0030".to_owned()),
        execution: Some("exec-1".to_owned()),
        host_boot: Some("boot-1".to_owned()),
        process_tree: Some("ptree-1".to_owned()),
        pane_session: Some("pane-1".to_owned()),
        credential_id: Some("provider-primary".to_owned()),
        credential_version: Some(2),
        lease: Some("lease-1".to_owned()),
        generation: Some(Generation(7)),
        output_scan: Some("scan-1".to_owned()),
        transcript_artifact: Some("artifact-1".to_owned()),
        provider_request: Some("preq-1".to_owned()),
        provider_revocation: Some("prev-1".to_owned()),
        vault_accessor: Some("accessor-1".to_owned()),
        deployment: Some("deploy-1".to_owned()),
        canary: Some("canary-1".to_owned()),
    };
    rec.provider = Some("mockprovider".to_owned());
    rec.model = Some("model-small".to_owned());
    rec.operation = Some(Operation::Completion);
    rec.charged = Some(1);
    rec.count = Some(42);
    rec.artifact_sha256 = Some("a".repeat(64));

    let line = rec.to_string();
    for required in [
        "incident=",
        "execution=",
        "host_boot=",
        "process_tree=",
        "pane_session=",
        "credential_id=",
        "credential_version=",
        "lease=",
        "generation=",
        "output_scan=",
        "transcript_artifact=",
        "provider_request=",
        "provider_revocation=",
        "vault_accessor=",
        "deployment=",
        "canary=",
    ] {
        assert!(line.contains(required), "audit line missing `{required}`");
    }
    // The credential *identifier* appears; no credential value can.
    assert!(line.contains("credential_id=provider-primary"));
}

/// The broker binary must never render the credential it loads.
#[test]
fn broker_binary_never_prints_the_credential() {
    let bin = read(&crate_root().join("src/bin/arcana-credential-broker.rs"));
    for (n, line) in bin.lines().enumerate() {
        let l = line.trim_start();
        if l.starts_with("//") || l.starts_with('*') {
            continue;
        }
        let prints = l.contains("println!") || l.contains("eprintln!") || l.contains("dbg!");
        if prints {
            assert!(
                !l.contains("credential)") && !l.contains("{credential}"),
                "line {} renders the credential value",
                n + 1
            );
        }
    }
    // The credential type must not be derived-Debug into any output.
    assert!(
        !bin.contains("{credential:?}"),
        "credential must never be Debug-formatted"
    );
}
