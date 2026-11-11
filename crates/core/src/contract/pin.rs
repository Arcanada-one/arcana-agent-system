//! The pin: which talomnia-knowledge schema bytes the strict reader enforces, and the check that
//! the bytes compiled into this binary are exactly those.
//!
//! ## How the pinned bytes are held (decision)
//!
//! The schema files are VENDORED byte for byte under `contract/schema/` and compiled in with
//! `include_bytes!`. The pin names, per file, the git blob id the schema owner published
//! (`git hash-object`, i.e. SHA-1 over `blob <len>\0<bytes>`); at run time the reader recomputes
//! that id over the compiled-in bytes and compares. Why this form:
//!
//! * offline and deterministic - no fetch from an unmerged PR at run time, so a strict read can
//!   never depend on the network or on a moving ref;
//! * verifiable in the owner's own vocabulary - the blob ids are the ones in the PR546 tree, so
//!   anybody can re-check them with `git hash-object` or the GitHub contents API;
//! * tamper-evident - a changed vendored byte, or a changed pinned id, refuses with
//!   `CONTRACT_READER_UNSUPPORTED` before any contract byte is read (KC-SWE's code for "a pinned
//!   schema blob mismatch"), never a silent downgrade to a looser reader.
//!
//! SHA-1 is used only because it is the identity git and the schema owner publish; it is an
//! identity check on files this repository vendors, not a security boundary against a chosen-prefix
//! collision (the files are reviewed in the PR that vendors them). The contract bytes themselves
//! are still bound by SHA-256 ([`super::digest_of`]).
//!
//! ## Limitation
//!
//! The commit is the head of OPEN, UNMERGED draft PR546. A squash-merge or an amendment of that PR
//! leaves this commit unreachable from a stable ref, and the pin then has to be moved to the
//! merged commit (new blobs only if the bytes changed) BEFORE PR273 can merge. [`SchemaPin::merged`]
//! is `false` until then and the parity state says so ([`super::SchemaParity::PinnedVerifiedUnmerged`]).

use sha1::{Digest as _, Sha1};

/// One vendored schema file and the blob id the owner published for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedSchema {
    /// File name under `ontology/schemas/` (also the `$ref` target the profile schema uses).
    pub name: &'static str,
    /// Git blob id of the file at [`SchemaPin::commit`].
    pub blob: &'static str,
    /// The vendored bytes, compiled in.
    pub bytes: &'static [u8],
}

/// Identity of the normative talomnia-knowledge schema set this reader enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaPin {
    /// Repository the schemas were published in.
    pub repo: &'static str,
    /// Commit of that repository that holds the files.
    pub commit: &'static str,
    /// `true` only when `commit` is on the repository's default branch.
    pub merged: bool,
    /// Where the commit comes from, for the receipt and for humans.
    pub source: &'static str,
    /// The schema files (every file the profile schema reaches, plus the legacy v2 contract schema).
    pub schemas: &'static [PinnedSchema],
    /// Git blob id of the producer-side reference reader `ontology/src/kc2_tools_profile.py` at
    /// `commit`. NOT vendored: it is the behaviour the parity corpus was measured against.
    pub reference_reader_blob: &'static str,
}

/// File name of the profile schema, the root every strict read validates against.
pub const PROFILE_SCHEMA: &str = "arcanada-kc2-tools-v1.schema.json";

/// The files the profile schema reaches by `$ref`; the reader capability is "these exact blobs".
pub const PROFILE_SCHEMA_FILES: [&str; 4] = [
    "arcanada-kc2-tools-v1.schema.json",
    "kc2-v2-body.schema.json",
    "kc2-v2-closure-manifest.schema.json",
    "common-defs.schema.json",
];

/// THE pin (talomnia-knowledge draft PR546, head `e98c507b...`, filled from the owner's
/// publication in the task brief and re-measured with `git hash-object`; nothing here is guessed).
pub const TALOMNIA_SCHEMA_PIN: Option<SchemaPin> = Some(SchemaPin {
    repo: "Arcanada-one/talomnia-knowledge",
    commit: "e98c507b697baffaabf4f53471420082a13e8488",
    merged: false,
    source: "draft PR546 (open, unmerged) head",
    schemas: &[
        PinnedSchema {
            name: "arcanada-kc2-tools-v1.schema.json",
            blob: "518c85d955abcc0925f10927932e7be5d5565247",
            bytes: include_bytes!("schema/arcanada-kc2-tools-v1.schema.json"),
        },
        PinnedSchema {
            name: "kc2-v2-body.schema.json",
            blob: "20a28176f1c90f5cd0fa0d80f62695e183bfa126",
            bytes: include_bytes!("schema/kc2-v2-body.schema.json"),
        },
        PinnedSchema {
            name: "kc2-v2-closure-manifest.schema.json",
            blob: "90e9db5d0443d72e573237b679e912bc2c1dccab",
            bytes: include_bytes!("schema/kc2-v2-closure-manifest.schema.json"),
        },
        PinnedSchema {
            name: "kc2-v2-contract.schema.json",
            blob: "5e5a2c97e7dbd4183a35ebffa2d0b84d767af4e8",
            bytes: include_bytes!("schema/kc2-v2-contract.schema.json"),
        },
        // Not in the brief's blob list but reached by every `$ref` to a digest or revision id, and
        // pinned by the producer-side reader's own capability set (`PROFILE_SCHEMA_FILES`).
        PinnedSchema {
            name: "common-defs.schema.json",
            blob: "9aa66b7eff2c3e7439b00725ec32f7ee1e8d4523",
            bytes: include_bytes!("schema/common-defs.schema.json"),
        },
    ],
    reference_reader_blob: "f310ab09601ee0367f562a7a049ca9f6d0825ff5",
});

/// Git blob id (`git hash-object`) of `bytes`.
#[must_use]
pub fn git_blob_id(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(40), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Check that the compiled-in bytes are exactly what the pin names. `Err` carries the reason.
///
/// # Errors
/// A profile schema file is missing from the pin, or a file's recomputed blob id differs from the
/// pinned one.
pub fn verify_pin(pin: &SchemaPin) -> Result<(), String> {
    for required in PROFILE_SCHEMA_FILES {
        if !pin.schemas.iter().any(|schema| schema.name == required) {
            return Err(format!(
                "the pin does not name the schema file `{required}`"
            ));
        }
    }
    for schema in pin.schemas {
        let actual = git_blob_id(schema.bytes);
        if actual != schema.blob {
            return Err(format!(
                "schema `{}`: the vendored bytes are blob {actual}, the pin (commit {}) names {}",
                schema.name, pin.commit, schema.blob
            ));
        }
    }
    Ok(())
}
