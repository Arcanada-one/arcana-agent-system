//! G07 D07 at the store level: private path, locking and fencing, parent swap,
//! permission failure, capacity, competing writers.
//!
//! No connector of any kind is involved; this file exercises only the private
//! intent record on a real filesystem (a temporary directory). Durability under
//! power loss and across filesystems is `NOT_MEASURED`: nothing here can show
//! that the kernel honoured `fsync`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use arcana_core::operation_intent::{
    Disposition, IntentError, NewIntent, OperationBinding, OperationIntentConfig, OperationSession,
    MAX_STORE_ENTRIES,
};
use tempfile::TempDir;

/// Fixed per test binary: the authoritative deadline does not move.
fn deadline() -> u64 {
    static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    })
}

fn binding(task: &str) -> OperationBinding {
    OperationBinding {
        task_id: Some(task.into()),
        plan_revision: Some("plan-r1".into()),
        attempt_id: Some("attempt-1".into()),
        lease_fence: Some("lease-1".into()),
        deadline_epoch_s: Some(deadline()),
        dialect_revision: Some("dialect-1".into()),
        reservation_ref: None,
    }
}

fn open(dir: &Path, task: &str) -> Result<OperationSession, IntentError> {
    OperationSession::open(&OperationIntentConfig::new(dir, binding(task)))
}

fn intent(turn: u64) -> NewIntent {
    NewIntent {
        run_id: "0123456789abcdef0123456789abcdef".into(),
        turn,
        provider: "scripted".into(),
        model: Some("test-model".into()),
        request_fingerprint: [7u8; 32],
        idempotency_key: format!("arcana.0123456789abcdef0123456789abcdef.{turn}"),
    }
}

fn store() -> (TempDir, PathBuf) {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("intents");
    (root, dir)
}

#[test]
fn a_new_store_directory_is_private_and_the_record_is_owner_only() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    for entry in std::fs::read_dir(&dir).unwrap() {
        let m = entry.unwrap().metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
    }
}

#[test]
fn d07_group_or_world_accessible_directory_is_refused() {
    let (_root, dir) = store();
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = open(&dir, "task-a").unwrap_err();
    assert_eq!(error.code(), "INTENT_PATH_INSECURE", "{error}");
}

#[test]
fn d07_a_symlink_in_the_store_path_is_never_followed() {
    let root = TempDir::new().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    // The link as the final component.
    assert_eq!(
        open(&link, "task-a").unwrap_err().code(),
        "INTENT_PATH_INSECURE"
    );
    // The link as an ancestor.
    let via = link.join("intents");
    std::fs::create_dir(real.join("intents")).unwrap();
    std::fs::set_permissions(real.join("intents"), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        open(&via, "task-a").unwrap_err().code(),
        "INTENT_PATH_INSECURE"
    );
    // Relative and non-normalized paths.
    assert_eq!(
        open(Path::new("relative/intents"), "task-a")
            .unwrap_err()
            .code(),
        "INTENT_PATH_INSECURE"
    );
    assert_eq!(
        open(&real.join("..").join("real"), "task-a")
            .unwrap_err()
            .code(),
        "INTENT_PATH_INSECURE"
    );
}

#[test]
fn d07_a_symlinked_record_file_is_never_followed() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    drop(session);
    let record = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    let aside = record.with_extension("aside");
    std::fs::rename(&record, &aside).unwrap();
    std::os::unix::fs::symlink(&aside, &record).unwrap();
    assert!(open(&dir, "task-a").is_err());
}

#[test]
fn d07_parent_swap_after_open_refuses_the_write() {
    let (root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    // Swap the verified directory for another one at the same path.
    std::fs::rename(&dir, root.path().join("moved")).unwrap();
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = session.persist_pending(&intent(1)).unwrap_err();
    assert_eq!(error.code(), "INTENT_PARENT_CHANGED", "{error}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing written into the impostor"
    );

    // And a symlink swapped in for the directory.
    let (root, dir) = store();
    let mut session = open(&dir, "task-b").unwrap();
    let moved = root.path().join("moved");
    std::fs::rename(&dir, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &dir).unwrap();
    let error = session.persist_pending(&intent(1)).unwrap_err();
    assert_eq!(error.code(), "INTENT_PARENT_CHANGED", "{error}");
}

#[test]
fn d07_permission_failure_on_write_is_a_typed_refusal_and_leaves_no_record() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let error = session.persist_pending(&intent(1)).unwrap_err();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // The directory mode check fires first (a 0500 directory is no longer the
    // verified private 0700 one) or the staging write is denied; either way it
    // is typed and nothing was published.
    assert!(
        matches!(error.code(), "INTENT_STORE_IO" | "INTENT_PATH_INSECURE"),
        "{error}"
    );
    assert!(std::fs::read_dir(&dir).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".json")));
}

#[test]
fn d07_unreadable_or_loose_record_is_refused() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    drop(session);
    let record = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        open(&dir, "task-a").unwrap_err().code(),
        "INTENT_PATH_INSECURE"
    );
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(open(&dir, "task-a").is_err());
}

#[test]
fn d07_second_opener_of_the_same_task_is_locked_out_and_the_lock_dies_with_the_holder() {
    let (_root, dir) = store();
    let first = open(&dir, "task-a").unwrap();
    assert_eq!(
        open(&dir, "task-a").unwrap_err().code(),
        "INTENT_STORE_LOCKED"
    );
    // A different task is a different scope.
    assert!(open(&dir, "task-b").is_ok());
    drop(first);
    assert!(
        open(&dir, "task-a").is_ok(),
        "lock released when the holder is gone"
    );
}

#[test]
fn d07_a_record_changed_under_the_writer_is_competing_state() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    let record = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    let mut bytes = std::fs::read(&record).unwrap();
    bytes.push(b' ');
    std::fs::write(&record, bytes).unwrap();
    let error = session.mark(Disposition::Unknown, None).unwrap_err();
    assert_eq!(error.code(), "INTENT_STATE_COMPETING", "{error}");
}

#[test]
fn d07_a_misfiled_or_duplicated_record_is_refused() {
    let (_root, dir) = store();
    let mut a = open(&dir, "task-a").unwrap();
    a.persist_pending(&intent(1)).unwrap();
    drop(a);
    drop(open(&dir, "task-b").unwrap());
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let record_a = files
        .iter()
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    // Task b's scope file name, task a's record bytes.
    let lock_b = files
        .iter()
        .find(|p| {
            p.extension().is_some_and(|x| x == "lock") && p.with_extension("json") != *record_a
        })
        .unwrap();
    let copy = lock_b.with_extension("json");
    std::fs::copy(record_a, &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        open(&dir, "task-b").unwrap_err().code(),
        "INTENT_RECORD_MISFILED"
    );
}

#[test]
fn d07_the_store_is_bounded_in_entries_and_refuses_foreign_files() {
    let (_root, dir) = store();
    drop(open(&dir, "task-a").unwrap());
    std::fs::write(dir.join("notes.txt"), b"x").unwrap();
    assert_eq!(
        open(&dir, "task-a").unwrap_err().code(),
        "INTENT_PATH_INSECURE"
    );
    std::fs::remove_file(dir.join("notes.txt")).unwrap();
    for n in 0..=MAX_STORE_ENTRIES {
        let name = format!("{:064x}.json", n + 1);
        std::fs::write(dir.join(name), b"{}").unwrap();
    }
    assert_eq!(
        open(&dir, "task-a").unwrap_err().code(),
        "INTENT_STORE_FULL"
    );
}

#[test]
fn a_record_holds_ids_and_hashes_only() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    session
        .mark(Disposition::Reconciled, Some("response-id-1"))
        .unwrap();
    let record = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    let text = std::fs::read_to_string(record).unwrap();
    assert!(
        !text.contains("response-id-1"),
        "the outcome is stored as a hash"
    );
    assert!(text.len() < 1500, "{}", text.len());
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let keys: Vec<&str> = value["body"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        keys.iter()
            .all(|k| !k.contains("prompt") && !k.contains("token") && !k.contains("secret")),
        "{keys:?}"
    );
}

#[test]
fn a_second_unresolved_operation_cannot_orphan_the_first() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    let error = session.persist_pending(&intent(2)).unwrap_err();
    assert_eq!(error.code(), "INTENT_STATE_COMPETING");
    session.mark(Disposition::Reconciled, Some("r")).unwrap();
    assert!(session.persist_pending(&intent(2)).is_ok());
}

fn record_path(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .expect("record file")
}

fn disposition_of(bytes: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    value["body"]["disposition"].as_str().unwrap().to_owned()
}

fn run_turn_of(bytes: &[u8]) -> (String, u64) {
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let body = &value["body"];
    (
        body["run_id"].as_str().unwrap().to_owned(),
        body["turn"].as_u64().unwrap(),
    )
}

/// Store API (1): same key K with a changed fingerprint A→B must not overwrite
/// the unresolved K/A record.
#[test]
fn unresolved_same_key_with_changed_fingerprint_is_refused_and_bytes_stay() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    let original = intent(1);
    session.persist_pending(&original).unwrap();
    let path = record_path(&dir);
    let before = std::fs::read(&path).unwrap();
    let before_disposition = disposition_of(&before);

    let mut changed = original.clone();
    changed.request_fingerprint = [9u8; 32];
    let error = session.persist_pending(&changed).unwrap_err();
    assert_eq!(error.code(), "INTENT_STATE_COMPETING", "{error}");

    let after = std::fs::read(&path).unwrap();
    assert_eq!(after, before, "retained bytes must not change");
    assert_eq!(disposition_of(&after), before_disposition);
    assert_eq!(disposition_of(&after), "pending");
}

/// Store API (2): same K+A after Unknown must not silently reset to Pending or
/// rewrite run/turn. Replay stays refused unless verified (caller path).
#[test]
fn unknown_same_key_and_fingerprint_is_not_reset_to_pending() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    let original = intent(1);
    session.persist_pending(&original).unwrap();
    session.mark(Disposition::Unknown, None).unwrap();
    let path = record_path(&dir);
    let before = std::fs::read(&path).unwrap();
    let (run_before, turn_before) = run_turn_of(&before);
    assert_eq!(disposition_of(&before), "unknown");

    let mut retry = original.clone();
    retry.run_id = "fedcba9876543210fedcba9876543210".into();
    retry.turn = 99;
    let error = session.persist_pending(&retry).unwrap_err();
    assert_eq!(error.code(), "INTENT_STATE_COMPETING", "{error}");

    let after = std::fs::read(&path).unwrap();
    assert_eq!(
        after, before,
        "Unknown record must be retained byte-for-byte"
    );
    assert_eq!(disposition_of(&after), "unknown");
    let (run_after, turn_after) = run_turn_of(&after);
    assert_eq!(run_after, run_before);
    assert_eq!(turn_after, turn_before);
}

/// Store API (3): a different key while a record is unresolved stays refused
/// (already pinned by `a_second_unresolved_operation_cannot_orphan_the_first`;
/// restated here so the invariant suite names the case explicitly).
#[test]
fn different_key_while_unresolved_is_still_refused() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    let path = record_path(&dir);
    let before = std::fs::read(&path).unwrap();
    let error = session.persist_pending(&intent(2)).unwrap_err();
    assert_eq!(error.code(), "INTENT_STATE_COMPETING", "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

/// Store API (4): after an observed reply (Reconciled), a later operation
/// still persists.
#[test]
fn after_reconciled_a_later_operation_still_persists() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    session
        .mark(Disposition::Reconciled, Some("observed-reply"))
        .unwrap();
    assert_eq!(
        disposition_of(&std::fs::read(record_path(&dir)).unwrap()),
        "reconciled"
    );
    session.persist_pending(&intent(2)).unwrap();
    assert_eq!(
        disposition_of(&std::fs::read(record_path(&dir)).unwrap()),
        "pending"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(record_path(&dir)).unwrap()).unwrap();
    assert_eq!(value["body"]["turn"].as_u64().unwrap(), 2);
}

/// Store API (5): a transition `unseal` would reject (Reconciled with no
/// `outcome_ref`) is refused before persistence; prior bytes stay.
#[test]
fn mark_reconciled_without_outcome_is_refused_before_persistence() {
    let (_root, dir) = store();
    let mut session = open(&dir, "task-a").unwrap();
    session.persist_pending(&intent(1)).unwrap();
    let path = record_path(&dir);
    let before = std::fs::read(&path).unwrap();
    assert_eq!(disposition_of(&before), "pending");

    let error = session.mark(Disposition::Reconciled, None).unwrap_err();
    assert_eq!(error.code(), "INTENT_RECORD_CORRUPT", "{error}");

    let after = std::fs::read(&path).unwrap();
    assert_eq!(after, before, "invalid transition must not publish");
    assert_eq!(disposition_of(&after), "pending");
}
