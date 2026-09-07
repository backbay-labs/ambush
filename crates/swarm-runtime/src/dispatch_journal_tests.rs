#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::sync::{Arc, Barrier};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_response::{ExecutionMode, ResponseStatus};

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("ambush-dispatch-journal-{}", uuid::Uuid::new_v4())))
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request() -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-one".into()),
        requested_by: AgentId("agent-one".into()),
        action: ResponseAction::TriggerEdrScan {
            host_id: "host-one".into(),
            scan_profile: "full".into(),
        },
        severity: Severity::High,
        evidence: serde_json::json!({"event":"one"}),
    }
}
fn lease() -> CapabilityLease {
    CapabilityLease {
        capability_id: "cap-one".into(),
        expires_at_ms: 10_000,
        action: request().action.kind().into(),
        scope: Some("host-one".into()),
    }
}
fn receipt() -> Result<ResponseReceipt, ResponseError> {
    Ok(ResponseReceipt {
        receipt_id: "receipt-one".into(),
        action: request().action.kind().into(),
        mode: ExecutionMode::Enforced,
        status: ResponseStatus::Executed,
        summary: "completed".into(),
        details: serde_json::json!({}),
        audit: Default::default(),
    })
}

#[test]
fn reservation_is_on_disk_before_return_and_remains_unknown_after_restart() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let id = journal.reserve(&request(), &lease(), 1).unwrap();
    let persisted = journal.lookup_persisted(&id).unwrap().unwrap();
    assert_eq!(persisted.phase(), DispatchPhase::OutcomeUnknown);
    assert_eq!(persisted.lease.capability_id, "cap-one");
    assert_eq!(persisted.request.evidence["event"], "one");
    let raw = fs::read_to_string(journal.journal_path()).unwrap();
    assert_eq!(raw.lines().count(), 2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(raw.lines().nth(1).unwrap()).unwrap()["kind"],
        "intent"
    );
    drop(journal);
    let reopened = DispatchJournal::open(&dir.0).unwrap();
    assert_eq!(
        reopened.lookup(&id).unwrap().unwrap().phase(),
        DispatchPhase::OutcomeUnknown
    );
    assert!(matches!(
        reopened.reserve(&request(), &lease(), 2),
        Err(DispatchJournalError::AlreadyReserved { .. })
    ));
}

#[test]
fn completed_success_and_failure_never_reauthorize() {
    for outcome in [
        receipt(),
        Err(ResponseError {
            failure: receipt().unwrap().into_failure(),
        }),
    ] {
        let dir = TestDirectory::new();
        let journal = DispatchJournal::open(&dir.0).unwrap();
        let id = journal.reserve(&request(), &lease(), 1).unwrap();
        journal.complete(&id, &outcome).unwrap();
        assert!(matches!(
            journal.complete(&id, &outcome),
            Err(DispatchJournalError::AlreadyCompleted(_))
        ));
        drop(journal);
        let reopened = DispatchJournal::open(&dir.0).unwrap();
        let record = reopened.lookup(&id).unwrap().unwrap();
        assert_eq!(record.phase(), DispatchPhase::Completed);
        assert_eq!(record.completion.unwrap().is_ok(), outcome.is_ok());
        assert!(matches!(
            reopened.reserve(&request(), &lease(), 2),
            Err(DispatchJournalError::AlreadyReserved { .. })
        ));
    }
}

#[test]
fn mutable_evidence_severity_and_lease_do_not_create_another_permission() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let id = journal.reserve(&request(), &lease(), 1).unwrap();
    let mut retry = request();
    retry.severity = Severity::Critical;
    retry.evidence = serde_json::json!({"time": 999, "new":"evidence"});
    let mut renewed = lease();
    renewed.capability_id = "renewed".into();
    renewed.expires_at_ms = 99_999;
    assert_eq!(request_id(&retry).unwrap(), id);
    assert!(matches!(
        journal.reserve(&retry, &renewed, 999),
        Err(DispatchJournalError::AlreadyReserved { .. })
    ));
    retry.action = ResponseAction::TriggerEdrScan {
        host_id: "host-two".into(),
        scan_profile: "full".into(),
    };
    assert_ne!(request_id(&retry).unwrap(), id);
    journal.reserve(&retry, &renewed, 999).unwrap();
}

#[test]
fn concurrent_reservation_has_one_winner() {
    let dir = TestDirectory::new();
    let journal = Arc::new(DispatchJournal::open(&dir.0).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let journal = Arc::clone(&journal);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                journal.reserve(&request(), &lease(), 1)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(DispatchJournalError::AlreadyReserved { .. })))
            .count(),
        7
    );
    assert_eq!(
        fs::read_to_string(journal.journal_path())
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn second_writer_is_rejected_until_owner_drops() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    assert!(matches!(
        DispatchJournal::open(&dir.0),
        Err(DispatchJournalError::AlreadyOpen { .. })
    ));
    drop(journal);
    DispatchJournal::open(&dir.0).unwrap();
}

#[test]
fn missing_lock_cannot_be_repaired_into_a_second_writer() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    fs::remove_file(dir.0.join(LOCK_NAME)).unwrap();
    assert!(DispatchJournal::open(&dir.0).is_err());
    assert!(DispatchJournal::open(&dir.0).is_err());
    assert!(journal.reserve(&request(), &lease(), 1).is_err());
    assert!(matches!(
        journal.reserve(&request(), &lease(), 1),
        Err(DispatchJournalError::Poisoned)
    ));
}

#[test]
fn missing_journal_or_checkpoint_is_never_an_empty_recovery() {
    for missing in [JOURNAL_NAME, MANIFEST_NAME] {
        let dir = TestDirectory::new();
        let journal = DispatchJournal::open(&dir.0).unwrap();
        journal.reserve(&request(), &lease(), 1).unwrap();
        drop(journal);
        fs::remove_file(dir.0.join(missing)).unwrap();
        assert!(DispatchJournal::open(&dir.0).is_err());
        assert!(DispatchJournal::open(&dir.0).is_err());
    }
}

#[test]
fn valid_record_boundary_truncation_is_detected_by_checkpoint() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let original = fs::read(journal.journal_path()).unwrap();
    journal.reserve(&request(), &lease(), 1).unwrap();
    drop(journal);
    fs::write(dir.0.join(JOURNAL_NAME), original).unwrap();
    assert!(matches!(
        DispatchJournal::open(&dir.0),
        Err(DispatchJournalError::Corrupt(_))
    ));
}

#[test]
fn truncated_or_extra_uncommitted_record_fails_closed() {
    for tail in [
        b"{\"kind\":\"intent\"".as_slice(),
        b"{\"kind\":\"header\",\"version\":1}\n".as_slice(),
    ] {
        let dir = TestDirectory::new();
        let journal = DispatchJournal::open(&dir.0).unwrap();
        journal.reserve(&request(), &lease(), 1).unwrap();
        drop(journal);
        OpenOptions::new()
            .append(true)
            .open(dir.0.join(JOURNAL_NAME))
            .unwrap()
            .write_all(tail)
            .unwrap();
        assert!(DispatchJournal::open(&dir.0).is_err());
    }
}

#[test]
fn same_length_corruption_is_detected_even_when_json_parses() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    journal.reserve(&request(), &lease(), 1).unwrap();
    let path = journal.journal_path().to_path_buf();
    drop(journal);
    let original = fs::read_to_string(&path).unwrap();
    let corrupted = original.replace("cap-one", "cap-two");
    assert_eq!(original.len(), corrupted.len());
    fs::write(path, corrupted).unwrap();
    assert!(DispatchJournal::open(&dir.0).is_err());
}

#[test]
fn oversized_request_does_not_consume_permission_or_grow_journal() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let before = fs::metadata(journal.journal_path()).unwrap().len();
    let mut oversized = request();
    oversized.evidence = serde_json::json!({"large":"x".repeat(MAX_DISPATCH_RECORD_BYTES)});
    assert!(matches!(
        journal.reserve(&oversized, &lease(), 1),
        Err(DispatchJournalError::LimitExceeded(_))
    ));
    assert_eq!(fs::metadata(journal.journal_path()).unwrap().len(), before);
    journal.reserve(&request(), &lease(), 1).unwrap();
}

#[test]
fn oversized_completion_leaves_consumed_permission_unknown() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let id = journal.reserve(&request(), &lease(), 1).unwrap();
    let mut huge = receipt().unwrap();
    huge.details = serde_json::json!({"large":"x".repeat(MAX_DISPATCH_RECORD_BYTES)});
    assert!(matches!(
        journal.complete(&id, &Ok(huge)),
        Err(DispatchJournalError::LimitExceeded(_))
    ));
    assert_eq!(
        journal.lookup_persisted(&id).unwrap().unwrap().phase(),
        DispatchPhase::OutcomeUnknown
    );
    assert!(matches!(
        journal.reserve(&request(), &lease(), 2),
        Err(DispatchJournalError::AlreadyReserved { .. })
    ));
}

#[test]
fn write_failure_poisoning_prevents_followup_permission() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    // Keep the same inode and metadata but make the actual write descriptor
    // read-only: validation succeeds, then the production write syscall fails.
    journal.state.lock().unwrap().file = File::open(journal.journal_path()).unwrap();
    assert!(matches!(
        journal.reserve(&request(), &lease(), 1),
        Err(DispatchJournalError::Io { .. })
    ));
    assert!(matches!(
        journal.reserve(&request(), &lease(), 1),
        Err(DispatchJournalError::Poisoned)
    ));
}

#[test]
fn invalid_authorization_and_unknown_completion_cannot_create_records() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let mut expired = lease();
    expired.expires_at_ms = 1;
    assert!(journal.reserve(&request(), &expired, 1).is_err());
    let mut wrong = lease();
    wrong.action = "kill_process".into();
    assert!(journal.reserve(&request(), &wrong, 1).is_err());
    assert!(matches!(
        journal.complete("missing", &receipt()),
        Err(DispatchJournalError::UnknownDispatch(_))
    ));
    assert_eq!(
        fs::read_to_string(journal.journal_path())
            .unwrap()
            .lines()
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn created_storage_is_private_without_relying_on_umask() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    journal.reserve(&request(), &lease(), 1).unwrap();
    assert_eq!(
        fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in [LOCK_NAME, JOURNAL_NAME, MANIFEST_NAME] {
        assert_eq!(
            fs::metadata(dir.0.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn in_place_corruption_blocks_the_next_live_reservation() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    journal.reserve(&request(), &lease(), 1).unwrap();
    let original = fs::read_to_string(journal.journal_path()).unwrap();
    fs::write(
        journal.journal_path(),
        original.replace("cap-one", "cap-two"),
    )
    .unwrap();
    let mut next = request();
    next.hunt_id = HuntId("different-hunt".into());
    assert!(matches!(
        journal.reserve(&next, &lease(), 1),
        Err(DispatchJournalError::Corrupt(_))
    ));
    assert!(matches!(
        journal.reserve(&next, &lease(), 1),
        Err(DispatchJournalError::Poisoned)
    ));
}

#[test]
fn deeply_nested_events_are_refused_before_they_make_recovery_impossible() {
    let dir = TestDirectory::new();
    let journal = DispatchJournal::open(&dir.0).unwrap();
    let mut deep = serde_json::Value::Null;
    for _ in 0..140 {
        deep = serde_json::Value::Array(vec![deep]);
    }
    let mut nested = request();
    nested.evidence = deep.clone();
    assert!(matches!(
        journal.reserve(&nested, &lease(), 1),
        Err(DispatchJournalError::Serialization(_))
    ));
    let id = journal.reserve(&request(), &lease(), 1).unwrap();
    let mut nested_receipt = receipt().unwrap();
    nested_receipt.details = deep;
    assert!(matches!(
        journal.complete(&id, &Ok(nested_receipt)),
        Err(DispatchJournalError::Serialization(_))
    ));
    drop(journal);
    let reopened = DispatchJournal::open(&dir.0).unwrap();
    assert_eq!(
        reopened.lookup(&id).unwrap().unwrap().phase(),
        DispatchPhase::OutcomeUnknown
    );
}

#[test]
fn opener_syncs_the_entire_existing_naming_chain_even_while_creator_is_paused() {
    let dir = TestDirectory::new();
    let leaf = dir.0.join("racing-parent").join("journal");
    let creator_leaf = leaf.clone();
    let (created_tx, created_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let creator = std::thread::spawn(move || {
        // Deliberately pause after mkdir of leaf AND parent, before fsync.
        fs::create_dir_all(&creator_leaf).unwrap();
        created_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        sync_directory(creator_leaf.parent().unwrap()).unwrap();
    });
    created_rx.recv().unwrap();
    let canonical = fs::canonicalize(&leaf).unwrap();
    let expected: Vec<_> = canonical.ancestors().map(Path::to_path_buf).collect();
    let mut seen = Vec::new();
    let journal = DispatchJournal::open_with_directory_sync(&leaf, |path| {
        seen.push(path.to_path_buf());
        sync_directory(path)
    })
    .unwrap();
    assert_eq!(seen, expected);
    journal.reserve(&request(), &lease(), 1).unwrap();
    resume_tx.send(()).unwrap();
    creator.join().unwrap();
}

#[test]
fn existing_unsynced_ancestor_failure_blocks_bootstrap() {
    let dir = TestDirectory::new();
    let leaf = dir.0.join("racing-parent").join("journal");
    fs::create_dir_all(&leaf).unwrap();
    let parent = fs::canonicalize(&leaf)
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut seen = Vec::new();
    let error = DispatchJournal::open_with_directory_sync(&leaf, |path| {
        seen.push(path.to_path_buf());
        if path == parent {
            return Err(io_error(
                path,
                std::io::Error::other("injected ancestor fsync failure"),
            ));
        }
        sync_directory(path)
    })
    .unwrap_err();
    assert!(matches!(error, DispatchJournalError::Io { .. }));
    assert_eq!(seen.last(), Some(&parent));
    assert!(!leaf.join(LOCK_NAME).exists());
    assert!(!leaf.join(JOURNAL_NAME).exists());
    assert!(!leaf.join(MANIFEST_NAME).exists());
}

#[test]
fn entry_capacity_refuses_new_permission_without_evicting_durable_history() {
    let dir = TestDirectory::new();
    let mut journal = DispatchJournal::open(&dir.0).unwrap();
    // Exercise the production algorithm at a small real persisted boundary.
    journal.limits.max_entries = 2;
    let first = request();
    let mut second = request();
    second.hunt_id = HuntId("hunt-two".into());
    let mut third = request();
    third.hunt_id = HuntId("hunt-three".into());
    let first_id = journal.reserve(&first, &lease(), 1).unwrap();
    let second_id = journal.reserve(&second, &lease(), 1).unwrap();
    journal.complete(&first_id, &receipt()).unwrap();
    let before = fs::read(journal.journal_path()).unwrap();
    assert!(matches!(
        journal.reserve(&third, &lease(), 1),
        Err(DispatchJournalError::LimitExceeded("dispatch entry count"))
    ));
    assert_eq!(fs::read(journal.journal_path()).unwrap(), before);
    drop(journal);
    let mut reopened = DispatchJournal::open(&dir.0).unwrap();
    reopened.limits.max_entries = 2;
    assert_eq!(
        reopened.lookup(&first_id).unwrap().unwrap().phase(),
        DispatchPhase::Completed
    );
    assert_eq!(
        reopened.lookup(&second_id).unwrap().unwrap().phase(),
        DispatchPhase::OutcomeUnknown
    );
    assert!(matches!(
        reopened.reserve(&first, &lease(), 2),
        Err(DispatchJournalError::AlreadyReserved { .. })
    ));
    assert!(matches!(
        reopened.reserve(&third, &lease(), 2),
        Err(DispatchJournalError::LimitExceeded("dispatch entry count"))
    ));
    assert_eq!(fs::read(reopened.journal_path()).unwrap(), before);
}

#[test]
fn byte_capacity_refuses_intent_and_completion_without_erasing_unknown_outcome() {
    let dir = TestDirectory::new();
    let mut journal = DispatchJournal::open(&dir.0).unwrap();
    let first = request();
    let first_id = request_id(&first).unwrap();
    let event = JournalEvent::Intent {
        dispatch_id: first_id.clone(),
        request: first.clone(),
        lease: lease(),
        reserved_at_ms: 1,
    };
    let exact_limit = fs::metadata(journal.journal_path()).unwrap().len()
        + serialize_event(&event).unwrap().len() as u64;
    journal.limits.max_bytes = exact_limit;
    journal.reserve(&first, &lease(), 1).unwrap();
    assert_eq!(
        fs::metadata(journal.journal_path()).unwrap().len(),
        exact_limit
    );
    let before = fs::read(journal.journal_path()).unwrap();
    let mut second = request();
    second.hunt_id = HuntId("hunt-two".into());
    assert!(matches!(
        journal.reserve(&second, &lease(), 1),
        Err(DispatchJournalError::LimitExceeded("journal byte count"))
    ));
    assert!(matches!(
        journal.complete(&first_id, &receipt()),
        Err(DispatchJournalError::LimitExceeded("journal byte count"))
    ));
    assert!(
        journal
            .lookup(&request_id(&second).unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read(journal.journal_path()).unwrap(), before);
    drop(journal);
    let mut reopened = DispatchJournal::open(&dir.0).unwrap();
    reopened.limits.max_bytes = exact_limit;
    assert_eq!(
        reopened.lookup(&first_id).unwrap().unwrap().phase(),
        DispatchPhase::OutcomeUnknown
    );
    assert!(matches!(
        reopened.reserve(&first, &lease(), 2),
        Err(DispatchJournalError::AlreadyReserved { .. })
    ));
    assert!(matches!(
        reopened.reserve(&second, &lease(), 2),
        Err(DispatchJournalError::LimitExceeded("journal byte count"))
    ));
    assert_eq!(fs::read(reopened.journal_path()).unwrap(), before);
}
