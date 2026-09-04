#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use swarm_core::types::ResponseAction;

// The fixtures live in `held_action_fixtures` so `swarm-runtime-http` and
// `swarm-ingest-runtime` can build the same records across the crate line; a
// `#[cfg(test)]` module here would be invisible to them.
pub(crate) use crate::held_action_fixtures::{T0, fixture_hold};

/// The top-level object keys of one JSON document, in emitted order.
///
/// A five-line scanner rather than a parse, because every parse into a
/// `serde_json::Value` re-sorts the keys and destroys the property under test.
fn top_level_keys(json: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let bytes = json.as_bytes();
    let mut depth: i32 = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b'"' => {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b'"' {
                    // Skip an escaped character so a `\"` inside a value does not
                    // end the string early.
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let literal = &json[start..end.min(json.len())];
                let is_key = json[end + 1..]
                    .bytes()
                    .find(|byte| !byte.is_ascii_whitespace())
                    == Some(b':');
                if depth == 1 && is_key {
                    keys.push(literal.to_string());
                }
                index = end;
            }
            _ => {}
        }
        index += 1;
    }
    keys
}

#[test]
fn a_minted_hold_id_matches_the_wire_pattern_and_is_v4() {
    let id = mint_hold_id();
    assert_eq!(id.len(), 41);
    assert!(id.starts_with("hold_"));
    assert!(is_opaque_hold_id(&id));
    assert!(!id.contains(':'));
    let uuid = &id["hold_".len()..];
    assert_eq!(uuid.as_bytes()[14], b'4');
    assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
}

#[test]
fn the_pattern_refuses_the_derived_colon_form() {
    assert!(!is_opaque_hold_id("hold:hunt-evt-1:1773739200000"));
    assert!(!is_opaque_hold_id("short"));
    assert!(!is_opaque_hold_id("_leading-underscore"));
    assert!(is_opaque_hold_id("h_a07aeacf"));
}

#[test]
fn the_record_serializes_in_verdict_pane_order() {
    let hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".to_string(),
        },
        T0,
    );
    // Read the key order off the SERIALIZED TEXT, not off `serde_json::to_value`:
    // `serde_json::Map` is a `BTreeMap` unless the `preserve_order` feature is on
    // (it is not, workspace-wide), so `to_value` sorts the keys alphabetically and
    // would hide the declaration order entirely. `to_string` runs the derived
    // serializer, which emits fields in declaration order — the order a consumer
    // on the wire actually sees.
    let json = serde_json::to_string(&hold).unwrap();
    let keys = top_level_keys(&json);
    // Every field, so a scanner that stopped early could not pass the order
    // assertions vacuously.
    assert_eq!(keys.len(), 18, "{keys:?}");
    // ACTION -> BLAST RADIUS -> IF YOU UNDO -> WHY WE ARE ASKING -> WHAT GRANTING OPENS
    // rides as: action_request -> rehearsal -> (inverse is derived) -> rationale -> expires_at_ms.
    let position = |name: &str| {
        keys.iter()
            .position(|key| key == name)
            .unwrap_or_else(|| panic!("no key `{name}` in {keys:?}"))
    };
    assert!(position("action_request") < position("rehearsal"));
    assert!(position("rehearsal") < position("policy_decision"));
    assert!(position("policy_decision") < position("rationale"));
    assert!(position("rationale") < position("expires_at_ms"));
    assert!(position("hold_id") == 0 && position("state") == 1);
}

#[test]
fn only_the_four_containment_actions_lease_a_containment() {
    let leased = [
        ResponseAction::QuarantineFile {
            host_id: "h".into(),
            file_path: "/tmp/x".into(),
        },
        ResponseAction::SuspendProcess {
            host_id: "h".into(),
            process_name: "p".into(),
        },
        ResponseAction::IsolateHost {
            host_id: "h".into(),
        },
        ResponseAction::TerminateUserSession {
            host_id: "h".into(),
            session_id: "s".into(),
        },
    ];
    for action in leased {
        assert!(fixture_hold(action, T0).leases_a_containment());
    }
    assert!(
        !fixture_hold(
            ResponseAction::BlockEgress {
                target: "203.0.113.10".into()
            },
            T0
        )
        .leases_a_containment()
    );
    assert!(
        !fixture_hold(
            ResponseAction::KillProcess {
                host_id: "h".into(),
                process_name: "p".into()
            },
            T0
        )
        .leases_a_containment()
    );
}

#[test]
fn decidable_is_created_notified_or_armed_and_not_expired() {
    let mut hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "h".into(),
        },
        T0,
    );
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    hold.state = HoldState::Notified;
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    hold.state = HoldState::Armed;
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    assert_eq!(
        hold.assert_decidable(T0 + 3_600_000).unwrap_err(),
        NotDecidable::Expired
    );
    hold.state = HoldState::Deciding;
    assert_eq!(
        hold.assert_decidable(T0 + 1).unwrap_err(),
        NotDecidable::Deciding
    );
    hold.state = HoldState::Refused;
    assert_eq!(
        hold.assert_decidable(T0 + 1).unwrap_err(),
        NotDecidable::Terminal
    );
}

fn memory_store_with_hold(state: HoldState) -> (MemoryHeldActionStore, String) {
    let store = MemoryHeldActionStore::default();
    let mut hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".into(),
        },
        T0,
    );
    hold.state = state;
    if state == HoldState::Notified {
        hold.notified_at_ms = Some(T0 + 10);
    }
    let id = hold.hold_id.clone();
    store.create(hold).unwrap();
    (store, id)
}

fn refused_record(intent: &str) -> HoldDecisionRecord {
    HoldDecisionRecord {
        decision: HoldDecision::Refuse,
        operator_id: "perch-dev-operator".into(),
        voter_id: format!("swarm:ed25519:{}", "ab".repeat(32)),
        rationale_sha256: None,
        hold_notice_published: false,
        governance_clearance: GovernanceClearance::NotRequired,
        decided_at_ms: T0 + 100,
        nostr_intent_event_id: intent.to_string(),
        signature: None,
        rationale: None,
        outcome: HoldOutcome::RefusedByOperator,
        dispatched: false,
        receipt_id: None,
        audit_trail_id: None,
        refusal: None,
        partition_state_at_execution: None,
    }
}

const INTENT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INTENT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn created_is_decidable_and_the_cas_records_the_prior_state() {
    let (store, id) = memory_store_with_hold(HoldState::Created);
    let claimed = store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    assert_eq!(claimed.state, HoldState::Deciding);
    assert_eq!(claimed.prior_state, Some(HoldState::Created));
    assert_eq!(claimed.deciding_intent_event_id.as_deref(), Some(INTENT_A));
    assert_eq!(claimed.cas_instant_ms, Some(T0 + 100));
}

#[test]
fn a_second_decision_on_a_deciding_hold_is_refused_with_the_current_record() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    let error = store.begin_decision(&id, INTENT_B, T0 + 101).unwrap_err();
    match error {
        HeldActionStoreError::NotDecidable { current, .. } => {
            assert_eq!(current.state, HoldState::Deciding);
            assert_eq!(current.deciding_intent_event_id.as_deref(), Some(INTENT_A));
        }
        other => panic!("expected NotDecidable, got {other:?}"),
    }
}

/// The double-grant proof. Sixteen threads race one compare-and-set on one
/// hold; exactly one may win, and the loser count must equal the thread count
/// minus one. A store that read-then-wrote outside the lock would let two
/// callers past here and dispatch the same destructive action twice.
#[test]
fn concurrent_claims_on_one_hold_produce_exactly_one_winner() {
    for round in 0..25 {
        let store = std::sync::Arc::new(MemoryHeldActionStore::default());
        let mut hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            T0,
        );
        hold.state = HoldState::Notified;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let losers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for slot in 0..16u8 {
            let store = std::sync::Arc::clone(&store);
            let barrier = std::sync::Arc::clone(&barrier);
            let winners = std::sync::Arc::clone(&winners);
            let losers = std::sync::Arc::clone(&losers);
            let id = id.clone();
            handles.push(std::thread::spawn(move || {
                let intent = format!("{slot:02x}").repeat(32);
                barrier.wait();
                match store.begin_decision(&id, &intent, T0 + 100) {
                    Ok(claimed) => {
                        assert_eq!(claimed.deciding_intent_event_id.as_deref(), Some(&*intent));
                        winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(HeldActionStoreError::NotDecidable { current, .. }) => {
                        assert_eq!(current.state, HoldState::Deciding);
                        losers.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(other) => panic!("unexpected error {other:?}"),
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            winners.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "round {round}: more than one claim won the compare-and-set"
        );
        assert_eq!(losers.load(std::sync::atomic::Ordering::SeqCst), 15);
        // And the record names exactly one winner.
        let hold = store.get(&id).unwrap().unwrap();
        assert_eq!(hold.state, HoldState::Deciding);
        assert!(hold.deciding_intent_event_id.is_some());
    }
}

/// Concurrent claims followed by concurrent completions: one hold, sixteen
/// racing decisions, and only the claim holder may write a terminal record.
#[test]
fn only_the_claim_holder_can_complete_a_decision() {
    let store = std::sync::Arc::new(MemoryHeldActionStore::default());
    let mut hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".into(),
        },
        T0,
    );
    hold.state = HoldState::Notified;
    let id = hold.hold_id.clone();
    store.create(hold).unwrap();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
    let dispatched = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::new();
    for slot in 0..16u8 {
        let store = std::sync::Arc::clone(&store);
        let barrier = std::sync::Arc::clone(&barrier);
        let dispatched = std::sync::Arc::clone(&dispatched);
        let id = id.clone();
        handles.push(std::thread::spawn(move || {
            let intent = format!("{slot:02x}").repeat(32);
            barrier.wait();
            let store_ref: &dyn HeldActionStore = &*store;
            if let Ok(claim) = DecisionClaim::begin(store_ref, &id, &intent, T0 + 100) {
                // Only the winner reaches the dispatch site.
                dispatched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                claim
                    .complete(refused_record(&intent), HoldState::Refused)
                    .unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(dispatched.load(std::sync::atomic::Ordering::SeqCst), 1);
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Refused);
    assert_eq!(
        hold.decision.as_ref().unwrap().outcome,
        HoldOutcome::RefusedByOperator
    );
}

#[test]
fn the_cas_rechecks_expiry_inside_the_lock() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let error = store
        .begin_decision(&id, INTENT_A, T0 + 3_600_000)
        .unwrap_err();
    assert!(matches!(error, HeldActionStoreError::NotDecidable { .. }));
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Notified);
}

#[test]
fn abandon_restores_the_prior_state_and_is_idempotent() {
    let (store, id) = memory_store_with_hold(HoldState::Armed);
    store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    store.abandon_decision(&id, INTENT_A).unwrap();
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Armed);
    assert_eq!(hold.deciding_intent_event_id, None);
    assert_eq!(hold.prior_state, None);
    // Abandoning again, or with the wrong id, is a no-op and not an error.
    store.abandon_decision(&id, INTENT_A).unwrap();
    store.abandon_decision(&id, INTENT_B).unwrap();
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Armed);
}

#[test]
fn every_pre_dispatch_refusal_leaves_the_hold_decidable() {
    // The Drop guard is the load-bearing half: every early return between the
    // CAS and complete_decision abandons, including ones nobody has written.
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    fn early_return(store: &dyn HeldActionStore, id: &str) -> Result<(), HeldActionStoreError> {
        let claim = DecisionClaim::begin(store, id, INTENT_A, T0 + 100)?;
        let _ = claim.claimed();
        Err(HeldActionStoreError::Poisoned) // an injected pre-dispatch failure
    }
    let _ = early_return(&store, &id);
    assert_eq!(
        store.get(&id).unwrap().unwrap().state,
        HoldState::Notified,
        "the guard parked the hold in deciding"
    );
}

/// A panic between the compare-and-set and the terminal write must also
/// release the claim: `Drop` runs while unwinding, so an injected panic proves
/// the guard covers the paths no `?` can reach.
#[test]
fn a_panic_between_the_cas_and_the_write_also_releases_the_claim() {
    let (store, id) = memory_store_with_hold(HoldState::Armed);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let store_ref: &dyn HeldActionStore = &store;
        let _claim = DecisionClaim::begin(store_ref, &id, INTENT_A, T0 + 100).unwrap();
        panic!("an injected fault between the claim and the dispatch");
    }));
    assert!(outcome.is_err());
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Armed);
    assert_eq!(hold.deciding_intent_event_id, None);
    assert!(hold.decision.is_none(), "a panic must not write a decision");
}

#[test]
fn complete_disarms_the_guard_and_writes_the_terminal_record() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let claim = DecisionClaim::begin(&store, &id, INTENT_A, T0 + 100).unwrap();
    claim
        .complete(refused_record(INTENT_A), HoldState::Refused)
        .unwrap();
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Refused);
    assert_eq!(
        hold.decision.as_ref().unwrap().nostr_intent_event_id,
        INTENT_A
    );
    assert_eq!(hold.deciding_intent_event_id.as_deref(), Some(INTENT_A));
    assert_eq!(hold.prior_state, None);
    // A retry on a terminal hold with the same id sees the stored record.
    let error = store.begin_decision(&id, INTENT_A, T0 + 200).unwrap_err();
    assert!(matches!(error, HeldActionStoreError::NotDecidable { .. }));
}

/// A refusal is terminal and dispatches nothing, and no later call -- retry,
/// sweep or expiry -- can turn it into a grant.
#[test]
fn a_refusal_is_terminal_and_no_later_sweep_can_reopen_it() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let claim = DecisionClaim::begin(&store, &id, INTENT_A, T0 + 100).unwrap();
    claim
        .complete(refused_record(INTENT_A), HoldState::Refused)
        .unwrap();
    let stored = store.get(&id).unwrap().unwrap();
    assert!(!stored.decision.as_ref().unwrap().dispatched);

    // Past the TTL, and past the stall bound.
    assert!(store.expire_due(T0 + 3_600_001).unwrap().is_empty());
    assert!(
        store
            .fail_stalled_decisions(T0 + 3_600_001, 60_000)
            .unwrap()
            .is_empty()
    );
    // A retry cannot claim it, and the record is unchanged.
    assert!(store.begin_decision(&id, INTENT_B, T0 + 200).is_err());
    let after = store.get(&id).unwrap().unwrap();
    assert_eq!(after.state, HoldState::Refused);
    assert_eq!(
        after.decision.as_ref().unwrap().decision,
        HoldDecision::Refuse
    );
    assert!(!after.decision.as_ref().unwrap().dispatched);
}

#[test]
fn list_is_sorted_by_expiry_then_id_and_hides_terminal_by_default() {
    let store = MemoryHeldActionStore::default();
    let mut late = fixture_hold(ResponseAction::BlockEgress { target: "a".into() }, T0 + 5);
    late.hold_id = "hold_zzzzzzzz-0000-4000-8000-000000000000".into();
    let mut early = fixture_hold(ResponseAction::BlockEgress { target: "b".into() }, T0);
    early.hold_id = "hold_aaaaaaaa-0000-4000-8000-000000000000".into();
    let mut done = fixture_hold(ResponseAction::BlockEgress { target: "c".into() }, T0);
    done.hold_id = "hold_bbbbbbbb-0000-4000-8000-000000000000".into();
    done.state = HoldState::Refused;
    for hold in [late.clone(), early.clone(), done.clone()] {
        store.create(hold).unwrap();
    }
    let open: Vec<String> = store
        .list(false, 10)
        .unwrap()
        .into_iter()
        .map(|hold| hold.hold_id)
        .collect();
    assert_eq!(open, vec![early.hold_id.clone(), late.hold_id.clone()]);
    assert_eq!(store.list(true, 10).unwrap().len(), 3);
    assert_eq!(store.list(true, 1).unwrap().len(), 1);
}

#[test]
fn mark_case_channel_and_mark_notified_move_created_to_notified() {
    let (store, id) = memory_store_with_hold(HoldState::Created);
    store
        .mark_case_channel(&id, "27799e23-ab25-4659-b381-3de47ea7ca4d")
        .unwrap();
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Created);
    store
        .mark_notified(&id, T0 + 50, &"cd".repeat(32), Some(&"ef".repeat(32)))
        .unwrap();
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Notified);
    assert_eq!(hold.notified_at_ms, Some(T0 + 50));
    assert_eq!(
        hold.case_channel.as_deref(),
        Some("27799e23-ab25-4659-b381-3de47ea7ca4d")
    );
    assert_eq!(
        hold.notice_event_id.as_deref(),
        Some("cd".repeat(32).as_str())
    );
}

#[test]
fn a_duplicate_hold_id_is_refused_and_leaves_the_first_record_intact() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let mut second = fixture_hold(
        ResponseAction::BlockEgress {
            target: "203.0.113.10".into(),
        },
        T0 + 1,
    );
    second.hold_id = id.clone();
    let error = store.create(second).unwrap_err();
    assert!(matches!(error, HeldActionStoreError::Duplicate { .. }));
    let stored = store.get(&id).unwrap().unwrap();
    assert_eq!(stored.action_request.action.kind(), "isolate_host");
    assert_eq!(stored.state, HoldState::Notified);
}

#[test]
fn a_store_operation_on_an_unknown_hold_is_not_found_and_creates_nothing() {
    let store = MemoryHeldActionStore::default();
    assert!(store.get("hold_missing0").unwrap().is_none());
    for error in [
        store.mark_case_channel("hold_missing0", "c").unwrap_err(),
        store
            .mark_notified("hold_missing0", T0, "e", None)
            .unwrap_err(),
        store.mark_armed("hold_missing0", T0).unwrap_err(),
        store
            .begin_decision("hold_missing0", INTENT_A, T0)
            .unwrap_err(),
        store
            .complete_decision(
                "hold_missing0",
                refused_record(INTENT_A),
                HoldState::Refused,
            )
            .unwrap_err(),
    ] {
        assert!(matches!(error, HeldActionStoreError::NotFound { .. }));
    }
    // abandon is deliberately idempotent, so an unknown id is not an error.
    store.abandon_decision("hold_missing0", INTENT_A).unwrap();
    assert!(store.list(true, 10).unwrap().is_empty());
}

#[test]
fn health_reports_the_memory_backend_as_not_durable_and_counts_stalled_claims() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let health = store.health(T0, 60_000).unwrap();
    assert!(!health.durable);
    assert_eq!(health.backend, "memory");
    assert_eq!(health.open_holds, 1);
    assert_eq!(health.deciding_stalled, 0);

    store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    let health = store.health(T0 + 100, 60_000).unwrap();
    assert_eq!(health.open_holds, 0, "deciding is not open");
    assert_eq!(health.deciding_stalled, 0);
    assert_eq!(
        store
            .health(T0 + 100 + 60_000, 60_000)
            .unwrap()
            .deciding_stalled,
        1
    );
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "held-action-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_file_store_recovers_an_open_hold_after_a_restart() {
    let dir = temp_dir("restart");
    let id = {
        let store = FileHeldActionStore::open(&dir).unwrap();
        let hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            T0,
        );
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        store
            .mark_notified(&id, T0 + 5, &"cd".repeat(32), None)
            .unwrap();
        id
    };
    let reopened = FileHeldActionStore::open(&dir).unwrap();
    let hold = reopened.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Notified);
    assert!(reopened.health(T0, 60_000).unwrap().durable);
    assert_eq!(reopened.health(T0, 60_000).unwrap().backend, "local_files");
}

/// Exactly one decision record is authoritative across a restart: a completed
/// decision reloads byte-identically, and the reopened store neither invents a
/// second one nor drops the one on disk.
#[test]
fn a_restart_recovers_the_one_decision_record_without_inventing_or_losing_one() {
    let dir = temp_dir("decision-restart");
    let (id, before) = {
        let store = FileHeldActionStore::open(&dir).unwrap();
        let hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            T0,
        );
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        store
            .mark_notified(&id, T0 + 5, &"cd".repeat(32), None)
            .unwrap();
        let store_ref: &dyn HeldActionStore = &store;
        let claim = DecisionClaim::begin(store_ref, &id, INTENT_A, T0 + 100).unwrap();
        claim
            .complete(refused_record(INTENT_A), HoldState::Refused)
            .unwrap();
        let before = store.get(&id).unwrap().unwrap();
        (id, before)
    };

    let reopened = FileHeldActionStore::open(&dir).unwrap();
    let after = reopened.get(&id).unwrap().unwrap();
    assert_eq!(after.state, HoldState::Refused);
    assert_eq!(after.decision, before.decision, "the decision changed");
    assert_eq!(
        after.decision.as_ref().unwrap().nostr_intent_event_id,
        INTENT_A
    );
    assert!(!after.decision.as_ref().unwrap().dispatched);
    assert_eq!(reopened.list(true, 10).unwrap().len(), 1, "one record only");

    // And the reopened store refuses a second decision on it.
    let error = reopened
        .begin_decision(&id, INTENT_B, T0 + 200)
        .unwrap_err();
    assert!(matches!(error, HeldActionStoreError::NotDecidable { .. }));
    assert_eq!(
        reopened.get(&id).unwrap().unwrap().decision,
        before.decision
    );
}

#[test]
fn a_deciding_hold_is_reloaded_as_deciding_and_resolved_by_the_sweep_not_by_a_guess() {
    let dir = temp_dir("deciding");
    let id = {
        let store = FileHeldActionStore::open(&dir).unwrap();
        let hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            T0,
        );
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
        id
    };
    let reopened = FileHeldActionStore::open(&dir).unwrap();
    assert_eq!(
        reopened.get(&id).unwrap().unwrap().state,
        HoldState::Deciding
    );
    assert!(
        reopened
            .fail_stalled_decisions(T0 + 100 + 59_999, 60_000)
            .unwrap()
            .is_empty()
    );
    let failed = reopened
        .fail_stalled_decisions(T0 + 100 + 60_000, 60_000)
        .unwrap();
    assert_eq!(failed.len(), 1);
    let hold = reopened.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Failed);
    let decision = hold.decision.unwrap();
    assert!(!decision.dispatched, "a stalled decision never dispatched");
    let refusal = decision.refusal.unwrap();
    assert_eq!(refusal.rule, "runtime.capability_lease_expired");
    assert!(refusal.reason.contains("whether the action ran is unknown"));

    // The resolution is itself durable.
    let again = FileHeldActionStore::open(&dir).unwrap();
    assert_eq!(again.get(&id).unwrap().unwrap().state, HoldState::Failed);
}

#[test]
fn a_torn_document_is_reported_as_corrupt_not_skipped() {
    let dir = temp_dir("torn");
    std::fs::write(dir.join("hold_torn.json"), b"{\"hold_id\": \"hold_torn").unwrap();
    let error = FileHeldActionStore::open(&dir).unwrap_err();
    assert!(matches!(error, HeldActionStoreError::Corrupt { .. }));
}

/// A hold that could not be written to disk is NOT in the store, so nothing
/// can list it, claim it or dispatch it. The durable write comes first.
#[test]
fn a_hold_that_cannot_be_persisted_is_not_actionable() {
    let dir = temp_dir("persist-fail");
    let store = FileHeldActionStore::open(&dir).unwrap();
    let hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".into(),
        },
        T0,
    );
    let id = hold.hold_id.clone();
    // Block the temp path with a directory: the write fails with EISDIR for
    // any uid, so the injection does not depend on running unprivileged.
    std::fs::create_dir(dir.join(format!("{id}.json.tmp"))).unwrap();

    let error = store.create(hold).unwrap_err();
    assert!(
        matches!(error, HeldActionStoreError::Io { .. }),
        "{error:?}"
    );
    assert!(
        store.get(&id).unwrap().is_none(),
        "an unpersisted hold is listed"
    );
    assert!(store.list(true, 10).unwrap().is_empty());
    assert!(
        store.begin_decision(&id, INTENT_A, T0 + 1).is_err(),
        "an unpersisted hold was claimable"
    );
    assert!(!dir.join(format!("{id}.json")).exists());
}

/// A leftover temp document from an interrupted write is not a hold. It is
/// ignored on reopen rather than parsed, so a half-written file cannot come
/// back as a decidable record.
#[test]
fn a_leftover_temp_document_is_ignored_on_reopen() {
    let dir = temp_dir("leftover-temp");
    let id = {
        let store = FileHeldActionStore::open(&dir).unwrap();
        let hold = fixture_hold(
            ResponseAction::BlockEgress {
                target: "203.0.113.10".into(),
            },
            T0,
        );
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        id
    };
    std::fs::write(
        dir.join("hold_interrupted.json.tmp"),
        b"{\"hold_id\": \"hold_i",
    )
    .unwrap();
    let reopened = FileHeldActionStore::open(&dir).unwrap();
    let ids: Vec<String> = reopened
        .list(true, 10)
        .unwrap()
        .into_iter()
        .map(|hold| hold.hold_id)
        .collect();
    assert_eq!(ids, vec![id]);
}

/// The file backend's compare-and-set is under the same one-winner rule as the
/// memory backend's, and the winner is the one on disk.
#[test]
fn concurrent_claims_on_a_file_backed_hold_produce_exactly_one_winner() {
    let dir = temp_dir("file-race");
    let store = std::sync::Arc::new(FileHeldActionStore::open(&dir).unwrap());
    let mut hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".into(),
        },
        T0,
    );
    hold.state = HoldState::Notified;
    let id = hold.hold_id.clone();
    store.create(hold).unwrap();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::new();
    for slot in 0..8u8 {
        let store = std::sync::Arc::clone(&store);
        let barrier = std::sync::Arc::clone(&barrier);
        let winners = std::sync::Arc::clone(&winners);
        let id = id.clone();
        handles.push(std::thread::spawn(move || {
            let intent = format!("{slot:02x}").repeat(32);
            barrier.wait();
            if store.begin_decision(&id, &intent, T0 + 100).is_ok() {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);

    let in_memory = store.get(&id).unwrap().unwrap();
    let on_disk = FileHeldActionStore::open(&dir)
        .unwrap()
        .get(&id)
        .unwrap()
        .unwrap();
    assert_eq!(on_disk.state, HoldState::Deciding);
    assert_eq!(
        on_disk.deciding_intent_event_id, in_memory.deciding_intent_event_id,
        "the winner on disk is not the winner in memory"
    );
}

#[test]
fn configured_store_is_memory_when_no_path_is_set() {
    let settings = ResponseHoldSettings::default();
    let store =
        ConfiguredHeldActionStore::from_settings(&settings, std::path::Path::new(".")).unwrap();
    assert!(!store.health(T0, 60_000).unwrap().durable);
}

/// A relative `hold_store_path` resolves against the config file's directory,
/// the way the containment lease store resolves its own path, so a daemon
/// started from another working directory writes to the same place.
#[test]
fn configured_store_resolves_a_relative_path_against_the_config_directory() {
    let dir = temp_dir("configured");
    let settings = ResponseHoldSettings {
        hold_store_path: Some("data/perch-dev/holds".to_string()),
        ..ResponseHoldSettings::default()
    };
    let store = ConfiguredHeldActionStore::from_settings(&settings, &dir).unwrap();
    let health = store.health(T0, 60_000).unwrap();
    assert!(health.durable);
    assert_eq!(health.backend, "local_files");

    let hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".into(),
        },
        T0,
    );
    let id = hold.hold_id.clone();
    store.create(hold).unwrap();
    assert!(
        dir.join("data/perch-dev/holds")
            .join(format!("{id}.json"))
            .exists()
    );
}
