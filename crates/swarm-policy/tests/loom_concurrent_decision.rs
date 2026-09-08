//! LOOM-02 — concurrent decision evaluation vs. ruleset reload, as a
//! `bounded_abstract_model` (labelled exactly that in `docs/assurance/MAPPING.md`).
//!
//! The policy crate itself has no reload operation: `ConfigurableApprovalGate`
//! rebuilds an immutable rule vector inside a fresh gate
//! (`configurable_gate.rs:13,26`). The real reload lives in
//! `swarm-ingest-runtime` (`ingest/mod.rs`), where `reload` publishes NEW
//! generations into SEPARATE `ArcSwap`s NON-atomically, and the request path
//! (`route_request`, `mod.rs:146`) reads ONE held generation via a single
//! `self.runtime.load_full()` and uses it for the whole request.
//!
//! Loom instruments only `loom::sync` types, so this models the two seams with
//! reviewed Loom state rather than the real `arc_swap::ArcSwap` / `std::sync`
//! primitives. Two models:
//!
//! * MODEL 1 asserts one held runtime generation per decision/lease. It does NOT
//!   claim all composition fields swap atomically — only that a decision and the
//!   lease it issues agree because both read one held runtime snapshot.
//! * MODEL 2 is the supplemental last-slot atomic prune/check/increment under one
//!   mutex (`configurable_gate.rs:85`, `agent_limit_exceeded`).
//!
//! Compiled only under `RUSTFLAGS="--cfg loom"`. The falsification of each oracle
//! is demonstrated (without editing the model) by setting `LOOM_FALSIFY`.

#![cfg(loom)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use loom::sync::{Arc, Mutex};
use loom::thread;

fn model_broken_variant() -> bool {
    std::env::var_os("LOOM_FALSIFY").is_some()
}

fn bounded_builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    // Documented preemption bound of 2 (287 design of record / codex prep).
    builder.preemption_bound = Some(2);
    // Leave the permutation/duration caps UNSET (see loom_concurrent_write.rs):
    // either can end exploration with a false pass.
    builder.max_permutations = None;
    builder.max_duration = None;
    builder
}

/// The composed request runtime for one generation. In production this is the
/// single `Arc<IngestRequestRuntime>` a request holds via `load_full()`.
#[derive(Clone)]
struct Runtime {
    generation: usize,
}

/// MODEL 1 — one held runtime generation per decision/lease.
///
/// An `ArcSwap` is modelled as `Mutex<Arc<Runtime>>`: `store` replaces the Arc,
/// `load_full` clones it. A reloader publishes generation 1 concurrently with a
/// request that derives BOTH a decision and a capability lease.
///
/// CORRECT: the request calls `load_full` ONCE and reads the decision and the
/// lease from that single held runtime — they always share one generation.
///
/// BROKEN (`LOOM_FALSIFY`): the request re-loads the slot for the lease instead
/// of holding the runtime the decision used; Loom finds the schedule where the
/// reload lands between the two loads and the lease reads a different generation
/// than the decision authorised.
#[test]
fn a_decision_and_its_lease_read_one_held_runtime_generation() {
    bounded_builder().check(|| {
        let slot = Arc::new(Mutex::new(Arc::new(Runtime { generation: 0 })));

        let reloader = {
            let slot = slot.clone();
            thread::spawn(move || {
                let next = Arc::new(Runtime { generation: 1 });
                *slot.lock().unwrap() = next;
            })
        };

        let request = {
            let slot = slot.clone();
            thread::spawn(move || {
                let (decision_generation, lease_generation) = if model_broken_variant() {
                    let decision_generation = slot.lock().unwrap().generation;
                    let lease_generation = slot.lock().unwrap().generation;
                    (decision_generation, lease_generation)
                } else {
                    let held = slot.lock().unwrap().clone();
                    let decision_generation = held.generation;
                    let lease_generation = held.generation;
                    (decision_generation, lease_generation)
                };
                assert_eq!(
                    decision_generation, lease_generation,
                    "decision and lease read different runtime generations \
                     (a reload was observed mid-request)"
                );
            })
        };

        reloader.join().unwrap();
        request.join().unwrap();
    });
}

/// MODEL 2 — the last-slot atomic prune/check/increment.
///
/// Mirrors `ConfigurableApprovalGate::agent_limit_exceeded`: under ONE mutex
/// guard it prunes the trailing-60s window, checks `len >= limit`, and only then
/// pushes. With one slot remaining (`LIMIT == 1`), two concurrent leases must not
/// both consume it.
///
/// CORRECT: check and increment share one guard, so at most one lease is granted.
///
/// BROKEN (`LOOM_FALSIFY`): the check and the increment are two separate critical
/// sections; Loom finds the schedule where both observe room and both increment,
/// over-consuming the last slot.
const LIMIT: usize = 1;

#[test]
fn the_last_capability_slot_is_never_over_consumed() {
    bounded_builder().check(|| {
        let occupancy = Arc::new(Mutex::new(0usize));

        let spawn_lease = |occupancy: Arc<Mutex<usize>>| {
            thread::spawn(move || -> bool {
                if model_broken_variant() {
                    let has_room = { *occupancy.lock().unwrap() < LIMIT };
                    if has_room {
                        let mut count = occupancy.lock().unwrap();
                        *count += 1;
                        true
                    } else {
                        false
                    }
                } else {
                    let mut count = occupancy.lock().unwrap();
                    if *count < LIMIT {
                        *count += 1;
                        true
                    } else {
                        false
                    }
                }
            })
        };

        let first = spawn_lease(occupancy.clone());
        let second = spawn_lease(occupancy.clone());
        let granted_first = first.join().unwrap();
        let granted_second = second.join().unwrap();

        let granted = usize::from(granted_first) + usize::from(granted_second);
        let final_occupancy = *occupancy.lock().unwrap();
        assert_eq!(
            granted, final_occupancy,
            "granted-lease count disagrees with window occupancy"
        );
        assert!(
            final_occupancy <= LIMIT,
            "the last capability slot was over-consumed: {final_occupancy} > {LIMIT}"
        );
    });
}
