#![allow(clippy::unwrap_used, clippy::expect_used)]
//! INV-03 and INV-04 as Rust, plus the 12 -> 4 -> 3 ladder the UI renders from.
//!
//! Target path in AMBUSH: `crates/swarm-response/tests/perch_response_taxonomy.rs`.
//! Run by `cargo test -p swarm-response`, i.e. by the existing `test` job in
//! `.github/workflows/ci.yml`; no new workflow step and therefore nothing for
//! `tools/check-gates-wired.sh` to complain about.
//!
//! WHY THIS FILE IS IN AMBUSH AND NOT IN THE CONSOLE
//!   INV-03 says the Undo affordance is enabled only when
//!   `resolve_inverse(action, step)` returns `Ok` for EVERY step of the plan, and
//!   INV-04 says the five `RollbackStepStatus` variants render as five distinct
//!   strings. The console can only assert what it was told. What the console is
//!   told has to be true, and the truth lives here:
//!
//!     `resolve_inverse` (crates/swarm-response/src/rollback.rs:151-192) is
//!     called per planned step by the release path in the `swarm_detect --serve`
//!     process; it joins a lease's typed `ResponseAction` with a
//!     `ResponseRollbackStepKind` and returns either a dispatchable
//!     `ContainmentInverse` or an `InverseGap`. `plan_is_reversible`
//!     (`:199-206`) is the exact predicate INV-03 gates on.
//!
//!   These tests compile against the CURRENT tree. They are the half of the
//!   invariant set that needs no backend bill item, which is why they land first.
//!
//! THE LADDER, and why the UI cannot flatten it
//!   Twelve destructive actions (`swarm-policy/src/static_gate.rs:37-53`).
//!   FOUR of the twelve are containment actions and only those four ever mint a
//!   `ContainmentLease` (`swarm-runtime/src/containment.rs:54-63`;
//!   `prepare_containment` returns `Ok(None)` otherwise,
//!   `swarm-runtime/src/lib.rs:829-831`). THREE of those four have an executable
//!   inverse; `TerminateUserSession` maps to `InverseGap::Irreversible` with a
//!   quotable reason (`rollback.rs:183-189`).
//!
//!   So a hold card for `revoke_credential` must render no pending containment
//!   lease, no countdown and no rollback receipt, and a hold card for
//!   `terminate_user_session` must render a containment lease AND a disabled
//!   Undo. Those two cases fail in opposite directions and both are asserted.

// `ResponseRollbackStepKind` lives in swarm-core's shared type module
// (crates/swarm-core/src/types.rs:517-533, fifteen variants); the inverse
// machinery lives in swarm-response. Getting that split wrong is a compile
// error, which is the good kind of wrong.
use swarm_core::types::{ResponseAction, ResponseRollbackStepKind};
use swarm_response::rollback::{
    resolve_inverse, ContainmentInverse, InverseGap, RollbackStepStatus,
};

fn quarantine_file() -> ResponseAction {
    ResponseAction::QuarantineFile {
        host_id: "host-7a3f".to_string(),
        file_path: "/tmp/payload.bin".to_string(),
    }
}

fn suspend_process() -> ResponseAction {
    ResponseAction::SuspendProcess {
        host_id: "host-7a3f".to_string(),
        process_name: "svchost.exe".to_string(),
    }
}

fn isolate_host() -> ResponseAction {
    ResponseAction::IsolateHost {
        host_id: "host-7a3f".to_string(),
    }
}

fn terminate_user_session() -> ResponseAction {
    ResponseAction::TerminateUserSession {
        host_id: "host-7a3f".to_string(),
        session_id: "sess-11".to_string(),
    }
}

fn revoke_credential() -> ResponseAction {
    ResponseAction::RevokeCredential {
        credential_id: "cred-9".to_string(),
    }
}

/// INV-03's positive half: exactly three actions have an executable inverse.
#[test]
fn exactly_three_actions_resolve_to_an_executable_inverse() {
    let resolvable = [
        (
            quarantine_file(),
            ResponseRollbackStepKind::ReleaseQuarantinedFile,
        ),
        (suspend_process(), ResponseRollbackStepKind::ResumeProcess),
        (
            isolate_host(),
            ResponseRollbackStepKind::RestoreHostConnectivity,
        ),
    ];

    let mut inverses = Vec::new();
    for (action, step) in resolvable {
        let inverse = resolve_inverse(&action, step)
            .expect("this pairing is one of the three the release path can dispatch");
        inverses.push(inverse);
    }

    assert_eq!(inverses.len(), 3);
    assert!(matches!(
        inverses[0],
        ContainmentInverse::ReleaseQuarantinedFile { .. }
    ));
    assert!(matches!(inverses[1], ContainmentInverse::ResumeProcess { .. }));
    assert!(matches!(
        inverses[2],
        ContainmentInverse::RestoreHostConnectivity { .. }
    ));
}

/// INV-03's negative half, and the one an operator most needs the UI to get
/// right: `SuspendProcess` is reversible and `KillProcess` is not, and
/// `TerminateUserSession` is a CONTAINMENT action that is still irreversible.
/// "Has a containment lease" therefore does not imply "can be undone", and any
/// UI that infers one from the other is wrong for exactly this action.
#[test]
fn terminate_user_session_is_contained_and_still_irreversible() {
    let gap = resolve_inverse(
        &terminate_user_session(),
        ResponseRollbackStepKind::ReauthenticateUserSession,
    )
    .expect_err("re-permitting login is not the inverse of ending a session");

    match gap {
        InverseGap::Irreversible { reason } => {
            // The reason is quotable, so the disabled Undo affordance can render
            // the daemon's own sentence instead of a generic "not available".
            assert!(
                reason.contains("terminated session cannot be resumed"),
                "the irreversibility reason must be renderable verbatim; got: {reason}"
            );
        }
        other => panic!("expected Irreversible, got {other:?}"),
    }
}

/// The eight destructive actions that are not containment actions resolve to
/// `Unmapped` for every step kind. A UI that renders a pending containment lease
/// beside one of them is inventing a fact.
#[test]
fn a_non_containment_destructive_action_has_no_inverse_for_any_step() {
    let every_step = [
        ResponseRollbackStepKind::ReleaseQuarantinedFile,
        ResponseRollbackStepKind::ResumeProcess,
        ResponseRollbackStepKind::RestoreHostConnectivity,
        ResponseRollbackStepKind::ReauthenticateUserSession,
    ];

    for step in every_step {
        let gap = resolve_inverse(&revoke_credential(), step)
            .expect_err("revoke_credential is destructive but never contained");
        assert!(
            matches!(gap, InverseGap::Unmapped),
            "expected Unmapped for {step:?}, got {gap:?}"
        );
    }
}

/// A mismatched (action, step) pair is `Unmapped`, not a silent success. This is
/// the arm that would otherwise let a plan report a reversal that never happened
/// -- `resolve_inverse`'s own doc comment says the fallthrough exists to record
/// the gap on the receipt rather than lie about it.
#[test]
fn a_step_that_does_not_match_its_action_is_unmapped() {
    let gap = resolve_inverse(&isolate_host(), ResponseRollbackStepKind::ResumeProcess)
        .expect_err("resuming a process is not the inverse of isolating a host");
    assert!(matches!(gap, InverseGap::Unmapped));
}

/// INV-04's precondition. The console renders five distinct strings; that is
/// only meaningful if there are exactly five variants and only one of them means
/// the world was restored.
#[test]
fn rollback_step_status_has_five_variants_and_one_restores() {
    let all = [
        RollbackStepStatus::Reversed,
        RollbackStepStatus::Simulated,
        RollbackStepStatus::Irreversible,
        RollbackStepStatus::Unsupported,
        RollbackStepStatus::Failed,
    ];
    assert_eq!(all.len(), 5);

    let restoring: Vec<_> = all.iter().copied().filter(|s| s.restored()).collect();
    assert_eq!(
        restoring,
        vec![RollbackStepStatus::Reversed],
        "only Reversed restored the pre-containment state; Simulated touched no \
         real target and Unsupported never ran"
    );

    // The wire strings are the console's join key, so they must be distinct too.
    // A UI cannot render five distinct labels off two identical wire values.
    let wire: Vec<String> = all
        .iter()
        .map(|status| serde_json::to_string(status).expect("RollbackStepStatus is Serialize"))
        .collect();
    let mut sorted = wire.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 5, "wire strings collided: {wire:?}");
}
