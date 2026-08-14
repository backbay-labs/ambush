//! Negative falsifiability tests for the `swarm-response` rows of
//! `docs/assurance/MAPPING.md` (FALSIFY-02).
//!
//! See the header of `crates/swarm-policy/tests/negative_policy_gates.rs` for
//! the three-step shape every test in this family follows (real function
//! refuses; unmutated mirror reproduces it; mutated mirror permits).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use swarm_core::types::{
    ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
    ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
    ResponseRollbackStep, ResponseRollbackStepKind,
};
use swarm_response::containment::{ContainmentLease, ContainmentLeaseError, ContainmentTtl};
use swarm_response::rollback::{
    RollbackExecutor, RollbackReceipt, RollbackStepOutcome, RollbackStepStatus, RollbackTrigger,
    SandboxRollbackExecutor, resolve_inverse,
};
use swarm_response::{ExecutionMode, ResponseStatus};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

fn quarantine_action() -> ResponseAction {
    ResponseAction::QuarantineFile {
        host_id: "host-1".to_string(),
        file_path: "/tmp/evil".to_string(),
    }
}

fn preview(steps: &[ResponseRollbackStepKind]) -> ResponseRehearsalPreview {
    ResponseRehearsalPreview {
        rehearsal_id: "rehearsal:negative".to_string(),
        source_bundle_id: "bundle:negative".to_string(),
        prepared_at_ms: 1_000,
        simulated_only: true,
        blast_radius: ResponseBlastRadiusPreview {
            scope_kind: ResponseRehearsalScopeKind::File,
            scope_value: "host-1:/tmp/evil".to_string(),
            impact: ResponseBlastRadiusImpact::FileQuarantined,
            max_affected_scopes: 1,
            affected_capabilities: vec!["file_access".to_string()],
            summary: "one quarantined file".to_string(),
        },
        rollback: ResponseRollbackPreview {
            required: true,
            summary: "release the quarantined file".to_string(),
            steps: steps
                .iter()
                .map(|kind| ResponseRollbackStep {
                    kind: *kind,
                    summary: format!("{kind:?}"),
                })
                .collect(),
        },
    }
}

fn lease(issued_at_ms: i64, ttl_ms: i64) -> ContainmentLease {
    ContainmentLease::open(
        "containment:negative",
        quarantine_action(),
        "resp:negative",
        Some("gov:negative".to_string()),
        &preview(&[ResponseRollbackStepKind::ReleaseQuarantinedFile]),
        issued_at_ms,
        ContainmentTtl::from_config_ms(ttl_ms).unwrap(),
    )
    .expect("the fixture lease is bounded")
}

// ---------------------------------------------------------------------------
// RESPONSE-LEASE-BOUNDED
// ---------------------------------------------------------------------------

/// Mirror of `ContainmentLease::open`'s expiry derivation, copied from
/// `crates/swarm-response/src/containment.rs`, with the post-add re-check
/// removed.
///
/// Only the derivation is mirrored, because that is the whole invariant: the
/// saturating add plus the `expires_at_ms <= issued_at_ms` re-check. The mirror
/// returns the expiry it would have written rather than a `ContainmentLease`,
/// since the real type has no other constructor -- which is itself the point.
fn broken_open_expiry(
    issued_at_ms: i64,
    ttl: ContainmentTtl,
) -> Result<i64, ContainmentLeaseError> {
    let expires_at_ms = issued_at_ms.saturating_add(ttl.get());
    Ok(expires_at_ms)
}

#[test]
fn broken_open_permits_the_unbounded_lease_the_real_constructor_refuses() {
    // The saturating add is a NO-OP here: `i64::MAX + 900_000` saturates back to
    // `i64::MAX`, so the derived expiry equals the issue instant and the lease
    // covers zero milliseconds -- an "expiry" that has already passed, on a
    // containment that has just taken effect. A clock this far forward is a
    // misconfiguration or a hostile `now_ms`, not an everyday value, and it is
    // exactly the case a derivation with no re-check gets wrong.
    let issued_at_ms = i64::MAX;
    let ttl = ContainmentTtl::from_config_ms(900_000).unwrap();

    let real = ContainmentLease::open(
        "containment:saturating",
        quarantine_action(),
        "resp:saturating",
        None,
        &preview(&[ResponseRollbackStepKind::ReleaseQuarantinedFile]),
        issued_at_ms,
        ttl,
    );
    let error = real.expect_err("the shipped constructor must refuse an unbounded lease");
    assert!(
        matches!(error, ContainmentLeaseError::UnboundedLease { .. }),
        "unexpected error: {error}"
    );

    let broken = broken_open_expiry(issued_at_ms, ttl).expect("the broken derivation returns one");
    assert_eq!(
        broken, issued_at_ms,
        "without the re-check the lease is written with an expiry that is not \
         after its issue instant, which is the unbounded containment the type \
         exists to make unrepresentable"
    );

    // Control: an ordinary clock produces a lease from both, so neither is
    // refusing everything.
    let ordinary = lease(1_000, 900_000);
    assert_eq!(ordinary.expires_at_ms(), 901_000);
    assert_eq!(broken_open_expiry(1_000, ttl).unwrap(), 901_000);
}

// ---------------------------------------------------------------------------
// RESPONSE-STORED-LEASE-BOUNDED
// ---------------------------------------------------------------------------

/// Mirror of `impl TryFrom<ContainmentLeaseRecord> for ContainmentLease`,
/// reduced to the two guards it applies, with the expiry bound removed.
///
/// `ContainmentLeaseRecord` is private -- deliberately, it is the only shape
/// that deserializes -- so the mirror reads the same fields off the wire JSON.
fn broken_stored_lease_accepts(record: &serde_json::Value) -> Result<i64, String> {
    let schema_version = record
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing schema_version")?;
    if schema_version != 1 {
        return Err(format!("unknown schema version {schema_version}"));
    }
    let issued_at_ms = record
        .get("issued_at_ms")
        .and_then(serde_json::Value::as_i64)
        .ok_or("missing issued_at_ms")?;
    let expires_at_ms = record
        .get("expires_at_ms")
        .and_then(serde_json::Value::as_i64)
        .ok_or("missing expires_at_ms")?;
    // The `expires_at_ms <= issued_at_ms` guard is what has been removed.
    let _ = issued_at_ms;
    Ok(expires_at_ms)
}

#[test]
fn broken_stored_lease_bound_accepts_the_already_expired_record_the_real_one_rejects() {
    // A lease record whose stored expiry is BEFORE its issue instant. Nothing
    // stops such a file appearing: `FileContainmentLeaseStore` reads a plain
    // JSON document off disk, so this is the at-rest tampering case.
    let mut wire = serde_json::to_value(lease(1_000, 900_000)).unwrap();
    wire["expires_at_ms"] = json!(900);
    assert_eq!(wire["issued_at_ms"], json!(1_000));

    let real = serde_json::from_value::<ContainmentLease>(wire.clone());
    let error = real.expect_err("the shipped deserializer must refuse an unbounded stored lease");
    assert!(
        error.to_string().contains("must be bounded"),
        "the refusal must name the bound: {error}"
    );

    let broken = broken_stored_lease_accepts(&wire)
        .expect("the broken variant admits the record the real one rejects");
    assert_eq!(
        broken, 900,
        "without the bound a stored lease can name an expiry already in the past \
         relative to its own issue, and the sweep would close it on first sight"
    );

    // Control: the untampered record round-trips through the real deserializer.
    let clean = serde_json::to_value(lease(1_000, 900_000)).unwrap();
    let restored: ContainmentLease = serde_json::from_value(clean).unwrap();
    assert_eq!(restored.expires_at_ms(), 901_000);
}

// ---------------------------------------------------------------------------
// RESPONSE-ENFORCED-SIMULATION-NOT-SUCCESS
// ---------------------------------------------------------------------------

/// Mirror of `RollbackReceipt::derive_status`, copied from
/// `crates/swarm-response/src/rollback.rs`, with the `mode == DryRun` condition
/// dropped from the all-`Simulated` arm.
///
/// That condition is the entire fix from cc5b169: `ResponseStatus::Simulated`
/// answers `indicates_success()` with `true`, which is only honest when nothing
/// was supposed to happen.
fn broken_derive_status(steps: &[RollbackStepOutcome], _mode: ExecutionMode) -> ResponseStatus {
    if steps.is_empty() {
        return ResponseStatus::Failed;
    }
    if steps.iter().all(|step| step.status.restored()) {
        ResponseStatus::Executed
    } else if steps
        .iter()
        .all(|step| step.status == RollbackStepStatus::Simulated)
    {
        ResponseStatus::Simulated
    } else {
        ResponseStatus::Failed
    }
}

#[test]
fn broken_mode_gate_reports_an_enforced_simulation_as_the_success_the_real_one_refuses() {
    let lease = lease(1_000, 900_000);
    let steps = vec![RollbackStepOutcome {
        kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
        status: RollbackStepStatus::Simulated,
        detail: "would issue `release_quarantined_file` (no side effect)".to_string(),
    }];

    // ENFORCED: this is every TTL expiry on a crowdstrike_rtr, webhook or
    // sandbox deployment, because all three resolve to
    // `SandboxRollbackExecutor`. The host is still quarantined.
    let real = RollbackReceipt::from_steps(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::Enforced,
        2_000,
        steps.clone(),
    );
    assert_eq!(real.status, ResponseStatus::Failed);
    assert!(
        !real.status.indicates_success(),
        "an enforced rollback that touched nothing must not read as a success"
    );
    assert!(!real.fully_reversed());

    let control = broken_derive_status(&steps, ExecutionMode::DryRun);
    assert_eq!(
        control,
        RollbackReceipt::from_steps(
            &lease,
            RollbackTrigger::Expiry,
            ExecutionMode::DryRun,
            2_000,
            steps.clone(),
        )
        .status,
        "the mirror must reproduce the real derivation in DryRun, where the two \
         agree; without this the mutation below could be any rewrite at all"
    );

    let broken = broken_derive_status(&steps, ExecutionMode::Enforced);
    assert_eq!(broken, ResponseStatus::Simulated);
    assert!(
        broken.indicates_success(),
        "without the mode gate the durable record marks a still-contained host a \
         success, and every caller that checks `indicates_success()` believes it"
    );
}

// ---------------------------------------------------------------------------
// RESPONSE-SANDBOX-NEVER-REVERSES
// ---------------------------------------------------------------------------

/// Mirror of `SandboxRollbackExecutor::rollback`, copied from
/// `crates/swarm-response/src/rollback.rs`, reinstating the pre-cc5b169 shape:
/// a resolved inverse is recorded as `Reversed` when the mode is `Enforced`.
///
/// This executor cannot reach a host -- it holds no transport at all -- so
/// every `Reversed` it writes is a claim about a world it never touched.
fn broken_sandbox_rollback(
    lease: &ContainmentLease,
    trigger: RollbackTrigger,
    mode: ExecutionMode,
    completed_at_ms: i64,
) -> RollbackReceipt {
    let steps = lease
        .rollback()
        .steps
        .iter()
        .map(|step| match resolve_inverse(lease.action(), step.kind) {
            Ok(inverse) => RollbackStepOutcome {
                kind: step.kind,
                status: if mode == ExecutionMode::Enforced {
                    RollbackStepStatus::Reversed
                } else {
                    RollbackStepStatus::Simulated
                },
                detail: format!("`{}` against `{}`", inverse.kind(), inverse.target()),
            },
            Err(_) => RollbackStepOutcome {
                kind: step.kind,
                status: RollbackStepStatus::Unsupported,
                detail: "no inverse".to_string(),
            },
        })
        .collect();
    RollbackReceipt::from_steps(lease, trigger, mode, completed_at_ms, steps)
}

#[tokio::test]
async fn broken_sandbox_executor_claims_the_reversal_the_real_one_refuses_to_claim() {
    let lease = lease(1_000, 900_000);

    let real = SandboxRollbackExecutor
        .rollback(
            &lease,
            RollbackTrigger::Expiry,
            ExecutionMode::Enforced,
            2_000,
        )
        .await
        .expect("the sandbox executor produces a receipt");
    assert_eq!(real.steps.len(), 1);
    assert_eq!(real.steps[0].status, RollbackStepStatus::Simulated);
    assert!(
        !real.fully_reversed(),
        "the shipped sandbox executor must never claim a real reversal"
    );
    assert_eq!(real.status, ResponseStatus::Failed);

    let control = broken_sandbox_rollback(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::DryRun,
        2_000,
    );
    let real_dry_run = SandboxRollbackExecutor
        .rollback(
            &lease,
            RollbackTrigger::Expiry,
            ExecutionMode::DryRun,
            2_000,
        )
        .await
        .expect("a receipt");
    assert_eq!(
        control.status, real_dry_run.status,
        "the mirror must reproduce the real executor in DryRun, where the two agree"
    );
    assert_eq!(
        control.steps[0].status, real_dry_run.steps[0].status,
        "and step for step, not only in the summary status"
    );

    let broken = broken_sandbox_rollback(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::Enforced,
        2_000,
    );
    assert!(
        broken.fully_reversed(),
        "the pre-cc5b169 shape reports a full reversal from code that holds no \
         transport and touched no host: {:?}",
        broken.steps
    );
    assert_eq!(broken.status, ResponseStatus::Executed);
    assert!(broken.status.indicates_success());
}
