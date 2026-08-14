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
// RESPONSE-TTL-STRICTLY-POSITIVE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TtlMutation {
    None,
    SkipPositiveCheck,
}

fn mirrored_ttl(ttl_ms: i64, mutation: TtlMutation) -> Result<i64, ContainmentLeaseError> {
    if mutation != TtlMutation::SkipPositiveCheck && ttl_ms <= 0 {
        return Err(ContainmentLeaseError::NonPositiveTtl { ttl_ms });
    }
    Ok(ttl_ms)
}

#[test]
fn broken_ttl_check_permits_a_zero_lifetime() {
    let real = ContainmentTtl::from_config_ms(0);
    assert_eq!(
        real,
        Err(ContainmentLeaseError::NonPositiveTtl { ttl_ms: 0 })
    );
    let control = mirrored_ttl(0, TtlMutation::None);
    assert_eq!(
        control,
        Err(ContainmentLeaseError::NonPositiveTtl { ttl_ms: 0 })
    );
    assert_eq!(mirrored_ttl(0, TtlMutation::SkipPositiveCheck), Ok(0));
}

// ---------------------------------------------------------------------------
// RESPONSE-LEASE-BOUNDED
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenMutation {
    None,
    SkipExpiryBound,
}

/// Mirror of `ContainmentLease::open`'s expiry derivation, copied from
/// `crates/swarm-response/src/containment.rs`, with the post-add re-check
/// selectively removable.
///
/// Only the derivation is mirrored, because that is the whole invariant: the
/// saturating add plus the `expires_at_ms <= issued_at_ms` re-check. The mirror
/// returns the expiry it would have written rather than a `ContainmentLease`,
/// since the real type has no other constructor -- which is itself the point.
fn mirrored_open_expiry(
    lease_id: &str,
    issued_at_ms: i64,
    ttl: ContainmentTtl,
    mutation: OpenMutation,
) -> Result<i64, ContainmentLeaseError> {
    let expires_at_ms = issued_at_ms.saturating_add(ttl.get());
    if mutation != OpenMutation::SkipExpiryBound && expires_at_ms <= issued_at_ms {
        return Err(ContainmentLeaseError::UnboundedLease {
            lease_id: lease_id.to_string(),
            issued_at_ms,
            expires_at_ms,
        });
    }
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

    let control = mirrored_open_expiry(
        "containment:saturating",
        issued_at_ms,
        ttl,
        OpenMutation::None,
    );
    assert_eq!(
        control,
        Err(error.clone()),
        "the unmutated mirror must reproduce the real refusal on the same \
         saturating-add probe"
    );

    let broken = mirrored_open_expiry(
        "containment:saturating",
        issued_at_ms,
        ttl,
        OpenMutation::SkipExpiryBound,
    )
    .expect("the broken derivation returns an expiry");
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
    assert_eq!(
        mirrored_open_expiry("containment:ordinary", 1_000, ttl, OpenMutation::None).unwrap(),
        901_000
    );
}

// ---------------------------------------------------------------------------
// RESPONSE-STORED-LEASE-BOUNDED
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredLeaseMutation {
    None,
    SkipExpiryBound,
    SkipSchemaVersion,
}

/// Mirror of `impl TryFrom<ContainmentLeaseRecord> for ContainmentLease`,
/// reduced to the two guards it applies, with the expiry bound selectively
/// removable.
///
/// `ContainmentLeaseRecord` is private -- deliberately, it is the only shape
/// that deserializes -- so the mirror reads the same fields off the wire JSON.
fn mirrored_stored_lease_accepts(
    record: &serde_json::Value,
    mutation: StoredLeaseMutation,
) -> Result<i64, String> {
    let schema_version = record
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing schema_version")?;
    if mutation != StoredLeaseMutation::SkipSchemaVersion && schema_version != 1 {
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
    if mutation != StoredLeaseMutation::SkipExpiryBound && expires_at_ms <= issued_at_ms {
        return Err("containment lease must be bounded".to_string());
    }
    Ok(expires_at_ms)
}

#[test]
fn broken_schema_check_loads_a_lease_from_an_unknown_wire_version() {
    let mut wire = serde_json::to_value(lease(1_000, 900_000)).unwrap();
    wire["schema_version"] = json!(99);
    let real = serde_json::from_value::<ContainmentLease>(wire.clone());
    assert!(real.is_err());
    let control = mirrored_stored_lease_accepts(&wire, StoredLeaseMutation::None);
    assert!(control.is_err());
    assert_eq!(
        mirrored_stored_lease_accepts(&wire, StoredLeaseMutation::SkipSchemaVersion),
        Ok(901_000)
    );
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

    let control = mirrored_stored_lease_accepts(&wire, StoredLeaseMutation::None);
    assert!(
        control
            .as_ref()
            .is_err_and(|reason| reason.contains("must be bounded")),
        "the unmutated mirror must refuse the same edited record: {control:?}"
    );

    let broken = mirrored_stored_lease_accepts(&wire, StoredLeaseMutation::SkipExpiryBound)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeriveStatusMutation {
    None,
    SkipDryRunMode,
    SkipEmptySteps,
    ReportPartialSuccess,
}

/// Mirror of `RollbackReceipt::derive_status`, copied from
/// `crates/swarm-response/src/rollback.rs`, with the `mode == DryRun` condition
/// dropped from the all-`Simulated` arm.
///
/// That condition is the entire fix from cc5b169: `ResponseStatus::Simulated`
/// answers `indicates_success()` with `true`, which is only honest when nothing
/// was supposed to happen.
fn mirrored_derive_status(
    steps: &[RollbackStepOutcome],
    mode: ExecutionMode,
    mutation: DeriveStatusMutation,
) -> ResponseStatus {
    if mutation != DeriveStatusMutation::SkipEmptySteps && steps.is_empty() {
        return ResponseStatus::Failed;
    }
    if steps.iter().all(|step| step.status.restored()) {
        ResponseStatus::Executed
    } else if steps
        .iter()
        .all(|step| step.status == RollbackStepStatus::Simulated)
        && (mutation == DeriveStatusMutation::SkipDryRunMode || mode == ExecutionMode::DryRun)
    {
        ResponseStatus::Simulated
    } else if mutation == DeriveStatusMutation::ReportPartialSuccess {
        ResponseStatus::Executed
    } else {
        ResponseStatus::Failed
    }
}

#[test]
fn broken_empty_step_status_reports_success_without_any_inverse() {
    let lease = lease(1_000, 900_000);
    let steps = Vec::new();
    let real = RollbackReceipt::from_steps(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::Enforced,
        2_000,
        steps.clone(),
    );
    assert_eq!(real.status, ResponseStatus::Failed);
    assert_eq!(
        mirrored_derive_status(&steps, ExecutionMode::Enforced, DeriveStatusMutation::None),
        real.status
    );
    assert_eq!(
        mirrored_derive_status(
            &steps,
            ExecutionMode::Enforced,
            DeriveStatusMutation::SkipEmptySteps,
        ),
        ResponseStatus::Executed,
        "without the empty-step guard the vacuous all-restored predicate reports success"
    );
}

#[test]
fn broken_partial_status_reports_success_with_an_unsupported_inverse() {
    let lease = lease(1_000, 900_000);
    let steps = vec![RollbackStepOutcome {
        kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
        status: RollbackStepStatus::Unsupported,
        detail: "no adapter inverse".to_string(),
    }];
    let real = RollbackReceipt::from_steps(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::Enforced,
        2_000,
        steps.clone(),
    );
    assert_eq!(real.status, ResponseStatus::Failed);
    assert_eq!(
        mirrored_derive_status(&steps, ExecutionMode::Enforced, DeriveStatusMutation::None),
        real.status
    );
    assert_eq!(
        mirrored_derive_status(
            &steps,
            ExecutionMode::Enforced,
            DeriveStatusMutation::ReportPartialSuccess,
        ),
        ResponseStatus::Executed
    );
}

// ---------------------------------------------------------------------------
// RESPONSE-UNMAPPED-INVERSE-REFUSED
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InverseMutation {
    None,
    InventUnmappedInverse,
}

fn mirrored_inverse(
    action: &ResponseAction,
    step: ResponseRollbackStepKind,
    mutation: InverseMutation,
) -> Result<&'static str, &'static str> {
    match (action, step) {
        (
            ResponseAction::QuarantineFile { .. },
            ResponseRollbackStepKind::ReleaseQuarantinedFile,
        ) => Ok("release_quarantined_file"),
        _ if mutation == InverseMutation::InventUnmappedInverse => Ok("invented_inverse"),
        _ => Err("unmapped"),
    }
}

#[test]
fn broken_unmapped_inverse_fabricates_an_operation_for_a_mismatched_step() {
    let action = quarantine_action();
    let step = ResponseRollbackStepKind::ResumeProcess;
    assert!(resolve_inverse(&action, step).is_err());
    assert_eq!(
        mirrored_inverse(&action, step, InverseMutation::None),
        Err("unmapped")
    );
    assert_eq!(
        mirrored_inverse(&action, step, InverseMutation::InventUnmappedInverse),
        Ok("invented_inverse")
    );
}

// ---------------------------------------------------------------------------
// RESPONSE-ROLLBACK-REQUIRES-STEPS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequireStepsMutation {
    None,
    SkipRequiredSteps,
}

fn mirrored_require_steps(
    lease: &ContainmentLease,
    mutation: RequireStepsMutation,
) -> Result<(), &'static str> {
    if mutation != RequireStepsMutation::SkipRequiredSteps && lease.rollback().steps.is_empty() {
        return Err("no rollback steps");
    }
    Ok(())
}

#[tokio::test]
async fn broken_required_steps_guard_runs_a_rollback_with_no_inverse_plan() {
    let empty = ContainmentLease::open(
        "containment:empty-plan",
        quarantine_action(),
        "resp:empty-plan",
        None,
        &preview(&[]),
        1_000,
        ContainmentTtl::from_config_ms(900_000).unwrap(),
    )
    .unwrap();
    let real = SandboxRollbackExecutor
        .rollback(
            &empty,
            RollbackTrigger::Expiry,
            ExecutionMode::Enforced,
            2_000,
        )
        .await;
    assert!(real.is_err());
    assert_eq!(
        mirrored_require_steps(&empty, RequireStepsMutation::None),
        Err("no rollback steps")
    );
    assert_eq!(
        mirrored_require_steps(&empty, RequireStepsMutation::SkipRequiredSteps),
        Ok(())
    );
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

    let control =
        mirrored_derive_status(&steps, ExecutionMode::Enforced, DeriveStatusMutation::None);
    assert_eq!(
        control, real.status,
        "the unmutated mirror must reproduce the real derivation on the same \
         Enforced all-simulated probe"
    );

    let broken = mirrored_derive_status(
        &steps,
        ExecutionMode::Enforced,
        DeriveStatusMutation::SkipDryRunMode,
    );
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxMutation {
    None,
    ClaimEnforcedReversed,
}

/// Mirror of `SandboxRollbackExecutor::rollback`, copied from
/// `crates/swarm-response/src/rollback.rs`, reinstating the pre-cc5b169 shape:
/// a resolved inverse is recorded as `Reversed` when the mode is `Enforced`.
///
/// This executor cannot reach a host -- it holds no transport at all -- so
/// every `Reversed` it writes is a claim about a world it never touched.
fn mirrored_sandbox_rollback(
    lease: &ContainmentLease,
    trigger: RollbackTrigger,
    mode: ExecutionMode,
    completed_at_ms: i64,
    mutation: SandboxMutation,
) -> RollbackReceipt {
    let steps = lease
        .rollback()
        .steps
        .iter()
        .map(|step| match resolve_inverse(lease.action(), step.kind) {
            Ok(inverse) => RollbackStepOutcome {
                kind: step.kind,
                status: if mutation == SandboxMutation::ClaimEnforcedReversed
                    && mode == ExecutionMode::Enforced
                {
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

    let control = mirrored_sandbox_rollback(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::Enforced,
        2_000,
        SandboxMutation::None,
    );
    assert_eq!(
        control.status, real.status,
        "the unmutated mirror must reproduce the real executor on the same \
         Enforced probe"
    );
    assert_eq!(
        control.steps[0].status, real.steps[0].status,
        "and step for step, not only in the summary status"
    );

    let broken = mirrored_sandbox_rollback(
        &lease,
        RollbackTrigger::Expiry,
        ExecutionMode::Enforced,
        2_000,
        SandboxMutation::ClaimEnforcedReversed,
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
