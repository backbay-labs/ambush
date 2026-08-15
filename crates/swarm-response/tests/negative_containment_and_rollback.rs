//! Negative falsifiability tests for the `swarm-response` rows of
//! `docs/assurance/MAPPING.md` (FALSIFY-02).
//!
//! See the header of `crates/swarm-policy/tests/negative_policy_gates.rs` for
//! the three-step shape every test in this family follows (real function
//! refuses; unmutated mirror reproduces it; mutated mirror permits).

#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate serde_json as __phase285_serde_json;
extern crate swarm_response as __phase285_swarm_response;

#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;

use serde_json::json;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::types::{
    ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
    ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
    ResponseRollbackStep, ResponseRollbackStepKind,
};
use swarm_response::containment::{
    ContainmentLease, ContainmentLeaseError, ContainmentLeaseStore, ContainmentStoreError,
    ContainmentTtl, FileContainmentLeaseStore, MemoryContainmentLeaseStore,
};
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
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_TTL_STRICTLY_POSITIVE,
        mutation: TtlMutation,
        control: TtlMutation::None,
        broken: TtlMutation::SkipPositiveCheck,
        state: {},
        probe: i64 = 0,
        outcome: Result<i64, String>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::containment::ContainmentTtl::from_config_ms,
        arguments: (*probe),
        call: sync,
        normalize: |production_result| production_result.map(ContainmentTtl::get).map_err(|error| error.to_string()),
        mirror: |_state, probe, mutation| mirrored_ttl(*probe, mutation).map_err(|error| error.to_string()),
        denied: |result| result.is_err(),
        permitted: |result| result == &Ok(0),
    }
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

    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_LEASE_BOUNDED,
        mutation: OpenMutation,
        control: OpenMutation::None,
        broken: OpenMutation::SkipExpiryBound,
        state: { ttl: ContainmentTtl = ttl },
        probe: i64 = issued_at_ms,
        outcome: Result<i64, String>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::containment::ContainmentLease::open,
        arguments: (
            "containment:saturating",
            quarantine_action(),
            "resp:saturating",
            None,
            &preview(&[ResponseRollbackStepKind::ReleaseQuarantinedFile]),
            *probe,
            *ttl,
        ),
        call: sync,
        normalize: |production_result| production_result.map(|lease| lease.expires_at_ms()).map_err(|error| error.to_string()),
        mirror: |_state, probe, mutation| mirrored_open_expiry("containment:saturating", *probe, *ttl, mutation).map_err(|error| error.to_string()),
        denied: |result| result.is_err(),
        permitted: |result| result == &Ok(i64::MAX),
    }

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
    let lease_id = record
        .get("lease_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing lease_id")?;
    let schema_version = record
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing schema_version")?;
    if mutation != StoredLeaseMutation::SkipSchemaVersion && schema_version != 1 {
        return Err(format!(
            "containment lease `{lease_id}` declares schema version {schema_version}, this build understands 1"
        ));
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
        return Err(format!(
            "containment lease `{lease_id}` would expire at {expires_at_ms} but was issued at {issued_at_ms}; a containment must be bounded"
        ));
    }
    Ok(expires_at_ms)
}

#[test]
fn broken_schema_check_loads_a_lease_from_an_unknown_wire_version() {
    let mut wire = serde_json::to_value(lease(1_000, 900_000)).unwrap();
    wire["schema_version"] = json!(99);
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_STORED_LEASE_SCHEMA_KNOWN,
        mutation: StoredLeaseMutation,
        control: StoredLeaseMutation::None,
        broken: StoredLeaseMutation::SkipSchemaVersion,
        state: {},
        probe: serde_json::Value = wire,
        outcome: Result<i64, String>,
        real_probe: probe,
        production: crate::__phase285_serde_json::from_value::<ContainmentLease>,
        arguments: (probe.clone()),
        call: sync,
        normalize: |production_result| production_result.map(|lease| lease.expires_at_ms()).map_err(|error| error.to_string()),
        mirror: |_state, probe, mutation| mirrored_stored_lease_accepts(probe, mutation),
        denied: |result| result.is_err(),
        permitted: |result| result == &Ok(901_000),
    }
}

#[test]
fn broken_stored_lease_bound_accepts_the_already_expired_record_the_real_one_rejects() {
    // A lease record whose stored expiry is BEFORE its issue instant. Nothing
    // stops such a file appearing: `FileContainmentLeaseStore` reads a plain
    // JSON document off disk, so this is the at-rest tampering case.
    let mut wire = serde_json::to_value(lease(1_000, 900_000)).unwrap();
    wire["expires_at_ms"] = json!(900);
    assert_eq!(wire["issued_at_ms"], json!(1_000));

    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_STORED_LEASE_BOUNDED,
        mutation: StoredLeaseMutation,
        control: StoredLeaseMutation::None,
        broken: StoredLeaseMutation::SkipExpiryBound,
        state: {},
        probe: serde_json::Value = wire,
        outcome: Result<i64, String>,
        real_probe: probe,
        production: crate::__phase285_serde_json::from_value::<ContainmentLease>,
        arguments: (probe.clone()),
        call: sync,
        normalize: |production_result| production_result.map(|lease| lease.expires_at_ms()).map_err(|error| error.to_string()),
        mirror: |_state, probe, mutation| mirrored_stored_lease_accepts(probe, mutation),
        denied: |result| result.as_ref().is_err_and(|error| error.contains("must be bounded")),
        permitted: |result| result == &Ok(900),
    }

    // Control: the untampered record round-trips through the real deserializer.
    let clean = serde_json::to_value(lease(1_000, 900_000)).unwrap();
    let restored: ContainmentLease = serde_json::from_value(clean).unwrap();
    assert_eq!(restored.expires_at_ms(), 901_000);
}

// ---------------------------------------------------------------------------
// RESPONSE-{MEMORY,FILE}-{DUPLICATE-LEASE,CLOSE-UNKNOWN-LEASE}-REFUSED
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreMutation {
    None,
    SkipMemoryDuplicateOpen,
    SkipMemoryNotOpenClose,
    SkipFileDuplicateOpen,
    SkipFileNotOpenClose,
}

fn mirrored_store_transition(
    file_backed: bool,
    already_open: bool,
    close: bool,
    mutation: StoreMutation,
) -> Result<(), &'static str> {
    let skip = matches!(
        (file_backed, close, mutation),
        (false, false, StoreMutation::SkipMemoryDuplicateOpen)
            | (false, true, StoreMutation::SkipMemoryNotOpenClose)
            | (true, false, StoreMutation::SkipFileDuplicateOpen)
            | (true, true, StoreMutation::SkipFileNotOpenClose)
    );
    if !skip && ((!close && already_open) || (close && !already_open)) {
        return Err(if close { "not open" } else { "already open" });
    }
    Ok(())
}

fn rollback_receipt_for(lease: &ContainmentLease) -> RollbackReceipt {
    RollbackReceipt::from_steps(
        lease,
        RollbackTrigger::Manual,
        ExecutionMode::Enforced,
        2_000,
        vec![RollbackStepOutcome {
            kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
            status: RollbackStepStatus::Reversed,
            detail: "released".to_string(),
        }],
    )
}

fn unique_store_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "swarm-phase285-{label}-{}-{nonce}.json",
        std::process::id()
    ))
}

#[test]
fn broken_memory_duplicate_guard_accepts_a_second_open_for_one_lease() {
    let store = MemoryContainmentLeaseStore::new();
    let probe = lease(1_000, 900_000);
    store.open_lease(&probe).unwrap();
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_MEMORY_DUPLICATE_LEASE_REFUSED,
        mutation: StoreMutation,
        control: StoreMutation::None,
        broken: StoreMutation::SkipMemoryDuplicateOpen,
        state: { store: MemoryContainmentLeaseStore = store },
        probe: ContainmentLease = probe,
        outcome: Result<(), &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::containment::MemoryContainmentLeaseStore::open_lease,
        arguments: (&*store, probe),
        call: sync,
        normalize: |production_result| production_result.map_err(|error| match error {
                ContainmentStoreError::AlreadyOpen { .. } => "already open",
                _ => "unexpected",
            }),
        mirror: |_state, _probe, mutation| mirrored_store_transition(false, true, false, mutation),
        denied: |result| result == &Err("already open"),
        permitted: |result| result == &Ok(()),
    }
}

#[test]
fn broken_memory_not_open_guard_closes_an_unknown_lease() {
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_MEMORY_CLOSE_UNKNOWN_LEASE_REFUSED,
        mutation: StoreMutation,
        control: StoreMutation::None,
        broken: StoreMutation::SkipMemoryNotOpenClose,
        state: {},
        probe: ContainmentLease = lease(1_000, 900_000),
        outcome: Result<(), &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::containment::MemoryContainmentLeaseStore::close,
        arguments: (&MemoryContainmentLeaseStore::new(), &rollback_receipt_for(probe)),
        call: sync,
        normalize: |production_result| production_result.map_err(|error| match error {
            ContainmentStoreError::NotOpen { .. } => "not open",
            _ => "unexpected",
        }),
        mirror: |_state, _probe, mutation| mirrored_store_transition(false, false, true, mutation),
        denied: |result| result == &Err("not open"),
        permitted: |result| result == &Ok(()),
    }
}

#[test]
fn broken_file_duplicate_guard_accepts_a_second_open_for_one_lease() {
    let path = unique_store_path("duplicate");
    let store = FileContainmentLeaseStore::open(&path);
    let probe = lease(1_000, 900_000);
    store.open_lease(&probe).unwrap();
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_FILE_DUPLICATE_LEASE_REFUSED,
        mutation: StoreMutation,
        control: StoreMutation::None,
        broken: StoreMutation::SkipFileDuplicateOpen,
        state: { store: FileContainmentLeaseStore = store },
        probe: ContainmentLease = probe,
        outcome: Result<(), &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::containment::FileContainmentLeaseStore::open_lease,
        arguments: (&*store, probe),
        call: sync,
        normalize: |production_result| production_result.map_err(|error| match error {
                ContainmentStoreError::AlreadyOpen { .. } => "already open",
                _ => "unexpected",
            }),
        mirror: |_state, _probe, mutation| mirrored_store_transition(true, true, false, mutation),
        denied: |result| result == &Err("already open"),
        permitted: |result| result == &Ok(()),
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn broken_file_not_open_guard_closes_an_unknown_lease() {
    let path = unique_store_path("not-open");
    let store = FileContainmentLeaseStore::open(&path);
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_FILE_CLOSE_UNKNOWN_LEASE_REFUSED,
        mutation: StoreMutation,
        control: StoreMutation::None,
        broken: StoreMutation::SkipFileNotOpenClose,
        state: { store: FileContainmentLeaseStore = store },
        probe: ContainmentLease = lease(1_000, 900_000),
        outcome: Result<(), &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::containment::FileContainmentLeaseStore::close,
        arguments: (&*store, &rollback_receipt_for(probe)),
        call: sync,
        normalize: |production_result| production_result.map_err(|error| match error {
                ContainmentStoreError::NotOpen { .. } => "not open",
                _ => "unexpected",
            }),
        mirror: |_state, _probe, mutation| mirrored_store_transition(true, false, true, mutation),
        denied: |result| result == &Err("not open"),
        permitted: |result| result == &Ok(()),
    }
    assert!(!path.exists());
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
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_EMPTY_ROLLBACK_NOT_SUCCESS,
        mutation: DeriveStatusMutation,
        control: DeriveStatusMutation::None,
        broken: DeriveStatusMutation::SkipEmptySteps,
        state: { lease: ContainmentLease = lease },
        probe: Vec<RollbackStepOutcome> = steps,
        outcome: ResponseStatus,
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::RollbackReceipt::from_steps,
        arguments: (lease, RollbackTrigger::Expiry, ExecutionMode::Enforced, 2_000, probe.clone()),
        call: sync,
        normalize: |production_result| production_result.status,
        mirror: |_state, probe, mutation| mirrored_derive_status(probe, ExecutionMode::Enforced, mutation),
        denied: |status| status == &ResponseStatus::Failed,
        permitted: |status| status == &ResponseStatus::Executed,
    }
}

#[test]
fn broken_partial_status_reports_success_with_an_unsupported_inverse() {
    let lease = lease(1_000, 900_000);
    let steps = vec![RollbackStepOutcome {
        kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
        status: RollbackStepStatus::Unsupported,
        detail: "no adapter inverse".to_string(),
    }];
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_PARTIAL_ROLLBACK_NOT_SUCCESS,
        mutation: DeriveStatusMutation,
        control: DeriveStatusMutation::None,
        broken: DeriveStatusMutation::ReportPartialSuccess,
        state: { lease: ContainmentLease = lease },
        probe: Vec<RollbackStepOutcome> = steps,
        outcome: ResponseStatus,
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::RollbackReceipt::from_steps,
        arguments: (lease, RollbackTrigger::Expiry, ExecutionMode::Enforced, 2_000, probe.clone()),
        call: sync,
        normalize: |production_result| production_result.status,
        mirror: |_state, probe, mutation| mirrored_derive_status(probe, ExecutionMode::Enforced, mutation),
        denied: |status| status == &ResponseStatus::Failed,
        permitted: |status| status == &ResponseStatus::Executed,
    }
}

// ---------------------------------------------------------------------------
// RESPONSE-UNMAPPED-INVERSE-REFUSED
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InverseMutation {
    None,
    InventUnmappedInverse,
    InventIrreversibleInverse,
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
        (
            ResponseAction::TerminateUserSession { .. },
            ResponseRollbackStepKind::ReauthenticateUserSession,
        ) if mutation == InverseMutation::InventIrreversibleInverse => {
            Ok("reauthenticate_user_session")
        }
        (
            ResponseAction::TerminateUserSession { .. },
            ResponseRollbackStepKind::ReauthenticateUserSession,
        ) => Err("irreversible"),
        _ if mutation == InverseMutation::InventUnmappedInverse => Ok("invented_inverse"),
        _ => Err("unmapped"),
    }
}

#[test]
fn broken_irreversible_inverse_invents_a_fresh_session_as_a_reversal() {
    let action = ResponseAction::TerminateUserSession {
        host_id: "host-1".to_string(),
        session_id: "session-1".to_string(),
    };
    let step = ResponseRollbackStepKind::ReauthenticateUserSession;
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_IRREVERSIBLE_INVERSE_REFUSED,
        mutation: InverseMutation,
        control: InverseMutation::None,
        broken: InverseMutation::InventIrreversibleInverse,
        state: {},
        probe: (ResponseAction, ResponseRollbackStepKind) = (action, step),
        outcome: Result<&'static str, &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::resolve_inverse,
        arguments: (&probe.0, probe.1),
        call: sync,
        normalize: |production_result| production_result.map(|_| "mapped").map_err(|gap| if format!("{gap:?}").contains("Irreversible") { "irreversible" } else { "unexpected" }),
        mirror: |_state, probe, mutation| mirrored_inverse(&probe.0, probe.1, mutation),
        denied: |result| result == &Err("irreversible"),
        permitted: |result| result == &Ok("reauthenticate_user_session"),
    }
}

#[test]
fn broken_unmapped_inverse_fabricates_an_operation_for_a_mismatched_step() {
    let action = quarantine_action();
    let step = ResponseRollbackStepKind::ResumeProcess;
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_UNMAPPED_INVERSE_REFUSED,
        mutation: InverseMutation,
        control: InverseMutation::None,
        broken: InverseMutation::InventUnmappedInverse,
        state: {},
        probe: (ResponseAction, ResponseRollbackStepKind) = (action, step),
        outcome: Result<&'static str, &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::resolve_inverse,
        arguments: (&probe.0, probe.1),
        call: sync,
        normalize: |production_result| production_result.map(|_| "mapped").map_err(|_| "unmapped"),
        mirror: |_state, probe, mutation| mirrored_inverse(&probe.0, probe.1, mutation),
        denied: |result| result == &Err("unmapped"),
        permitted: |result| result == &Ok("invented_inverse"),
    }
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
    negative_protocol::assert_registered_async_negative_case! {
        case: RESPONSE_ROLLBACK_REQUIRES_STEPS,
        mutation: RequireStepsMutation,
        control: RequireStepsMutation::None,
        broken: RequireStepsMutation::SkipRequiredSteps,
        state: {},
        probe: ContainmentLease = empty,
        outcome: Result<(), &'static str>,
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::SandboxRollbackExecutor::rollback,
        arguments: (&SandboxRollbackExecutor, probe, RollbackTrigger::Expiry, ExecutionMode::Enforced, 2_000),
        call: awaited,
        normalize: |production_result| production_result.map(|_| ()).map_err(|_| "no rollback steps"),
        mirror: |_state, probe, mutation| mirrored_require_steps(probe, mutation),
        denied: |result| result == &Err("no rollback steps"),
        permitted: |result| result == &Ok(()),
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
    negative_protocol::assert_registered_negative_case! {
        case: RESPONSE_ENFORCED_SIMULATION_NOT_SUCCESS,
        mutation: DeriveStatusMutation,
        control: DeriveStatusMutation::None,
        broken: DeriveStatusMutation::SkipDryRunMode,
        state: { lease: ContainmentLease = lease },
        probe: Vec<RollbackStepOutcome> = steps,
        outcome: ResponseStatus,
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::RollbackReceipt::from_steps,
        arguments: (lease, RollbackTrigger::Expiry, ExecutionMode::Enforced, 2_000, probe.clone()),
        call: sync,
        normalize: |production_result| production_result.status,
        mirror: |_state, probe, mutation| mirrored_derive_status(probe, ExecutionMode::Enforced, mutation),
        denied: |status| status == &ResponseStatus::Failed && !status.indicates_success(),
        permitted: |status| status == &ResponseStatus::Simulated && status.indicates_success(),
    }
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
    negative_protocol::assert_registered_async_negative_case! {
        case: RESPONSE_SANDBOX_NEVER_REVERSES,
        mutation: SandboxMutation,
        control: SandboxMutation::None,
        broken: SandboxMutation::ClaimEnforcedReversed,
        state: {},
        probe: ContainmentLease = lease(1_000, 900_000),
        outcome: (ResponseStatus, RollbackStepStatus),
        real_probe: probe,
        production: crate::__phase285_swarm_response::rollback::SandboxRollbackExecutor::rollback,
        arguments: (&SandboxRollbackExecutor, probe, RollbackTrigger::Expiry, ExecutionMode::Enforced, 2_000),
        call: awaited,
        normalize: |production_result| {
            let receipt = production_result.expect("receipt");
            (receipt.status, receipt.steps[0].status)
        },
        mirror: |_state, probe, mutation| {
            let receipt = mirrored_sandbox_rollback(probe, RollbackTrigger::Expiry, ExecutionMode::Enforced, 2_000, mutation);
            (receipt.status, receipt.steps[0].status)
        },
        denied: |result| result == &(ResponseStatus::Failed, RollbackStepStatus::Simulated),
        permitted: |result| result == &(ResponseStatus::Executed, RollbackStepStatus::Reversed),
    }
}
