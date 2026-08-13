//! Containment leases: the bounded, addressable record of a containment that
//! took effect, plus the stores that keep one durable.
//!
//! WHY THE FIELDS ARE PRIVATE AND THE MODULE IS SEPARATE FROM `rollback`.
//! The whole point of a lease is the invariant `expires_at_ms > issued_at_ms`:
//! a containment with no guaranteed end is the unbounded containment this lane
//! exists to remove. Rust field privacy is MODULE scoped, so a lease declared
//! in `rollback.rs` next to `SandboxRollbackExecutor` is freely constructible
//! by it — `ContainmentLease { expires_at_ms: 0, .. }` compiles, and the
//! invariant is prose. Declaring it here, where no executor lives, is what makes
//! [`ContainmentLease::open`] the only way to get one in code.
//!
//! (`ContainmentLedger`, the in-memory `Vec` that shipped in 4d03543 with zero
//! non-test callers, is [`MemoryContainmentLeaseStore`] now: the same
//! bookkeeping behind the trait the sweep and the runtime actually depend on.)
//!
//! The other way in is deserialization, and a `#[derive(Deserialize)]` walks
//! straight past a constructor. So the wire form is a separate private struct
//! and `TryFrom` re-checks the bound: a stored lease that was hand-edited to
//! drop its expiry fails to parse rather than defaulting to zero.
//!
//! Owns: the lease record, its lifetime bound, and lease persistence.
//! Does not own: deriving the inverse plan (that is `swarm-runtime`'s
//! `build_rehearsal_preview`), executing it (that is [`crate::rollback`]), or
//! deciding when to sweep (that is `swarm-runtime`'s containment module).

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroI64;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use swarm_core::types::{
    ResponseAction, ResponseBlastRadiusPreview, ResponseRehearsalPreview, ResponseRollbackPreview,
};

use crate::rollback::RollbackReceipt;

/// Wire format version for a persisted [`ContainmentLease`].
///
/// Bump when a field is added or removed. A stored lease whose version this
/// build does not recognise is refused rather than partially read, because a
/// half-understood lease cannot be trusted to bound anything.
pub const CONTAINMENT_LEASE_SCHEMA_VERSION: u32 = 1;

/// Errors raised while constructing or validating a containment lease.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentLeaseError {
    #[error("containment lease ttl must be strictly positive, got {ttl_ms}ms")]
    NonPositiveTtl { ttl_ms: i64 },

    #[error(
        "containment lease `{lease_id}` would expire at {expires_at_ms} but was issued at \
         {issued_at_ms}; a containment must be bounded"
    )]
    UnboundedLease {
        lease_id: String,
        issued_at_ms: i64,
        expires_at_ms: i64,
    },

    #[error(
        "containment lease `{lease_id}` declares schema version {found}, this build understands \
         {expected}"
    )]
    UnknownSchemaVersion {
        lease_id: String,
        found: u32,
        expected: u32,
    },
}

/// A strictly positive containment lifetime.
///
/// The newtype is the "mandatory expiry" requirement expressed as a type: there
/// is no `ContainmentTtl` that means "no expiry", so a caller holding one
/// cannot open an unbounded lease. Mirrors the `ttl_ms <= 0 -> None` guard that
/// `issue_contingency_lease` applies in `swarm-agents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainmentTtl(NonZeroI64);

impl ContainmentTtl {
    /// Build a TTL from a configured millisecond value, refusing zero and negatives.
    pub fn from_config_ms(ttl_ms: i64) -> Result<Self, ContainmentLeaseError> {
        match NonZeroI64::new(ttl_ms) {
            Some(value) if value.get() > 0 => Ok(Self(value)),
            _ => Err(ContainmentLeaseError::NonPositiveTtl { ttl_ms }),
        }
    }

    /// Lifetime in milliseconds, always `> 0`.
    pub fn get(self) -> i64 {
        self.0.get()
    }
}

/// Persisted form of a lease. Private on purpose: it is the only shape that can
/// be deserialized, and [`ContainmentLease`] is reachable from it only through
/// the `TryFrom` below, which re-applies the bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainmentLeaseRecord {
    schema_version: u32,
    lease_id: String,
    action: ResponseAction,
    origin_receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    governance_receipt_id: Option<String>,
    blast_radius: ResponseBlastRadiusPreview,
    rollback: ResponseRollbackPreview,
    issued_at_ms: i64,
    // Deliberately no `#[serde(default)]`. A stored lease with no expiry is a
    // parse error, not a lease that expires at the epoch. `TryFrom` below is a
    // SECOND, independent check; this one is what makes the field mandatory at
    // the wire rather than merely bounded once read.
    expires_at_ms: i64,
}

/// A containment that took effect, the plan that undoes it, and when it lapses.
///
/// The action is the TYPED [`ResponseAction`], not its name. A rollback step
/// carries only a kind and a prose summary (`ResponseRollbackStep` in
/// `swarm-core`), so nothing on the plan is addressable; the concrete host,
/// file, process or session an inverse has to act on can only come from the
/// action itself. Storing the action as a string is what made the shipped
/// rollback executor unable to do anything but echo the summary back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "ContainmentLeaseRecord", try_from = "ContainmentLeaseRecord")]
pub struct ContainmentLease {
    lease_id: String,
    action: ResponseAction,
    origin_receipt_id: String,
    governance_receipt_id: Option<String>,
    blast_radius: ResponseBlastRadiusPreview,
    rollback: ResponseRollbackPreview,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

impl From<ContainmentLease> for ContainmentLeaseRecord {
    fn from(lease: ContainmentLease) -> Self {
        Self {
            schema_version: CONTAINMENT_LEASE_SCHEMA_VERSION,
            lease_id: lease.lease_id,
            action: lease.action,
            origin_receipt_id: lease.origin_receipt_id,
            governance_receipt_id: lease.governance_receipt_id,
            blast_radius: lease.blast_radius,
            rollback: lease.rollback,
            issued_at_ms: lease.issued_at_ms,
            expires_at_ms: lease.expires_at_ms,
        }
    }
}

impl TryFrom<ContainmentLeaseRecord> for ContainmentLease {
    type Error = ContainmentLeaseError;

    fn try_from(record: ContainmentLeaseRecord) -> Result<Self, Self::Error> {
        if record.schema_version != CONTAINMENT_LEASE_SCHEMA_VERSION {
            return Err(ContainmentLeaseError::UnknownSchemaVersion {
                lease_id: record.lease_id,
                found: record.schema_version,
                expected: CONTAINMENT_LEASE_SCHEMA_VERSION,
            });
        }
        if record.expires_at_ms <= record.issued_at_ms {
            return Err(ContainmentLeaseError::UnboundedLease {
                lease_id: record.lease_id,
                issued_at_ms: record.issued_at_ms,
                expires_at_ms: record.expires_at_ms,
            });
        }
        Ok(Self {
            lease_id: record.lease_id,
            action: record.action,
            origin_receipt_id: record.origin_receipt_id,
            governance_receipt_id: record.governance_receipt_id,
            blast_radius: record.blast_radius,
            rollback: record.rollback,
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        })
    }
}

impl ContainmentLease {
    /// The only constructor. Derives the expiry from a strictly positive TTL, so
    /// no caller chooses it and no caller can omit it.
    ///
    /// `preview` is the rehearsal the runtime already derives for this action;
    /// taking the whole preview is what puts the blast radius and the inverse
    /// plan on the lease from one derivation rather than two.
    pub fn open(
        lease_id: impl Into<String>,
        action: ResponseAction,
        origin_receipt_id: impl Into<String>,
        governance_receipt_id: Option<String>,
        preview: &ResponseRehearsalPreview,
        issued_at_ms: i64,
        ttl: ContainmentTtl,
    ) -> Result<Self, ContainmentLeaseError> {
        let lease_id = lease_id.into();
        // Saturating rather than wrapping, then re-checked: at `i64::MAX` the
        // add is a no-op and the lease would be unbounded, which is exactly the
        // state the error below exists to refuse.
        let expires_at_ms = issued_at_ms.saturating_add(ttl.get());
        if expires_at_ms <= issued_at_ms {
            return Err(ContainmentLeaseError::UnboundedLease {
                lease_id,
                issued_at_ms,
                expires_at_ms,
            });
        }
        Ok(Self {
            lease_id,
            action,
            origin_receipt_id: origin_receipt_id.into(),
            governance_receipt_id,
            blast_radius: preview.blast_radius.clone(),
            rollback: preview.rollback.clone(),
            issued_at_ms,
            expires_at_ms,
        })
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// The typed containment this lease holds open.
    pub fn action(&self) -> &ResponseAction {
        &self.action
    }

    /// Stable action name, for messages and receipts.
    pub fn action_kind(&self) -> &'static str {
        self.action.kind()
    }

    /// Receipt that recorded the containment, for chain linkage.
    pub fn origin_receipt_id(&self) -> &str {
        &self.origin_receipt_id
    }

    /// Governance receipt that authorized the containment, when one applied.
    pub fn governance_receipt_id(&self) -> Option<&str> {
        self.governance_receipt_id.as_deref()
    }

    /// What the containment reaches, as derived when it was authorized.
    pub fn blast_radius(&self) -> &ResponseBlastRadiusPreview {
        &self.blast_radius
    }

    /// The inverse plan derived when the containment was authorized.
    pub fn rollback(&self) -> &ResponseRollbackPreview {
        &self.rollback
    }

    pub fn issued_at_ms(&self) -> i64 {
        self.issued_at_ms
    }

    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    /// Whether the lease has reached or passed its expiry at `now_ms`.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Milliseconds remaining before automatic rollback, saturating at zero.
    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        self.expires_at_ms.saturating_sub(now_ms).max(0)
    }
}

/// Errors raised by a containment lease store.
#[derive(Debug, thiserror::Error)]
pub enum ContainmentStoreError {
    #[error("containment lease `{lease_id}` is already open")]
    AlreadyOpen { lease_id: String },

    #[error("no open containment lease `{lease_id}` to close")]
    NotOpen { lease_id: String },

    #[error("containment lease store i/o failed: {0}")]
    Io(String),

    #[error("containment lease store holds unreadable state: {0}")]
    Corrupt(String),
}

/// Durable record of which containments are open and which were undone.
///
/// `close` must reject a second close of the same lease: a lease that can close
/// twice can produce two rollback receipts for one containment, and the audit
/// trail then cannot say which one describes reality.
pub trait ContainmentLeaseStore: Send + Sync + std::fmt::Debug {
    fn open_lease(&self, lease: &ContainmentLease) -> Result<(), ContainmentStoreError>;
    fn get(&self, lease_id: &str) -> Result<Option<ContainmentLease>, ContainmentStoreError>;
    fn open_leases(&self) -> Result<Vec<ContainmentLease>, ContainmentStoreError>;
    fn closed_receipts(&self) -> Result<Vec<RollbackReceipt>, ContainmentStoreError>;
    fn close(&self, receipt: &RollbackReceipt) -> Result<(), ContainmentStoreError>;

    /// Leases whose expiry has passed at `now_ms`, in issue order.
    ///
    /// `now_ms` IS A PARAMETER and there is no default. The sweep that drives
    /// this is the one piece of the lane whose correctness is a statement about
    /// time, and a store that read the clock itself would make that statement
    /// untestable without sleeping.
    fn expired(&self, now_ms: i64) -> Result<Vec<ContainmentLease>, ContainmentStoreError> {
        let mut expired: Vec<ContainmentLease> = self
            .open_leases()?
            .into_iter()
            .filter(|lease| lease.is_expired(now_ms))
            .collect();
        expired.sort_by_key(|lease| lease.issued_at_ms);
        Ok(expired)
    }
}

#[derive(Debug, Default)]
struct ContainmentState {
    open: Vec<ContainmentLease>,
    closed: Vec<RollbackReceipt>,
}

impl ContainmentState {
    fn open_lease(&mut self, lease: &ContainmentLease) -> Result<(), ContainmentStoreError> {
        if self
            .open
            .iter()
            .any(|existing| existing.lease_id == lease.lease_id)
        {
            return Err(ContainmentStoreError::AlreadyOpen {
                lease_id: lease.lease_id.clone(),
            });
        }
        self.open.push(lease.clone());
        Ok(())
    }

    fn close(&mut self, receipt: &RollbackReceipt) -> Result<(), ContainmentStoreError> {
        let Some(index) = self
            .open
            .iter()
            .position(|lease| lease.lease_id == receipt.lease_id)
        else {
            return Err(ContainmentStoreError::NotOpen {
                lease_id: receipt.lease_id.clone(),
            });
        };
        self.open.remove(index);
        self.closed.push(receipt.clone());
        Ok(())
    }
}

/// In-memory lease store. The durability boundary for tests and for
/// `detect_only` deployments that never contain anything for real.
#[derive(Debug, Default)]
pub struct MemoryContainmentLeaseStore {
    state: Mutex<ContainmentState>,
}

impl MemoryContainmentLeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, ContainmentState> {
        // A poisoned lock still holds a consistent `ContainmentState`; refusing
        // every later containment because one unrelated test panicked would be
        // worse than reading through the poison.
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl ContainmentLeaseStore for MemoryContainmentLeaseStore {
    fn open_lease(&self, lease: &ContainmentLease) -> Result<(), ContainmentStoreError> {
        self.locked().open_lease(lease)
    }

    fn get(&self, lease_id: &str) -> Result<Option<ContainmentLease>, ContainmentStoreError> {
        Ok(self
            .locked()
            .open
            .iter()
            .find(|lease| lease.lease_id == lease_id)
            .cloned())
    }

    fn open_leases(&self) -> Result<Vec<ContainmentLease>, ContainmentStoreError> {
        Ok(self.locked().open.clone())
    }

    fn closed_receipts(&self) -> Result<Vec<RollbackReceipt>, ContainmentStoreError> {
        Ok(self.locked().closed.clone())
    }

    fn close(&self, receipt: &RollbackReceipt) -> Result<(), ContainmentStoreError> {
        self.locked().close(receipt)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedContainmentState {
    #[serde(default)]
    open: BTreeMap<String, ContainmentLease>,
    #[serde(default)]
    closed: Vec<RollbackReceipt>,
}

/// File-backed lease store: one JSON document, written tmp-then-rename.
///
/// The in-process `Mutex` serializes readers and writers in this process; the
/// rename is what keeps a reader in ANOTHER process from ever observing a
/// half-written document. Two writing processes are still a lost update, which
/// is why nothing in this lane opens a second writer — see the module note on
/// the CLI in `swarm-runtime`'s containment module.
#[derive(Debug)]
pub struct FileContainmentLeaseStore {
    path: PathBuf,
    guard: Mutex<()>,
}

impl FileContainmentLeaseStore {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            guard: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<PersistedContainmentState, ContainmentStoreError> {
        if !self.path.exists() {
            return Ok(PersistedContainmentState::default());
        }
        let bytes =
            fs::read(&self.path).map_err(|error| ContainmentStoreError::Io(error.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| ContainmentStoreError::Corrupt(error.to_string()))
    }

    fn write(&self, state: &PersistedContainmentState) -> Result<(), ContainmentStoreError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|error| ContainmentStoreError::Io(error.to_string()))?;
        }
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| ContainmentStoreError::Corrupt(error.to_string()))?;
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, bytes)
            .map_err(|error| ContainmentStoreError::Io(error.to_string()))?;
        fs::rename(&tmp_path, &self.path)
            .map_err(|error| ContainmentStoreError::Io(error.to_string()))?;
        Ok(())
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, ()> {
        self.guard.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl ContainmentLeaseStore for FileContainmentLeaseStore {
    fn open_lease(&self, lease: &ContainmentLease) -> Result<(), ContainmentStoreError> {
        let _guard = self.locked();
        let mut state = self.read()?;
        if state.open.contains_key(&lease.lease_id) {
            return Err(ContainmentStoreError::AlreadyOpen {
                lease_id: lease.lease_id.clone(),
            });
        }
        state.open.insert(lease.lease_id.clone(), lease.clone());
        self.write(&state)
    }

    fn get(&self, lease_id: &str) -> Result<Option<ContainmentLease>, ContainmentStoreError> {
        let _guard = self.locked();
        Ok(self.read()?.open.get(lease_id).cloned())
    }

    fn open_leases(&self) -> Result<Vec<ContainmentLease>, ContainmentStoreError> {
        let _guard = self.locked();
        Ok(self.read()?.open.into_values().collect())
    }

    fn closed_receipts(&self) -> Result<Vec<RollbackReceipt>, ContainmentStoreError> {
        let _guard = self.locked();
        Ok(self.read()?.closed)
    }

    fn close(&self, receipt: &RollbackReceipt) -> Result<(), ContainmentStoreError> {
        let _guard = self.locked();
        let mut state = self.read()?;
        if state.open.remove(&receipt.lease_id).is_none() {
            return Err(ContainmentStoreError::NotOpen {
                lease_id: receipt.lease_id.clone(),
            });
        }
        state.closed.push(receipt.clone());
        self.write(&state)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::rollback::{RollbackStepOutcome, RollbackStepStatus, RollbackTrigger};
    use crate::{ExecutionMode, ResponseStatus};
    use swarm_core::types::{
        ResponseBlastRadiusImpact, ResponseRehearsalScopeKind, ResponseRollbackStep,
        ResponseRollbackStepKind,
    };

    pub(super) fn sample_preview() -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:test".to_string(),
            source_bundle_id: "bundle:test".to_string(),
            prepared_at_ms: 1_000,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::File,
                scope_value: "host-1:/tmp/a".to_string(),
                impact: ResponseBlastRadiusImpact::FileQuarantined,
                max_affected_scopes: 1,
                affected_capabilities: vec!["file_access".to_string()],
                summary: "quarantines one file".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: "release the file".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
                    summary: "restore /tmp/a".to_string(),
                }],
            },
        }
    }

    fn quarantine_action() -> ResponseAction {
        ResponseAction::QuarantineFile {
            host_id: "host-1".to_string(),
            file_path: "/tmp/a".to_string(),
        }
    }

    pub(super) fn sample_lease(lease_id: &str, issued_at_ms: i64, ttl_ms: i64) -> ContainmentLease {
        ContainmentLease::open(
            lease_id,
            quarantine_action(),
            format!("resp:{lease_id}"),
            Some(format!("gov:{lease_id}")),
            &sample_preview(),
            issued_at_ms,
            ContainmentTtl::from_config_ms(ttl_ms).unwrap(),
        )
        .unwrap()
    }

    fn receipt_for(lease_id: &str) -> RollbackReceipt {
        RollbackReceipt {
            rollback_id: format!("rollback:{lease_id}"),
            lease_id: lease_id.to_string(),
            origin_receipt_id: format!("resp:{lease_id}"),
            governance_receipt_id: Some(format!("gov:{lease_id}")),
            trigger: RollbackTrigger::Manual,
            mode: ExecutionMode::Enforced,
            status: ResponseStatus::Executed,
            steps: vec![RollbackStepOutcome {
                kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
                status: RollbackStepStatus::Reversed,
                detail: "released".to_string(),
            }],
            completed_at_ms: 5_000,
            summary: "reversed".to_string(),
        }
    }

    #[test]
    fn a_ttl_must_be_strictly_positive() {
        assert_eq!(
            ContainmentTtl::from_config_ms(0),
            Err(ContainmentLeaseError::NonPositiveTtl { ttl_ms: 0 })
        );
        assert_eq!(
            ContainmentTtl::from_config_ms(-1),
            Err(ContainmentLeaseError::NonPositiveTtl { ttl_ms: -1 })
        );
        assert_eq!(ContainmentTtl::from_config_ms(1).unwrap().get(), 1);
    }

    #[test]
    fn open_derives_the_expiry_from_the_ttl() {
        let lease = sample_lease("lease-1", 1_000, 4_000);
        assert_eq!(lease.issued_at_ms(), 1_000);
        assert_eq!(lease.expires_at_ms(), 5_000);
        assert!(!lease.is_expired(4_999));
        assert!(lease.is_expired(5_000));
        assert_eq!(lease.remaining_ms(4_500), 500);
        assert_eq!(lease.remaining_ms(9_000), 0);
    }

    #[test]
    fn open_refuses_a_lease_that_cannot_be_bounded() {
        let error = ContainmentLease::open(
            "lease-max",
            quarantine_action(),
            "resp:lease-max",
            None,
            &sample_preview(),
            i64::MAX,
            ContainmentTtl::from_config_ms(1_000).unwrap(),
        )
        .expect_err("saturating add at i64::MAX cannot bound a lease");
        assert!(
            matches!(error, ContainmentLeaseError::UnboundedLease { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_lease_carries_blast_radius_and_the_typed_action() {
        let lease = sample_lease("lease-1", 1_000, 4_000);
        assert_eq!(lease.action(), &quarantine_action());
        assert_eq!(lease.action_kind(), "quarantine_file");
        assert_eq!(lease.blast_radius().scope_value, "host-1:/tmp/a");
        assert_eq!(lease.rollback().steps.len(), 1);
        assert_eq!(lease.governance_receipt_id(), Some("gov:lease-1"));
    }

    #[test]
    fn a_stored_lease_with_no_expiry_fails_to_deserialize() {
        let lease = sample_lease("lease-1", 1_000, 4_000);
        let mut value = serde_json::to_value(&lease).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("expires_at_ms")
            .expect("the serialized form must carry an expiry");
        let error = serde_json::from_value::<ContainmentLease>(value)
            .expect_err("a lease with no expiry must not parse");
        assert!(
            error.to_string().contains("expires_at_ms"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_stored_lease_that_expires_before_issue_fails_to_deserialize() {
        let lease = sample_lease("lease-1", 1_000, 4_000);
        let mut value = serde_json::to_value(&lease).unwrap();
        value.as_object_mut().unwrap().insert(
            "expires_at_ms".to_string(),
            serde_json::Value::from(1_000_i64),
        );
        let error = serde_json::from_value::<ContainmentLease>(value)
            .expect_err("a lease expiring at issue must not parse");
        assert!(
            error.to_string().contains("a containment must be bounded"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_stored_lease_from_an_unknown_schema_version_fails_to_deserialize() {
        let lease = sample_lease("lease-1", 1_000, 4_000);
        let mut value = serde_json::to_value(&lease).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("schema_version".to_string(), serde_json::Value::from(99));
        let error = serde_json::from_value::<ContainmentLease>(value)
            .expect_err("an unknown schema version must not parse");
        assert!(
            error.to_string().contains("schema version 99"),
            "unexpected error: {error}"
        );
    }

    fn store_round_trip(store: &dyn ContainmentLeaseStore) {
        let early = sample_lease("lease-early", 1_000, 1_000);
        let late = sample_lease("lease-late", 1_000, 9_000);
        store.open_lease(&early).unwrap();
        store.open_lease(&late).unwrap();

        assert!(matches!(
            store.open_lease(&early),
            Err(ContainmentStoreError::AlreadyOpen { .. })
        ));
        assert_eq!(store.open_leases().unwrap().len(), 2);
        assert_eq!(
            store.get("lease-early").unwrap().map(|l| l.expires_at_ms()),
            Some(2_000)
        );
        assert!(store.get("missing").unwrap().is_none());

        assert!(store.expired(1_999).unwrap().is_empty());
        let expired = store.expired(2_000).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id(), "lease-early");

        store.close(&receipt_for("lease-early")).unwrap();
        assert_eq!(store.open_leases().unwrap().len(), 1);
        assert_eq!(store.closed_receipts().unwrap().len(), 1);
        assert!(matches!(
            store.close(&receipt_for("lease-early")),
            Err(ContainmentStoreError::NotOpen { .. })
        ));
    }

    #[test]
    fn memory_store_holds_the_lease_contract() {
        store_round_trip(&MemoryContainmentLeaseStore::new());
    }

    #[test]
    fn file_store_holds_the_lease_contract_across_reopen() {
        let dir = std::env::temp_dir().join(format!("swarm-containment-{}", std::process::id()));
        let path = dir.join("leases.json");
        let _ = fs::remove_file(&path);
        store_round_trip(&FileContainmentLeaseStore::open(&path));

        // Reopening reads the same document: the lease survived the process
        // boundary, which is the only reason a file store exists.
        let reopened = FileContainmentLeaseStore::open(&path);
        assert_eq!(reopened.open_leases().unwrap().len(), 1);
        assert_eq!(reopened.closed_receipts().unwrap().len(), 1);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
