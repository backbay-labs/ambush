//! Reversible containment: leases, inverse execution, and chained receipts.
//!
//! Containment actions (`QuarantineFile`, `IsolateHost`, `SuspendProcess`,
//! `TerminateUserSession`) dispatch through the adapters in this crate and take
//! real effect on real hosts. Until this module existed the runtime could
//! derive an inverse plan (`build_rehearsal_preview` in `swarm-runtime`) and
//! render it for an operator, but nothing could execute one: the system could
//! contain a host and could not un-contain it.
//!
//! Reversibility is what makes aggressive autonomous containment acceptable. An
//! irreversible action taken on a false positive is the failure mode this
//! product cannot afford, so every containment recorded here carries a bounded
//! lifetime and an executable undo.
//!
//! Owns: containment lease records, inverse-plan execution, rollback receipts
//! chained to the receipt that authorized the containment.
//!
//! Does not own: deriving the inverse plan (that is `swarm-runtime`'s
//! `build_rehearsal_preview`), authorizing the original containment (that is
//! `swarm-policy` plus governance), or signing (that is `swarm-crypto`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use swarm_core::types::{ResponseRollbackPreview, ResponseRollbackStepKind};

use crate::{ExecutionMode, ResponseError, ResponseStatus};

/// Why a rollback ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTrigger {
    /// An operator released the containment early.
    Manual,
    /// The lease reached `expires_at_ms` and the sweep released it.
    Expiry,
}

/// A containment that took effect and can be undone.
///
/// `expires_at_ms` is mandatory by construction: a lease with no expiry is a
/// containment with no guaranteed end, which is the state this module exists to
/// make unrepresentable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentLease {
    pub lease_id: String,
    /// Stable action name of the containment being held open.
    pub action: String,
    /// Receipt that recorded the containment, for chain linkage.
    pub origin_receipt_id: String,
    /// Inverse plan derived when the containment was authorized.
    pub rollback: ResponseRollbackPreview,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    /// Governance receipt that authorized the destructive action, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
}

impl ContainmentLease {
    /// Whether the lease has reached or passed its expiry at `now_ms`.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Milliseconds remaining before automatic rollback, saturating at zero.
    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        self.expires_at_ms.saturating_sub(now_ms).max(0)
    }
}

/// Outcome of one inverse step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackStepOutcome {
    pub kind: ResponseRollbackStepKind,
    pub status: ResponseStatus,
    pub detail: String,
}

/// Receipt proving a containment was undone, chained to the receipt that made it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackReceipt {
    pub rollback_id: String,
    pub lease_id: String,
    /// Chain link back to the containment receipt this undoes.
    pub origin_receipt_id: String,
    pub trigger: RollbackTrigger,
    pub mode: ExecutionMode,
    pub status: ResponseStatus,
    pub steps: Vec<RollbackStepOutcome>,
    pub completed_at_ms: i64,
    pub summary: String,
}

impl RollbackReceipt {
    /// Whether every inverse step reached a terminal success state.
    pub fn fully_reversed(&self) -> bool {
        !self.steps.is_empty()
            && self.steps.iter().all(|step| {
                matches!(
                    step.status,
                    ResponseStatus::Executed | ResponseStatus::Simulated
                )
            })
    }
}

/// Executes the inverse plan recorded on a containment lease.
#[async_trait]
pub trait RollbackExecutor: Send + Sync {
    async fn rollback(
        &self,
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
    ) -> Result<RollbackReceipt, ResponseError>;
}

/// Sandbox executor: records every inverse step without touching a real host.
///
/// Mirrors the sandbox response adapter's contract so a rollback can be
/// rehearsed on the same path that will later run it for real.
#[derive(Debug, Clone, Default)]
pub struct SandboxRollbackExecutor;

#[async_trait]
impl RollbackExecutor for SandboxRollbackExecutor {
    async fn rollback(
        &self,
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
    ) -> Result<RollbackReceipt, ResponseError> {
        if lease.rollback.steps.is_empty() {
            // A containment whose plan has no steps cannot be proven reversible,
            // so refuse rather than emit a receipt claiming it was undone.
            return Err(ResponseError::unavailable(
                lease.action.clone(),
                mode,
                format!(
                    "containment lease `{}` carries no rollback steps; refusing to claim reversal",
                    lease.lease_id
                ),
            ));
        }

        let status = match mode {
            ExecutionMode::DryRun => ResponseStatus::Simulated,
            ExecutionMode::Enforced => ResponseStatus::Executed,
        };

        let steps: Vec<RollbackStepOutcome> = lease
            .rollback
            .steps
            .iter()
            .map(|step| RollbackStepOutcome {
                kind: step.kind,
                status,
                detail: step.summary.clone(),
            })
            .collect();

        Ok(RollbackReceipt {
            rollback_id: format!("rollback:{}", lease.lease_id),
            lease_id: lease.lease_id.clone(),
            origin_receipt_id: lease.origin_receipt_id.clone(),
            trigger,
            mode,
            status,
            summary: format!(
                "reversed `{}` via {} inverse step(s) ({:?} trigger)",
                lease.action,
                steps.len(),
                trigger
            ),
            steps,
            completed_at_ms: lease.expires_at_ms,
        })
    }
}

/// In-memory ledger of open containments and the rollbacks that closed them.
///
/// The durable store lands with the runtime sweep; this type owns the
/// bookkeeping so expiry selection and double-rollback rejection are testable
/// without a filesystem.
#[derive(Debug, Default)]
pub struct ContainmentLedger {
    open: Vec<ContainmentLease>,
    closed: Vec<RollbackReceipt>,
}

impl ContainmentLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a containment that took effect. Rejects a lease that expires at or
    /// before it was issued, since that cannot bound anything.
    pub fn record(&mut self, lease: ContainmentLease) -> Result<(), ResponseError> {
        if lease.expires_at_ms <= lease.issued_at_ms {
            return Err(ResponseError::unavailable(
                lease.action.clone(),
                ExecutionMode::Enforced,
                format!(
                    "containment lease `{}` expires at or before issue; a containment must be bounded",
                    lease.lease_id
                ),
            ));
        }
        if self.open.iter().any(|open| open.lease_id == lease.lease_id) {
            return Err(ResponseError::unavailable(
                lease.action.clone(),
                ExecutionMode::Enforced,
                format!("containment lease `{}` is already open", lease.lease_id),
            ));
        }
        self.open.push(lease);
        Ok(())
    }

    pub fn open_leases(&self) -> &[ContainmentLease] {
        &self.open
    }

    pub fn closed_receipts(&self) -> &[RollbackReceipt] {
        &self.closed
    }

    pub fn get(&self, lease_id: &str) -> Option<&ContainmentLease> {
        self.open.iter().find(|lease| lease.lease_id == lease_id)
    }

    /// Leases whose expiry has passed at `now_ms`, in issue order.
    pub fn expired(&self, now_ms: i64) -> Vec<&ContainmentLease> {
        self.open
            .iter()
            .filter(|lease| lease.is_expired(now_ms))
            .collect()
    }

    /// Close a lease against its rollback receipt. A lease can only close once.
    pub fn close(&mut self, receipt: RollbackReceipt) -> Result<(), ResponseError> {
        let Some(index) = self
            .open
            .iter()
            .position(|lease| lease.lease_id == receipt.lease_id)
        else {
            return Err(ResponseError::unavailable(
                receipt.lease_id.clone(),
                receipt.mode,
                format!("no open containment lease `{}` to close", receipt.lease_id),
            ));
        };
        self.open.remove(index);
        self.closed.push(receipt);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::types::ResponseRollbackStep;

    fn plan(kinds: &[ResponseRollbackStepKind]) -> ResponseRollbackPreview {
        ResponseRollbackPreview {
            required: true,
            summary: "restore pre-containment state".to_string(),
            steps: kinds
                .iter()
                .map(|kind| ResponseRollbackStep {
                    kind: *kind,
                    summary: format!("{kind:?}"),
                })
                .collect(),
        }
    }

    fn lease(id: &str, expires_at_ms: i64) -> ContainmentLease {
        ContainmentLease {
            lease_id: id.to_string(),
            action: "quarantine_file".to_string(),
            origin_receipt_id: format!("resp:{id}"),
            rollback: plan(&[ResponseRollbackStepKind::ReleaseQuarantinedFile]),
            issued_at_ms: 1_000,
            expires_at_ms,
            governance_receipt_id: Some(format!("gov:{id}")),
        }
    }

    #[tokio::test]
    async fn rollback_receipt_chains_to_the_containment_receipt() {
        let lease = lease("lease-1", 61_000);
        let receipt = SandboxRollbackExecutor
            .rollback(&lease, RollbackTrigger::Manual, ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.origin_receipt_id, "resp:lease-1");
        assert_eq!(receipt.lease_id, "lease-1");
        assert!(receipt.fully_reversed());
        assert_eq!(receipt.trigger, RollbackTrigger::Manual);
    }

    #[tokio::test]
    async fn rollback_executes_every_step_of_the_inverse_plan() {
        let mut lease = lease("lease-2", 61_000);
        lease.rollback = plan(&[
            ResponseRollbackStepKind::RestoreHostConnectivity,
            ResponseRollbackStepKind::ReauthenticateUserSession,
            ResponseRollbackStepKind::ResumeProcess,
        ]);
        let receipt = SandboxRollbackExecutor
            .rollback(&lease, RollbackTrigger::Expiry, ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.steps.len(), 3);
        assert_eq!(
            receipt.steps[0].kind,
            ResponseRollbackStepKind::RestoreHostConnectivity
        );
        assert!(receipt.fully_reversed());
    }

    #[tokio::test]
    async fn rollback_refuses_a_plan_with_no_steps() {
        // A receipt claiming reversal for a plan that reverses nothing is exactly
        // the fabricated-assurance failure mode; refuse instead.
        let mut lease = lease("lease-3", 61_000);
        lease.rollback = plan(&[]);
        let error = SandboxRollbackExecutor
            .rollback(&lease, RollbackTrigger::Manual, ExecutionMode::Enforced)
            .await
            .unwrap_err();
        assert!(error.failure.message.contains("no rollback steps"));
    }

    #[test]
    fn a_containment_lease_must_be_bounded() {
        let mut ledger = ContainmentLedger::new();
        // expiry at issue time bounds nothing
        let unbounded = lease("lease-4", 1_000);
        assert!(ledger.record(unbounded).is_err());
        assert!(ledger.open_leases().is_empty());
    }

    #[test]
    fn expiry_selects_only_leases_past_their_deadline() {
        let mut ledger = ContainmentLedger::new();
        ledger.record(lease("early", 5_000)).unwrap();
        ledger.record(lease("late", 90_000)).unwrap();

        let due = ledger.expired(60_000);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].lease_id, "early");
    }

    #[test]
    fn remaining_ms_saturates_rather_than_going_negative() {
        let lease = lease("lease-5", 5_000);
        assert_eq!(lease.remaining_ms(1_000), 4_000);
        assert_eq!(lease.remaining_ms(9_999), 0);
        assert!(lease.is_expired(5_000));
    }

    #[tokio::test]
    async fn a_lease_closes_exactly_once() {
        let mut ledger = ContainmentLedger::new();
        ledger.record(lease("lease-6", 61_000)).unwrap();
        let receipt = SandboxRollbackExecutor
            .rollback(
                ledger.get("lease-6").unwrap(),
                RollbackTrigger::Expiry,
                ExecutionMode::Enforced,
            )
            .await
            .unwrap();

        ledger.close(receipt.clone()).unwrap();
        assert!(ledger.open_leases().is_empty());
        assert_eq!(ledger.closed_receipts().len(), 1);
        // second close has no open lease to act on
        assert!(ledger.close(receipt).is_err());
    }

    #[tokio::test]
    async fn dry_run_marks_steps_simulated_not_executed() {
        let lease = lease("lease-7", 61_000);
        let receipt = SandboxRollbackExecutor
            .rollback(&lease, RollbackTrigger::Manual, ExecutionMode::DryRun)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Simulated);
        assert!(
            receipt
                .steps
                .iter()
                .all(|step| step.status == ResponseStatus::Simulated)
        );
    }
}
