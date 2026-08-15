//! Reversible containment: inverse execution and chained rollback receipts.
//!
//! Containment actions (`QuarantineFile`, `IsolateHost`, `SuspendProcess`,
//! `TerminateUserSession`) dispatch through the adapters in this crate and take
//! real effect on real hosts. Until this module existed the runtime could
//! derive an inverse plan (`build_rehearsal_preview` in `swarm-runtime`) and
//! render it for an operator, but nothing could execute one: the system could
//! contain a host and could not un-contain it.
//!
//! WHAT THE INVERSE IS DERIVED FROM. A `ResponseRollbackStep` carries a kind
//! and a prose `summary` and nothing else — no host, no path, no pid. So the
//! plan alone cannot be executed, and an executor that reads it can only echo
//! the summary back. The addressable half comes from the lease's TYPED
//! `ResponseAction`; [`resolve_inverse`] is the single place the two are joined
//! and is the only thing an executor is allowed to act on.
//!
//! WHAT IS NOT REVERSIBLE, AND WHY THAT IS RECORDED RATHER THAN PAPERED OVER.
//! `TerminateUserSession`'s own rollback preview is `required: false` and says
//! outright that the terminated session cannot be resumed; its
//! `ReauthenticateUserSession` step merely re-permits login, which is not the
//! same world as before the containment. A receipt claiming that action was
//! `fully_reversed` would be a false audit record, so the mapping refuses it and
//! the step is recorded as [`RollbackStepStatus::Irreversible`].
//!
//! Owns: inverse-plan resolution and execution, rollback receipts chained to the
//! receipt that authorized the containment.
//!
//! Does not own: deriving the inverse plan (that is `swarm-runtime`'s
//! `build_rehearsal_preview`), the lease record itself (that is
//! [`crate::containment`]), authorizing the original containment (that is
//! `swarm-policy` plus governance), or signing (that is `swarm-crypto`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use swarm_core::types::{ResponseAction, ResponseRollbackStepKind};

use crate::containment::ContainmentLease;
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

impl RollbackTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Expiry => "expiry",
        }
    }
}

/// The concrete, addressable operation that undoes one containment step.
///
/// Every variant names the target it acts on. That is the difference between
/// this and a `ResponseRollbackStep`: a step describes an intention in prose, an
/// inverse is something an adapter can dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ContainmentInverse {
    ReleaseQuarantinedFile {
        host_id: String,
        file_path: String,
    },
    ResumeProcess {
        host_id: String,
        process_name: String,
    },
    RestoreHostConnectivity {
        host_id: String,
    },
}

impl ContainmentInverse {
    /// Stable operation name, used as the adapter-facing action field.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ReleaseQuarantinedFile { .. } => "release_quarantined_file",
            Self::ResumeProcess { .. } => "resume_process",
            Self::RestoreHostConnectivity { .. } => "restore_host_connectivity",
        }
    }

    /// Host the inverse acts on.
    pub fn host_id(&self) -> &str {
        match self {
            Self::ReleaseQuarantinedFile { host_id, .. }
            | Self::ResumeProcess { host_id, .. }
            | Self::RestoreHostConnectivity { host_id } => host_id,
        }
    }

    /// Target within the host, for messages.
    pub fn target(&self) -> String {
        match self {
            Self::ReleaseQuarantinedFile { host_id, file_path } => format!("{host_id}:{file_path}"),
            Self::ResumeProcess {
                host_id,
                process_name,
            } => format!("{host_id}:{process_name}"),
            Self::RestoreHostConnectivity { host_id } => host_id.clone(),
        }
    }
}

/// Why a planned rollback step has no executable inverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InverseGap {
    /// The forward action's own rollback preview states the effect cannot be
    /// undone. No adapter, however capable, changes this.
    Irreversible { reason: &'static str },
    /// No inverse is defined for this (action, step kind) pair. A mapping gap,
    /// not a statement about the world.
    Unmapped,
}

impl InverseGap {
    fn detail(&self, action_kind: &str, step: ResponseRollbackStepKind) -> String {
        match self {
            Self::Irreversible { reason } => format!(
                "`{action_kind}` cannot be reversed: {reason} (planned step {step:?} does not \
                 restore the pre-containment state)"
            ),
            Self::Unmapped => format!(
                "no inverse operation is defined for step {step:?} of `{action_kind}`; the \
                 containment stays in effect"
            ),
        }
    }

    fn status(&self) -> RollbackStepStatus {
        match self {
            Self::Irreversible { .. } => RollbackStepStatus::Irreversible,
            Self::Unmapped => RollbackStepStatus::Unsupported,
        }
    }
}

/// The one place a planned step and the lease's typed action become an
/// executable operation.
///
/// Adding a containment action means adding an arm here; forgetting to falls
/// through to [`InverseGap::Unmapped`], which records the gap on the receipt
/// rather than silently reporting a reversal that never happened.
pub fn resolve_inverse(
    action: &ResponseAction,
    step: ResponseRollbackStepKind,
) -> Result<ContainmentInverse, InverseGap> {
    match (action, step) {
        (
            ResponseAction::QuarantineFile { host_id, file_path },
            ResponseRollbackStepKind::ReleaseQuarantinedFile,
        ) => Ok(ContainmentInverse::ReleaseQuarantinedFile {
            host_id: host_id.clone(),
            file_path: file_path.clone(),
        }),
        (
            ResponseAction::SuspendProcess {
                host_id,
                process_name,
            },
            ResponseRollbackStepKind::ResumeProcess,
        ) => Ok(ContainmentInverse::ResumeProcess {
            host_id: host_id.clone(),
            process_name: process_name.clone(),
        }),
        (
            ResponseAction::IsolateHost { host_id },
            ResponseRollbackStepKind::RestoreHostConnectivity,
        ) => Ok(ContainmentInverse::RestoreHostConnectivity {
            host_id: host_id.clone(),
        }),
        // `service/preview.rs` derives this step for `TerminateUserSession` with
        // `required: false` and the summary "the terminated session cannot be
        // resumed". Re-permitting login is not the inverse of ending a session,
        // so this arm exists to say so on the receipt.
        (
            ResponseAction::TerminateUserSession { .. },
            ResponseRollbackStepKind::ReauthenticateUserSession,
        ) => {
            // INVARIANT: RESPONSE-IRREVERSIBLE-INVERSE-REFUSED
            Err(InverseGap::Irreversible {
                reason: "a terminated session cannot be resumed; the principal can only establish a \
                         fresh session",
            })
        }
        // INVARIANT: RESPONSE-UNMAPPED-INVERSE-REFUSED
        _ => Err(InverseGap::Unmapped),
    }
}

/// Whether every step of a lease's plan has a real inverse.
///
/// A lease that answers `false` will expire into a receipt that is explicitly
/// not a reversal. Callers that want to refuse such containments up front can
/// ask before executing.
pub fn plan_is_reversible(lease: &ContainmentLease) -> bool {
    !lease.rollback().steps.is_empty()
        && lease
            .rollback()
            .steps
            .iter()
            .all(|step| resolve_inverse(lease.action(), step.kind).is_ok())
}

/// Terminal state of one inverse step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStepStatus {
    /// The inverse ran against the real target and succeeded.
    Reversed,
    /// The inverse was rehearsed; no real target was touched.
    Simulated,
    /// No inverse exists for this step. The world was not restored and no
    /// adapter can restore it.
    Irreversible,
    /// The configured adapter cannot execute this inverse.
    Unsupported,
    /// The inverse was attempted against a real target and failed.
    Failed,
}

impl RollbackStepStatus {
    /// Whether this step actually restored the pre-containment state.
    pub fn restored(self) -> bool {
        matches!(self, Self::Reversed)
    }
}

/// Outcome of one inverse step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackStepOutcome {
    pub kind: ResponseRollbackStepKind,
    pub status: RollbackStepStatus,
    pub detail: String,
}

/// Receipt proving what a rollback did, chained to the receipt that made the
/// containment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackReceipt {
    pub rollback_id: String,
    pub lease_id: String,
    /// Chain link back to the containment receipt this undoes.
    pub origin_receipt_id: String,
    /// Chain link back to the GOVERNANCE receipt that authorized the
    /// containment, carried from the lease.
    ///
    /// QRT-02's text is "a rollback receipt chained to the original governance
    /// receipt id", and `origin_receipt_id` is the RESPONSE receipt, not that
    /// one. Without this field the durable record left after `close()` -- which
    /// drops the lease -- names no governance decision at all, so the audit
    /// chain from "who authorized this containment" to "it was undone" is
    /// broken at the last link. `Option` because a lease minted outside a
    /// governed path carries none, and inventing an id would be worse.
    pub governance_receipt_id: Option<String>,
    pub trigger: RollbackTrigger,
    pub mode: ExecutionMode,
    pub status: ResponseStatus,
    pub steps: Vec<RollbackStepOutcome>,
    pub completed_at_ms: i64,
    pub summary: String,
    /// The governance attestation over this receipt, if one was produced.
    ///
    /// OPAQUE ON PURPOSE, AND THIS CRATE NEVER READS IT. The value is a
    /// serialized `swarm_consensus::ConsensusGovernanceReceipt`; naming that
    /// type here would put `swarm-consensus` on `swarm-response`'s manifest,
    /// and `swarm-response` is a declared dependency of the trusted-computing-
    /// base crate `swarm-spine` (`tools/check-workspace-layering.sh`). The
    /// meaning of this field, and the only code allowed to decide whether it is
    /// valid, live in `swarm_runtime::containment` --
    /// `verify_release_attestation`.
    ///
    /// `None` means the release was NOT attested: no governance authority was
    /// wired, or none could sign. It does not mean "attested and fine", and
    /// nothing may read it that way -- the verifier refuses an unattested
    /// receipt rather than passing it.
    ///
    /// EXCLUDED FROM ITS OWN SUBJECT. The attestation covers the canonical form
    /// of this receipt with this field cleared, which is what
    /// `skip_serializing_if` gives for free on the `None` the signer is handed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_attestation: Option<serde_json::Value>,
}

impl RollbackReceipt {
    /// Whether the pre-containment state was actually restored.
    ///
    /// DELIBERATELY STRICTER THAN "nothing errored". A simulated step did not
    /// restore anything, and an irreversible step never will; both make this
    /// false. The audit record has to be able to distinguish "we undid it" from
    /// "we went through the motions", because an operator reading
    /// `fully_reversed` acts on it.
    pub fn fully_reversed(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|step| step.status.restored())
    }

    /// Whether every step was rehearsed rather than executed. The dry-run
    /// counterpart of [`Self::fully_reversed`].
    pub fn fully_rehearsed(&self) -> bool {
        !self.steps.is_empty()
            && self
                .steps
                .iter()
                .all(|step| step.status == RollbackStepStatus::Simulated)
    }

    /// Steps that no adapter will ever be able to undo.
    pub fn irreversible_steps(&self) -> impl Iterator<Item = &RollbackStepOutcome> {
        self.steps
            .iter()
            .filter(|step| step.status == RollbackStepStatus::Irreversible)
    }

    fn derive_status(steps: &[RollbackStepOutcome], mode: ExecutionMode) -> ResponseStatus {
        if steps.is_empty() {
            return ResponseStatus::Failed;
        }
        if steps.iter().all(|step| step.status.restored()) {
            ResponseStatus::Executed
        } else if steps
            .iter()
            .all(|step| step.status == RollbackStepStatus::Simulated)
            && mode == ExecutionMode::DryRun
        {
            // `Simulated` is a success-ish status (`indicates_success()` is
            // true), and that is only honest when nothing was SUPPOSED to
            // happen. In Enforced mode an all-simulated rollback means the host
            // is still contained and the executor merely went through the
            // motions -- which is every expiry on a deployment whose adapter
            // resolves to `SandboxRollbackExecutor` (crowdstrike_rtr, webhook,
            // sandbox). Reporting that as success would put a false claim in the
            // durable record, so the mode gates the arm.
            ResponseStatus::Simulated
        } else {
            // Anything left is a containment still partly or wholly in effect.
            // `indicates_success()` is false for `Failed`, so every caller that
            // checks it treats an unreversed rollback as a failure.
            ResponseStatus::Failed
        }
    }

    /// Assemble a receipt from resolved step outcomes, deriving the overall
    /// status from them so no executor can disagree with its own steps.
    pub fn from_steps(
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
        completed_at_ms: i64,
        steps: Vec<RollbackStepOutcome>,
    ) -> Self {
        // INVARIANT: RESPONSE-EMPTY-ROLLBACK-NOT-SUCCESS
        // INVARIANT: RESPONSE-ENFORCED-SIMULATION-NOT-SUCCESS
        // INVARIANT: RESPONSE-PARTIAL-ROLLBACK-NOT-SUCCESS
        let status = Self::derive_status(&steps, mode);
        let reversed = steps.iter().filter(|step| step.status.restored()).count();
        Self {
            rollback_id: format!("rollback:{}:{}", lease.lease_id(), completed_at_ms),
            lease_id: lease.lease_id().to_string(),
            origin_receipt_id: lease.origin_receipt_id().to_string(),
            governance_receipt_id: lease.governance_receipt_id().map(str::to_string),
            trigger,
            mode,
            status,
            summary: format!(
                "{} trigger on `{}` ({}): {reversed}/{} step(s) restored",
                trigger.as_str(),
                lease.action_kind(),
                lease.blast_radius().scope_value,
                steps.len()
            ),
            steps,
            completed_at_ms,
            // Always `None` here. `from_steps` is what every executor builds a
            // receipt with, and an executor cannot attest: it holds no governor
            // key. The attestation is stamped once, by the single release path
            // in `swarm_runtime::containment`, after the executor returns.
            governance_attestation: None,
        }
    }
}

/// Executes the inverse plan recorded on a containment lease.
///
/// `completed_at_ms` is a PARAMETER. A manual release happens before expiry and
/// a swept release happens at or after it, so an executor that stamped the
/// lease's own `expires_at_ms` would misdate every manual rollback, and an
/// executor that read the clock could not be tested without sleeping.
#[async_trait]
pub trait RollbackExecutor: Send + Sync + std::fmt::Debug {
    async fn rollback(
        &self,
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
        completed_at_ms: i64,
    ) -> Result<RollbackReceipt, ResponseError>;
}

/// Refuse a plan with no steps. A containment whose plan has no steps cannot be
/// proven reversible, so no executor may emit a receipt about it.
fn require_steps(lease: &ContainmentLease, mode: ExecutionMode) -> Result<(), ResponseError> {
    if lease.rollback().steps.is_empty() {
        return Err(ResponseError::unavailable(
            lease.action_kind(),
            mode,
            format!(
                "containment lease `{}` carries no rollback steps; refusing to claim reversal",
                lease.lease_id()
            ),
        ));
    }
    Ok(())
}

/// Sandbox executor: resolves every inverse and records it without touching a
/// real host.
///
/// It never reports [`RollbackStepStatus::Reversed`], in any mode. The previous
/// implementation returned `Executed` for `ExecutionMode::Enforced` having
/// performed no side effect, which is a receipt asserting a host was restored by
/// code that cannot reach a host.
#[derive(Debug, Clone, Default)]
pub struct SandboxRollbackExecutor;

#[async_trait]
impl RollbackExecutor for SandboxRollbackExecutor {
    async fn rollback(
        &self,
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
        completed_at_ms: i64,
    ) -> Result<RollbackReceipt, ResponseError> {
        // INVARIANT: RESPONSE-ROLLBACK-REQUIRES-STEPS
        require_steps(lease, mode)?;

        let steps = lease
            .rollback()
            .steps
            .iter()
            .map(|step| match resolve_inverse(lease.action(), step.kind) {
                // INVARIANT: RESPONSE-SANDBOX-NEVER-REVERSES
                Ok(inverse) => RollbackStepOutcome {
                    kind: step.kind,
                    status: RollbackStepStatus::Simulated,
                    detail: format!(
                        "would issue `{}` against `{}` (sandbox executor performs no side effect)",
                        inverse.kind(),
                        inverse.target()
                    ),
                },
                Err(gap) => RollbackStepOutcome {
                    kind: step.kind,
                    status: gap.status(),
                    detail: gap.detail(lease.action_kind(), step.kind),
                },
            })
            .collect();

        Ok(RollbackReceipt::from_steps(
            lease,
            trigger,
            mode,
            completed_at_ms,
            steps,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::containment::{ContainmentLease, ContainmentTtl};
    use swarm_core::types::{
        ResponseBlastRadiusImpact, ResponseBlastRadiusPreview, ResponseRehearsalPreview,
        ResponseRehearsalScopeKind, ResponseRollbackPreview, ResponseRollbackStep,
    };

    pub(crate) fn preview_with(
        scope_value: &str,
        required: bool,
        kinds: &[ResponseRollbackStepKind],
    ) -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:test".to_string(),
            source_bundle_id: "bundle:test".to_string(),
            prepared_at_ms: 1_000,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::File,
                scope_value: scope_value.to_string(),
                impact: ResponseBlastRadiusImpact::FileQuarantined,
                max_affected_scopes: 1,
                affected_capabilities: vec!["file_access".to_string()],
                summary: "test blast radius".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required,
                summary: "test rollback".to_string(),
                steps: kinds
                    .iter()
                    .map(|kind| ResponseRollbackStep {
                        kind: *kind,
                        summary: format!("{kind:?}"),
                    })
                    .collect(),
            },
        }
    }

    pub(crate) fn lease_for(
        lease_id: &str,
        action: ResponseAction,
        required: bool,
        kinds: &[ResponseRollbackStepKind],
    ) -> ContainmentLease {
        let scope = format!("scope:{lease_id}");
        ContainmentLease::open(
            lease_id,
            action,
            format!("resp:{lease_id}"),
            // A governance receipt id, so the tests below prove the value
            // actually FLOWS lease -> receipt. Leaving this `None` would let a
            // `governance_receipt_id: None` hard-coded in `from_steps` pass
            // every assertion.
            Some(format!("gov:{lease_id}")),
            &preview_with(&scope, required, kinds),
            1_000,
            ContainmentTtl::from_config_ms(4_000).unwrap(),
        )
        .unwrap()
    }

    fn quarantine_lease(lease_id: &str) -> ContainmentLease {
        lease_for(
            lease_id,
            ResponseAction::QuarantineFile {
                host_id: "host-1".to_string(),
                file_path: "/tmp/a".to_string(),
            },
            true,
            &[ResponseRollbackStepKind::ReleaseQuarantinedFile],
        )
    }

    fn session_lease(lease_id: &str) -> ContainmentLease {
        lease_for(
            lease_id,
            ResponseAction::TerminateUserSession {
                host_id: "host-1".to_string(),
                session_id: "sess-9".to_string(),
            },
            false,
            &[ResponseRollbackStepKind::ReauthenticateUserSession],
        )
    }

    #[test]
    fn the_three_reversible_containments_resolve_to_addressable_inverses() {
        assert_eq!(
            resolve_inverse(
                &ResponseAction::QuarantineFile {
                    host_id: "host-1".to_string(),
                    file_path: "/tmp/a".to_string(),
                },
                ResponseRollbackStepKind::ReleaseQuarantinedFile,
            ),
            Ok(ContainmentInverse::ReleaseQuarantinedFile {
                host_id: "host-1".to_string(),
                file_path: "/tmp/a".to_string(),
            })
        );
        assert_eq!(
            resolve_inverse(
                &ResponseAction::SuspendProcess {
                    host_id: "host-1".to_string(),
                    process_name: "evil.exe".to_string(),
                },
                ResponseRollbackStepKind::ResumeProcess,
            ),
            Ok(ContainmentInverse::ResumeProcess {
                host_id: "host-1".to_string(),
                process_name: "evil.exe".to_string(),
            })
        );
        assert_eq!(
            resolve_inverse(
                &ResponseAction::IsolateHost {
                    host_id: "host-1".to_string(),
                },
                ResponseRollbackStepKind::RestoreHostConnectivity,
            ),
            Ok(ContainmentInverse::RestoreHostConnectivity {
                host_id: "host-1".to_string(),
            })
        );
    }

    #[test]
    fn terminate_user_session_resolves_to_irreversible_not_to_an_inverse() {
        let gap = resolve_inverse(
            &ResponseAction::TerminateUserSession {
                host_id: "host-1".to_string(),
                session_id: "sess-9".to_string(),
            },
            ResponseRollbackStepKind::ReauthenticateUserSession,
        )
        .expect_err("a terminated session has no inverse");
        assert!(
            matches!(gap, InverseGap::Irreversible { .. }),
            "unexpected gap: {gap:?}"
        );
    }

    #[test]
    fn a_step_kind_that_does_not_belong_to_the_action_is_unmapped() {
        assert_eq!(
            resolve_inverse(
                &ResponseAction::QuarantineFile {
                    host_id: "host-1".to_string(),
                    file_path: "/tmp/a".to_string(),
                },
                ResponseRollbackStepKind::RestoreHostConnectivity,
            ),
            Err(InverseGap::Unmapped)
        );
    }

    #[tokio::test]
    async fn sandbox_rollback_never_claims_a_real_reversal() {
        let lease = quarantine_lease("lease-1");
        let receipt = SandboxRollbackExecutor
            .rollback(
                &lease,
                RollbackTrigger::Expiry,
                ExecutionMode::Enforced,
                5_000,
            )
            .await
            .unwrap();
        assert_eq!(receipt.steps.len(), 1);
        assert_eq!(receipt.steps[0].status, RollbackStepStatus::Simulated);
        assert!(
            !receipt.fully_reversed(),
            "a sandbox executor touched no host; it must not report a reversal"
        );
        assert!(receipt.fully_rehearsed());
        // ENFORCED, and nothing was restored, so the overall status must not be
        // a success-ish one. `ResponseStatus::Simulated.indicates_success()` is
        // true, and this executor is what a `crowdstrike_rtr`, `webhook` or
        // `sandbox` deployment gets, so reporting `Simulated` here would mark
        // EVERY expiry on those deployments a success while the host stayed
        // contained. The mode is what separates "nothing was supposed to
        // happen" from "nothing happened".
        assert_eq!(receipt.status, ResponseStatus::Failed);
        assert!(!receipt.status.indicates_success());
        assert_eq!(receipt.origin_receipt_id, "resp:lease-1");
        assert_eq!(
            receipt.governance_receipt_id.as_deref(),
            Some("gov:lease-1"),
            "the rollback receipt must name the governance decision that \
             authorized the containment; after close() the lease is gone and \
             this is the only remaining link"
        );
        assert_eq!(receipt.completed_at_ms, 5_000);
        assert!(
            receipt.steps[0].detail.contains("host-1:/tmp/a"),
            "the detail must name the addressable target: {}",
            receipt.steps[0].detail
        );
    }

    /// The same executor and the same steps in DRY RUN, where `Simulated` is the
    /// honest answer: nothing was supposed to happen, and nothing did. This is
    /// the other half of the mode distinction -- without it, gating the
    /// `Simulated` arm on the mode could be "fixed" by deleting the arm.
    #[tokio::test]
    async fn a_dry_run_rollback_is_reported_as_simulated_not_failed() {
        let lease = quarantine_lease("lease-1");
        let receipt = SandboxRollbackExecutor
            .rollback(
                &lease,
                RollbackTrigger::Expiry,
                ExecutionMode::DryRun,
                5_000,
            )
            .await
            .unwrap();
        assert!(receipt.fully_rehearsed());
        assert!(!receipt.fully_reversed());
        assert_eq!(receipt.status, ResponseStatus::Simulated);
        assert!(receipt.status.indicates_success());
    }

    #[tokio::test]
    async fn an_irreversible_action_is_never_fully_reversed() {
        let lease = session_lease("lease-2");
        let receipt = SandboxRollbackExecutor
            .rollback(
                &lease,
                RollbackTrigger::Expiry,
                ExecutionMode::Enforced,
                5_000,
            )
            .await
            .unwrap();
        assert_eq!(receipt.steps[0].status, RollbackStepStatus::Irreversible);
        assert!(
            !receipt.fully_reversed(),
            "`terminate_user_session` cannot be reversed; its receipt must not say it was"
        );
        assert!(!receipt.fully_rehearsed());
        assert_eq!(receipt.status, ResponseStatus::Failed);
        assert!(!receipt.status.indicates_success());
        assert_eq!(receipt.irreversible_steps().count(), 1);
        assert!(
            receipt.steps[0]
                .detail
                .contains("cannot be reversed: a terminated session cannot be resumed"),
            "unexpected detail: {}",
            receipt.steps[0].detail
        );
    }

    #[test]
    fn plan_reversibility_separates_the_three_from_the_fourth() {
        assert!(plan_is_reversible(&quarantine_lease("lease-1")));
        assert!(!plan_is_reversible(&session_lease("lease-2")));
    }

    #[tokio::test]
    async fn a_plan_with_no_steps_is_refused_rather_than_claimed_reversed() {
        let lease = lease_for(
            "lease-3",
            ResponseAction::QuarantineFile {
                host_id: "host-1".to_string(),
                file_path: "/tmp/a".to_string(),
            },
            true,
            &[],
        );
        let error = SandboxRollbackExecutor
            .rollback(
                &lease,
                RollbackTrigger::Manual,
                ExecutionMode::Enforced,
                5_000,
            )
            .await
            .expect_err("an empty plan cannot prove a reversal");
        assert!(
            error.to_string().contains("carries no rollback steps"),
            "unexpected error: {error}"
        );
    }
}
