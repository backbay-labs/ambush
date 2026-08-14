//! Releasing a containment: on operator demand, and on lease expiry.
//!
//! ONE FUNCTION DOES BOTH. [`release_lease`] is the whole release path; the TTL
//! sweep calls it per expired lease and a manual release calls it once. Two code
//! paths for the same act is how a lane ends up with a manual release that
//! records a receipt and an automatic one that does not, and no reviewer can see
//! the difference from either side.
//!
//! THE CLOCK IS A PARAMETER, EVERYWHERE IN THIS MODULE. `sweep(now_ms)` and
//! `release_lease(.., now_ms)` take the instant they act at; only
//! [`ContainmentSweep::run_until_shutdown`] reads a clock, once per tick, at the
//! call site. This is the shape `prune_expired_contingency_leases(state,
//! now_ms)` already has in `swarm-agents`, and it is deliberate: this repo has
//! nine shipped defects where a verdict was decided by wall-clock, and
//! `dispatch_integration.rs`'s `thread::sleep(2000)` against a 1000ms TTL is
//! documented in 1c4d728 as the anti-pattern. A sweep whose expiry test could
//! only be exercised by sleeping would be untestable in exactly the same way.
//!
//! Owns: choosing which leases to release and when, and closing them against
//! their receipts.
//!
//! Does not own: executing the inverse (that is `swarm_response::rollback`), the
//! lease record (that is `swarm_response::containment`), or opening a lease
//! (that is `SwarmRuntime`, at the moment a containment executes).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use swarm_consensus::ConsensusGovernanceReceipt;
use swarm_crypto::{canonical_json_bytes, sha256_hex};
use swarm_policy::governance::GovernanceAuthority;
use swarm_response::containment::{
    ContainmentLease, ContainmentLeaseError, ContainmentLeaseStore, ContainmentStoreError,
    ContainmentTtl, FileContainmentLeaseStore, MemoryContainmentLeaseStore,
};
use swarm_response::rollback::{
    RollbackExecutor, RollbackReceipt, RollbackStepStatus, RollbackTrigger,
};
use swarm_response::{ExecutionMode, ResponseError};

/// The response actions that leave a target in a changed state until something
/// undoes it.
///
/// These are the four the roadmap names, and they are exactly the four for which
/// `build_rehearsal_preview` derives an inverse plan. Everything else either
/// changes nothing durable (`TriggerEdrScan`, `Escalate`) or is out of scope for
/// this lane. Adding a containment action means adding it here AND adding an arm
/// to `swarm_response::rollback::resolve_inverse`; adding it only here produces
/// a lease whose expiry closes with an `Unsupported` step rather than a silent
/// claim of reversal.
pub fn is_containment_action(action: &swarm_core::types::ResponseAction) -> bool {
    use swarm_core::types::ResponseAction;
    matches!(
        action,
        ResponseAction::QuarantineFile { .. }
            | ResponseAction::SuspendProcess { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::TerminateUserSession { .. }
    )
}

/// A lease store and TTL built from configuration.
///
/// Returned as a pair because [`SwarmRuntime::with_containment_store`] takes
/// both; see its doc for why neither is useful alone.
///
/// [`SwarmRuntime::with_containment_store`]: crate::SwarmRuntime::with_containment_store
pub type ContainmentBindingFromConfig = (Arc<dyn ContainmentLeaseStore>, ContainmentTtl);

/// Build the lease store and TTL a runtime should hold, from configuration.
///
/// A configured `lease_store_path` gets a file store; no path gets an in-memory
/// one. The in-memory case is NOT free: a restart forgets every open lease, so
/// nothing will ever sweep those containments and they hold until an operator
/// acts.
///
/// The shipped `rulesets/default.yaml` does NOT set a path and cannot -- it is
/// digest-signed and the key is not in the repo -- so a `live_response`
/// deployment has to set one in its own config. `docs/CONFIGURATION.md` says
/// that, and says what omitting it costs.
pub fn containment_binding_from_config(
    settings: &swarm_core::config::ContainmentSettings,
) -> Result<ContainmentBindingFromConfig, ContainmentLeaseError> {
    let ttl = ContainmentTtl::from_config_ms(settings.lease_ttl_ms)?;
    let store: Arc<dyn ContainmentLeaseStore> = match settings.lease_store_path.as_deref() {
        Some(path) if !path.trim().is_empty() => Arc::new(FileContainmentLeaseStore::open(path)),
        _ => Arc::new(MemoryContainmentLeaseStore::new()),
    };
    Ok((store, ttl))
}

/// Build the rollback executor that matches the configured response adapter.
///
/// The inverse has to go out through the same integration the forward action
/// did, so this mirrors `DispatchingExecutor::from_config` arm for arm.
///
/// TWO ARMS RETURN A SANDBOX EXECUTOR THAT CANNOT UNDO ANYTHING, AND SAY SO.
/// `webhook` is a notification transport with no inverse endpoint, and
/// `crowdstrike_rtr` handles only `IsolateHost`/`KillProcess`/`QuarantineFile`
/// on the way out (`crowdstrike_rtr.rs:453-481`), so it could not reverse
/// `SuspendProcess` or `TerminateUserSession` even with a mapping written. On
/// those deployments a lease still bounds the containment and still expires --
/// its rollback receipt just reports `Simulated`/`Irreversible` rather than
/// `Reversed`, which is the true statement. Wiring a real CrowdStrike inverse is
/// follow-up work, not something to fake here.
pub fn rollback_executor_from_config(
    adapter: &swarm_core::config::ResponseAdapterConfig,
) -> Result<Arc<dyn RollbackExecutor>, ResponseError> {
    use swarm_core::config::ResponseAdapterConfig;
    Ok(match adapter {
        ResponseAdapterConfig::HttpEdr { config } => Arc::new(
            swarm_response::http_edr::HttpEdrRollbackExecutor::new(config.clone())?,
        ),
        ResponseAdapterConfig::Sandbox
        | ResponseAdapterConfig::Webhook { .. }
        | ResponseAdapterConfig::CrowdStrikeRtr { .. } => {
            Arc::new(swarm_response::rollback::SandboxRollbackExecutor)
        }
    })
}

/// Why a rollback receipt's governance attestation could not be trusted.
///
/// Every variant is a REFUSAL, including [`Self::Unattested`]. A verifier that
/// answered "fine" for a receipt carrying no signature would be the eleventh
/// entry in `.planning/STATE.md`: a check reporting success over a region it
/// never inspected.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseAttestationError {
    #[error(
        "rollback receipt `{rollback_id}` carries no governance attestation; it proves nothing \
         about who authorized the release"
    )]
    Unattested { rollback_id: String },

    #[error(
        "rollback receipt `{rollback_id}` carries a malformed governance attestation: {source}"
    )]
    Malformed {
        rollback_id: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("rollback receipt `{rollback_id}` could not be canonicalized: {source}")]
    Canonicalization {
        rollback_id: String,
        #[source]
        source: swarm_crypto::CryptoError,
    },

    #[error(
        "governance attestation on rollback receipt `{rollback_id}` failed signature \
         verification: {source}"
    )]
    Signature {
        rollback_id: String,
        #[source]
        source: swarm_consensus::ConsensusError,
    },

    #[error(
        "governance attestation on rollback receipt `{rollback_id}` was signed over subject \
         `{attested}` but this receipt canonicalizes to `{derived}`; the signature does not cover \
         this body"
    )]
    SubjectMismatch {
        rollback_id: String,
        attested: String,
        derived: String,
    },
}

/// The exact body a governance attestation is taken over.
///
/// The receipt with its own attestation field cleared, because a signature
/// cannot cover itself. `governance_attestation` is
/// `skip_serializing_if = "Option::is_none"`, so the cleared field is absent
/// from the canonical bytes rather than present as `null` -- which is what lets
/// a verifier rebuild the identical subject from a receipt that has since been
/// stamped.
fn release_subject(receipt: &RollbackReceipt) -> RollbackReceipt {
    let mut subject = receipt.clone();
    subject.governance_attestation = None;
    subject
}

/// Digest of the canonical release subject: the value an attestation's
/// `proposal_id` must equal.
fn release_subject_id(receipt: &RollbackReceipt) -> Result<String, swarm_crypto::CryptoError> {
    Ok(sha256_hex(&canonical_json_bytes(&release_subject(
        receipt,
    ))?))
}

/// Verify that a rollback receipt carries a governance attestation, that the
/// signature is good, and that it was taken over THIS receipt.
///
/// BOTH CHECKS ARE LOAD BEARING AND NEITHER IMPLIES THE OTHER.
/// [`ConsensusGovernanceReceipt::verify`] re-canonicalizes the governance
/// payload and checks the detached ed25519 signature, so a mutated attestation
/// fails there. But that payload names a commit, not a rollback -- it would
/// verify just as happily attached to a DIFFERENT release, or to a rollback
/// receipt whose steps had been rewritten from `Failed` to `Reversed`. The
/// subject check is what binds the signature to this body: the attestation's
/// `proposal_id` is the digest of the canonical receipt-minus-attestation, so
/// mutating any field of the receipt moves the derived digest away from the
/// signed one.
pub fn verify_release_attestation(
    receipt: &RollbackReceipt,
) -> Result<ConsensusGovernanceReceipt, ReleaseAttestationError> {
    let rollback_id = receipt.rollback_id.clone();
    let Some(raw) = receipt.governance_attestation.as_ref() else {
        return Err(ReleaseAttestationError::Unattested { rollback_id });
    };
    let attestation: ConsensusGovernanceReceipt =
        serde_json::from_value(raw.clone()).map_err(|source| {
            ReleaseAttestationError::Malformed {
                rollback_id: rollback_id.clone(),
                source,
            }
        })?;
    attestation
        .verify()
        .map_err(|source| ReleaseAttestationError::Signature {
            rollback_id: rollback_id.clone(),
            source,
        })?;
    let derived = release_subject_id(receipt).map_err(|source| {
        ReleaseAttestationError::Canonicalization {
            rollback_id: rollback_id.clone(),
            source,
        }
    })?;
    if attestation.payload.proposal_id != derived {
        return Err(ReleaseAttestationError::SubjectMismatch {
            rollback_id,
            attested: attestation.payload.proposal_id.clone(),
            derived,
        });
    }
    Ok(attestation)
}

/// Stamp a governance attestation onto a rollback receipt, in place.
///
/// Failure to attest is LOGGED AND TOLERATED, never fatal. A lease that has
/// expired must be released whether or not a governor is available to co-sign
/// the fact; refusing would leave a host contained because the audit trail was
/// unavailable, which inverts the safety argument. What is not tolerated is
/// pretending: the receipt goes to the store with `governance_attestation:
/// None` and [`verify_release_attestation`] refuses it.
fn attest_release_receipt(
    governance: Option<&dyn GovernanceAuthority>,
    receipt: &mut RollbackReceipt,
    now_ms: i64,
) {
    let Some(governance) = governance else {
        return;
    };
    let subject = match serde_json::to_value(release_subject(receipt)) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(
                module = module_path!(),
                rollback_id = %receipt.rollback_id,
                reason = %error,
                "containment release could not be serialized for attestation; recorded unattested"
            );
            return;
        }
    };
    match governance.attest_release(&subject, now_ms) {
        Some(attestation) => receipt.governance_attestation = Some(attestation),
        None => tracing::warn!(
            module = module_path!(),
            rollback_id = %receipt.rollback_id,
            lease_id = %receipt.lease_id,
            "governance declined to attest this containment release; recorded unattested"
        ),
    }
}

/// Errors raised while releasing a containment.
#[derive(Debug, thiserror::Error)]
pub enum ContainmentReleaseError {
    #[error("no open containment lease `{lease_id}`")]
    UnknownLease { lease_id: String },

    #[error(transparent)]
    Store(#[from] ContainmentStoreError),

    #[error("rollback of containment lease `{lease_id}` failed: {source}")]
    Rollback {
        lease_id: String,
        #[source]
        source: ResponseError,
    },
}

/// Release one containment: execute its inverse, then close the lease against
/// the receipt that records what the inverse actually did.
///
/// ORDER MATTERS AND IS NOT AN ACCIDENT. The lease closes only after the
/// executor returns, and only if the inverse actually reached a decision: a
/// lease closed against a rollback that never ran would erase the only record
/// that the host is still contained.
///
/// "Could not be issued" IS NOT THE SAME AS `Err`, and reading it that way was
/// a real hole. `HttpEdrRollbackExecutor` returns `Err` only for an empty step
/// list; a transport failure comes back as `Ok` with a `Failed` step. Measured
/// against a dead port, the lease closed anyway:
///
/// ```text
/// receipt.status = Failed
/// steps = [.. status: Failed, detail: "`restore_host_connectivity` for
///          `host-1` could not be issued: error sending request for url
///          (http://127.0.0.1:9/); the containment stays in effect" ]
/// open_leases after = 0     closed_receipts after = 1
/// ```
///
/// So a brief EDR blip at sweep time ended the lease permanently and abandoned
/// a contained host after one attempt, while the step detail said "the
/// containment stays in effect". The decision is therefore made on the STEPS: a
/// `Failed` step means the attempt did not land and the lease stays open for
/// the next sweep to retry.
///
/// A receipt that comes back reporting the containment was NOT restored for a
/// reason retrying cannot change -- `Irreversible`, or `Unsupported` by this
/// adapter -- DOES close the lease, as do `Reversed` and `Simulated`. The
/// expiry has passed and another attempt cannot change the answer; the receipt
/// says plainly what happened and `fully_reversed()` is false on it.
pub async fn release_lease(
    store: &dyn ContainmentLeaseStore,
    executor: &dyn RollbackExecutor,
    mode: ExecutionMode,
    lease_id: &str,
    trigger: RollbackTrigger,
    now_ms: i64,
    governance: Option<&dyn GovernanceAuthority>,
) -> Result<RollbackReceipt, ContainmentReleaseError> {
    let Some(lease) = store.get(lease_id)? else {
        return Err(ContainmentReleaseError::UnknownLease {
            lease_id: lease_id.to_string(),
        });
    };

    let mut receipt = executor
        .rollback(&lease, trigger, mode, now_ms)
        .await
        .map_err(|source| ContainmentReleaseError::Rollback {
            lease_id: lease_id.to_string(),
            source,
        })?;

    // A `Failed` step means the inverse was attempted and did not land, so the
    // host is still contained and the lease is the only record of it. Keep it
    // open and let the next sweep retry rather than closing over a host nobody
    // is tracking any more.
    let attempt_failed = receipt
        .steps
        .iter()
        .any(|step| step.status == RollbackStepStatus::Failed);
    if attempt_failed {
        tracing::warn!(
            module = module_path!(),
            lease_id = %receipt.lease_id,
            rollback_id = %receipt.rollback_id,
            trigger = receipt.trigger.as_str(),
            "containment release did not land; lease stays open for the next sweep"
        );
        return Ok(receipt);
    }

    // ATTEST FIRST, THEN CLOSE, AND ONLY ON THIS PATH.
    //
    // First, because the attestation is part of the receipt: `store.close`
    // takes the receipt by reference and persists a clone, so stamping after
    // the close would leave the durable copy unattested while the copy returned
    // to the caller carried a signature. Two records of one release disagreeing
    // about whether it was attested is exactly the audit hazard this lane
    // exists to remove.
    //
    // Only on this path, because the early return above is a release that did
    // NOT happen -- the inverse failed, the lease stays open, and the next
    // sweep retries. Attesting it would put a governance-signed record of a
    // release into the chain for a host that is still contained, and would burn
    // one chain link per retry against a flapping EDR.
    attest_release_receipt(governance, &mut receipt, now_ms);

    store.close(&receipt)?;

    if receipt.fully_reversed() {
        tracing::info!(
            module = module_path!(),
            lease_id = %receipt.lease_id,
            rollback_id = %receipt.rollback_id,
            origin_receipt_id = %receipt.origin_receipt_id,
            trigger = receipt.trigger.as_str(),
            "containment released"
        );
    } else {
        tracing::warn!(
            module = module_path!(),
            lease_id = %receipt.lease_id,
            rollback_id = %receipt.rollback_id,
            origin_receipt_id = %receipt.origin_receipt_id,
            trigger = receipt.trigger.as_str(),
            summary = %receipt.summary,
            "containment lease closed WITHOUT full restoration; the effect may still be in place"
        );
    }

    Ok(receipt)
}

/// What one sweep did.
#[derive(Debug, Default)]
pub struct ContainmentSweepReport {
    /// Leases found expired at the swept instant.
    pub expired: usize,
    /// Receipts produced, including receipts that report no restoration.
    pub receipts: Vec<RollbackReceipt>,
    /// Leases that could not be released, and why. These stay open.
    pub failures: Vec<(String, String)>,
}

impl ContainmentSweepReport {
    /// Leases whose pre-containment state was actually restored.
    pub fn restored(&self) -> usize {
        self.receipts
            .iter()
            .filter(|receipt| receipt.fully_reversed())
            .count()
    }
}

/// Releases containment leases whose expiry has passed, and the one object an
/// operator-driven early release goes through.
///
/// ONE INSTANCE PER PROCESS, SHARED. The TTL task and the operator HTTP handler
/// hold the same `Arc<ContainmentSweep>`, so they cannot be pointed at
/// different stores, different executors, different execution modes or
/// different governance authorities. That sharing is not decoration: with a
/// `MemoryContainmentLeaseStore` a second instance is a different map, and a
/// handler built beside the sweep would report "no open lease `x`" for every
/// lease the daemon actually holds.
#[derive(Clone)]
pub struct ContainmentSweep {
    store: Arc<dyn ContainmentLeaseStore>,
    executor: Arc<dyn RollbackExecutor>,
    mode: ExecutionMode,
    governance: Option<Arc<dyn GovernanceAuthority>>,
}

impl std::fmt::Debug for ContainmentSweep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentSweep")
            .field("store", &self.store)
            .field("executor", &self.executor)
            .field("mode", &self.mode)
            .field("governance", &self.governance.is_some())
            .finish()
    }
}

impl ContainmentSweep {
    pub fn new(
        store: Arc<dyn ContainmentLeaseStore>,
        executor: Arc<dyn RollbackExecutor>,
        mode: ExecutionMode,
    ) -> Self {
        Self {
            store,
            executor,
            mode,
            governance: None,
        }
    }

    /// Attach the governance authority that co-signs every release this sweep
    /// performs.
    ///
    /// It is attached to the SWEEP rather than passed per call, which is what
    /// makes "manual and automatic release cannot diverge" structural rather
    /// than a convention: [`Self::release`] and [`Self::sweep`] read the same
    /// field, so there is no call site at which one could be attested and the
    /// other not.
    pub fn with_governance(mut self, governance: Arc<dyn GovernanceAuthority>) -> Self {
        self.governance = Some(governance);
        self
    }

    /// Every lease currently open, for the operator listing.
    pub fn open_leases(&self) -> Result<Vec<ContainmentLease>, ContainmentStoreError> {
        self.store.open_leases()
    }

    fn governance(&self) -> Option<&dyn GovernanceAuthority> {
        self.governance.as_deref()
    }

    /// Release one named lease early. Same function the sweep uses.
    pub async fn release(
        &self,
        lease_id: &str,
        now_ms: i64,
    ) -> Result<RollbackReceipt, ContainmentReleaseError> {
        release_lease(
            self.store.as_ref(),
            self.executor.as_ref(),
            self.mode,
            lease_id,
            RollbackTrigger::Manual,
            now_ms,
            self.governance(),
        )
        .await
    }

    /// Release every lease expired at `now_ms`.
    ///
    /// One lease failing does not abort the pass and does not close that lease.
    /// A sweep that stopped at the first failure would leave later leases
    /// contained indefinitely because of an unrelated host being unreachable.
    pub async fn sweep(&self, now_ms: i64) -> ContainmentSweepReport {
        let expired = match self.store.expired(now_ms) {
            Ok(expired) => expired,
            Err(error) => {
                return ContainmentSweepReport {
                    expired: 0,
                    receipts: Vec::new(),
                    failures: vec![("<store>".to_string(), error.to_string())],
                };
            }
        };

        let mut report = ContainmentSweepReport {
            expired: expired.len(),
            ..Default::default()
        };

        for lease in expired {
            match release_lease(
                self.store.as_ref(),
                self.executor.as_ref(),
                self.mode,
                lease.lease_id(),
                RollbackTrigger::Expiry,
                now_ms,
                self.governance(),
            )
            .await
            {
                Ok(receipt) => report.receipts.push(receipt),
                Err(error) => {
                    tracing::warn!(
                        module = module_path!(),
                        lease_id = %lease.lease_id(),
                        reason = %error,
                        "expired containment lease could not be released; it stays open"
                    );
                    report
                        .failures
                        .push((lease.lease_id().to_string(), error.to_string()));
                }
            }
        }

        report
    }

    /// Sweep on an interval until shutdown.
    ///
    /// The ONLY clock read in this module, and it is read here rather than
    /// inside `sweep` so the verdict "this lease was expired" stays a pure
    /// function of a supplied instant. Structure copied from
    /// `ConcentrationMonitor::run_until_shutdown`.
    pub async fn run_until_shutdown(&self, interval_ms: u64, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms.max(1)));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if *shutdown.borrow() {
                        break;
                    }
                    let report = self.sweep(crate::runtime_events::now_ms()).await;
                    if report.expired > 0 {
                        tracing::info!(
                            module = module_path!(),
                            expired = report.expired,
                            restored = report.restored(),
                            failures = report.failures.len(),
                            "containment sweep completed"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use swarm_core::types::{
        ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
        ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
        ResponseRollbackStep, ResponseRollbackStepKind,
    };
    use swarm_response::containment::{
        ContainmentLease, ContainmentTtl, MemoryContainmentLeaseStore,
    };
    use swarm_response::rollback::{RollbackStepOutcome, RollbackStepStatus};
    use swarm_response::{ResponseStatus, SandboxRollbackExecutor};

    fn preview() -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:test".to_string(),
            source_bundle_id: "bundle:test".to_string(),
            prepared_at_ms: 1_000,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::Host,
                scope_value: "host-1".to_string(),
                impact: ResponseBlastRadiusImpact::HostConnectivityIsolated,
                max_affected_scopes: 1,
                affected_capabilities: vec!["network_connectivity".to_string()],
                summary: "isolates one host".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: "restore connectivity".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::RestoreHostConnectivity,
                    summary: "restore host-1".to_string(),
                }],
            },
        }
    }

    fn lease(lease_id: &str, issued_at_ms: i64, ttl_ms: i64) -> ContainmentLease {
        ContainmentLease::open(
            lease_id,
            ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            format!("resp:{lease_id}"),
            None,
            &preview(),
            issued_at_ms,
            ContainmentTtl::from_config_ms(ttl_ms).unwrap(),
        )
        .unwrap()
    }

    /// Records what it was asked to reverse and reports a real restoration, so a
    /// test can tell "the sweep called the executor" from "the sweep closed the
    /// lease anyway".
    #[derive(Debug, Default)]
    struct RecordingExecutor {
        calls: AtomicUsize,
        seen: Mutex<Vec<(String, RollbackTrigger, i64)>>,
        /// Return `Err`. Measured against the real executors, this shape occurs
        /// only for an EMPTY step list -- never for a transport failure.
        fail: bool,
        /// Return `Ok` carrying a `Failed` step. THIS is what
        /// `HttpEdrRollbackExecutor` actually produces when the endpoint is
        /// unreachable, which is why it needs its own case: a test that only
        /// drives `fail` checks a shape production never emits.
        fail_step: bool,
    }

    #[async_trait::async_trait]
    impl RollbackExecutor for RecordingExecutor {
        async fn rollback(
            &self,
            lease: &ContainmentLease,
            trigger: RollbackTrigger,
            mode: ExecutionMode,
            completed_at_ms: i64,
        ) -> Result<RollbackReceipt, ResponseError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push((
                lease.lease_id().to_string(),
                trigger,
                completed_at_ms,
            ));
            if self.fail {
                return Err(ResponseError::unavailable(
                    lease.action_kind(),
                    mode,
                    "edr unreachable",
                ));
            }
            let status = if self.fail_step {
                RollbackStepStatus::Failed
            } else {
                RollbackStepStatus::Reversed
            };
            let detail = if self.fail_step {
                "`restore_host_connectivity` for `host-1` could not be issued: error sending \
                 request; the containment stays in effect"
                    .to_string()
            } else {
                "restored".to_string()
            };
            Ok(RollbackReceipt::from_steps(
                lease,
                trigger,
                mode,
                completed_at_ms,
                vec![RollbackStepOutcome {
                    kind: ResponseRollbackStepKind::RestoreHostConnectivity,
                    status,
                    detail,
                }],
            ))
        }
    }

    fn sweep_with(
        executor: Arc<RecordingExecutor>,
    ) -> (Arc<MemoryContainmentLeaseStore>, ContainmentSweep) {
        let store = Arc::new(MemoryContainmentLeaseStore::new());
        let sweep = ContainmentSweep::new(store.clone(), executor, ExecutionMode::Enforced);
        (store, sweep)
    }

    #[test]
    fn a_configured_path_gets_a_durable_store_and_no_path_gets_an_in_memory_one() {
        use swarm_core::config::ContainmentSettings;

        let (memory, ttl) =
            containment_binding_from_config(&ContainmentSettings::default()).unwrap();
        assert_eq!(ttl.get(), 900_000);
        assert_eq!(
            format!("{memory:?}"),
            format!("{:?}", MemoryContainmentLeaseStore::new()),
            "no configured path must not silently produce a file store"
        );

        let path = std::env::temp_dir().join("swarm-containment-binding.json");
        let (file, ttl) = containment_binding_from_config(&ContainmentSettings {
            lease_ttl_ms: 1_234,
            sweep_interval_ms: 10,
            lease_store_path: Some(path.display().to_string()),
        })
        .unwrap();
        assert_eq!(ttl.get(), 1_234);
        assert!(
            format!("{file:?}").contains("FileContainmentLeaseStore"),
            "a configured path must produce a durable store, got {file:?}"
        );

        // The TTL is the bound; a non-positive one must not build a runtime.
        let error = containment_binding_from_config(&ContainmentSettings {
            lease_ttl_ms: 0,
            ..ContainmentSettings::default()
        })
        .expect_err("a zero ttl cannot bound a containment");
        assert!(
            matches!(error, ContainmentLeaseError::NonPositiveTtl { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn only_the_http_edr_deployment_gets_an_executor_that_can_touch_a_host() {
        use swarm_core::config::{
            CircuitBreakerConfig, CrowdStrikeRtrConfig, HttpEdrConfig, ResponseAdapterConfig,
            RetryConfig, WebhookConfig,
        };

        let http = rollback_executor_from_config(&ResponseAdapterConfig::HttpEdr {
            config: HttpEdrConfig {
                endpoint: "http://127.0.0.1:9/".to_string(),
                auth_token: "secret".to_string().into(),
                timeout_ms: 50,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        })
        .unwrap();
        assert!(format!("{http:?}").contains("HttpEdrRollbackExecutor"));

        // The other three fall back to the sandbox executor, which never reports
        // `Reversed`. That is the honest answer for a webhook (no inverse
        // endpoint) and for CrowdStrike RTR (its forward adapter covers only
        // three of the actions), not a gap being papered over.
        for adapter in [
            ResponseAdapterConfig::Sandbox,
            ResponseAdapterConfig::Webhook {
                config: WebhookConfig {
                    url: "http://127.0.0.1:9/".to_string(),
                    timeout_ms: 50,
                    channel: None,
                    auth_token: None,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
            ResponseAdapterConfig::CrowdStrikeRtr {
                config: CrowdStrikeRtrConfig {
                    base_url: "http://127.0.0.1:9/".to_string(),
                    client_id: "id".to_string().into(),
                    client_secret: "secret".to_string().into(),
                    timeout_ms: 50,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
        ] {
            let executor = rollback_executor_from_config(&adapter).unwrap();
            assert!(
                format!("{executor:?}").contains("SandboxRollbackExecutor"),
                "unexpected executor for {adapter:?}: {executor:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_sweep_before_expiry_releases_nothing_and_one_at_expiry_releases() {
        let executor = Arc::new(RecordingExecutor::default());
        let (store, sweep) = sweep_with(executor.clone());
        store.open_lease(&lease("lease-1", 1_000, 4_000)).unwrap();

        // Both instants are literals. No sleeping, no wall clock: the verdict
        // is a pure function of the supplied `now_ms`.
        let before = sweep.sweep(4_999).await;
        assert_eq!(before.expired, 0);
        assert!(before.receipts.is_empty());
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.open_leases().unwrap().len(), 1);

        let at = sweep.sweep(5_000).await;
        assert_eq!(at.expired, 1);
        assert_eq!(at.receipts.len(), 1);
        assert_eq!(at.restored(), 1);
        assert_eq!(at.receipts[0].trigger, RollbackTrigger::Expiry);
        assert_eq!(at.receipts[0].completed_at_ms, 5_000);
        assert_eq!(at.receipts[0].origin_receipt_id, "resp:lease-1");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
        assert!(store.open_leases().unwrap().is_empty());
        assert_eq!(store.closed_receipts().unwrap().len(), 1);
    }

    /// The case the `Err`-returning test above does NOT cover, and the one that
    /// actually happens in production.
    ///
    /// `HttpEdrRollbackExecutor` returns `Err` only for an empty step list. A
    /// transport failure -- an EDR blip at sweep time, the most likely real
    /// failure -- comes back as `Ok` with a `Failed` step. Measured through
    /// `release_lease` against a dead port before this was fixed:
    ///
    /// ```text
    /// receipt.status = Failed
    /// steps = [.. status: Failed, detail: ".. could not be issued: error
    ///          sending request for url (http://127.0.0.1:9/); the containment
    ///          stays in effect" ]
    /// open_leases after = 0     closed_receipts after = 1
    /// ```
    ///
    /// So one blip ended the lease permanently and abandoned a contained host
    /// after a single attempt, while the step detail said the containment was
    /// still in effect. The lease must survive for the next sweep to retry.
    #[tokio::test]
    async fn a_lease_whose_inverse_was_attempted_and_failed_stays_open_for_retry() {
        let executor = Arc::new(RecordingExecutor {
            fail_step: true,
            ..Default::default()
        });
        let (store, sweep) = sweep_with(executor.clone());
        store.open_lease(&lease("lease-1", 1_000, 4_000)).unwrap();

        let report = sweep.sweep(5_000).await;
        assert_eq!(report.expired, 1);
        assert_eq!(
            report.receipts.len(),
            1,
            "the executor did return a receipt"
        );
        assert!(!report.receipts[0].fully_reversed());
        assert_eq!(
            store.open_leases().unwrap().len(),
            1,
            "an attempt that did not land leaves the host contained, so the lease is still the \
             only record of it and must survive for the next sweep"
        );
        assert!(
            store.closed_receipts().unwrap().is_empty(),
            "closing here abandons a contained host after one attempt"
        );

        // And the retry actually happens: the same lease is swept again.
        let retry = sweep.sweep(6_000).await;
        assert_eq!(retry.expired, 1, "the surviving lease is retried");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_lease_whose_inverse_could_not_be_issued_stays_open() {
        let executor = Arc::new(RecordingExecutor {
            fail: true,
            ..Default::default()
        });
        let (store, sweep) = sweep_with(executor.clone());
        store.open_lease(&lease("lease-1", 1_000, 4_000)).unwrap();

        let report = sweep.sweep(5_000).await;
        assert_eq!(report.expired, 1);
        assert!(report.receipts.is_empty());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].0, "lease-1");
        assert!(
            report.failures[0].1.contains("edr unreachable"),
            "unexpected failure: {}",
            report.failures[0].1
        );
        assert_eq!(
            store.open_leases().unwrap().len(),
            1,
            "a lease closed against a rollback that never ran erases the only record that the \
             host is still contained"
        );
        assert!(store.closed_receipts().unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_unreachable_lease_does_not_strand_the_others() {
        // Fails the first call, succeeds afterwards, so the pass must continue
        // past the failure to release the second lease.
        #[derive(Debug, Default)]
        struct FailFirst {
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl RollbackExecutor for FailFirst {
            async fn rollback(
                &self,
                lease: &ContainmentLease,
                trigger: RollbackTrigger,
                mode: ExecutionMode,
                completed_at_ms: i64,
            ) -> Result<RollbackReceipt, ResponseError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(ResponseError::unavailable(
                        lease.action_kind(),
                        mode,
                        "edr unreachable",
                    ));
                }
                Ok(RollbackReceipt::from_steps(
                    lease,
                    trigger,
                    mode,
                    completed_at_ms,
                    vec![RollbackStepOutcome {
                        kind: ResponseRollbackStepKind::RestoreHostConnectivity,
                        status: RollbackStepStatus::Reversed,
                        detail: "restored".to_string(),
                    }],
                ))
            }
        }

        let store = Arc::new(MemoryContainmentLeaseStore::new());
        let sweep = ContainmentSweep::new(
            store.clone(),
            Arc::new(FailFirst::default()),
            ExecutionMode::Enforced,
        );
        store.open_lease(&lease("lease-a", 1_000, 1_000)).unwrap();
        store.open_lease(&lease("lease-b", 2_000, 1_000)).unwrap();

        let report = sweep.sweep(9_000).await;
        assert_eq!(report.expired, 2);
        assert_eq!(report.receipts.len(), 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].0, "lease-a");
        assert_eq!(report.receipts[0].lease_id, "lease-b");
    }

    #[tokio::test]
    async fn a_manual_release_and_an_expiry_sweep_run_the_same_function() {
        let executor = Arc::new(RecordingExecutor::default());
        let (store, sweep) = sweep_with(executor.clone());
        store
            .open_lease(&lease("lease-manual", 1_000, 9_000))
            .unwrap();
        store
            .open_lease(&lease("lease-expiry", 1_000, 1_000))
            .unwrap();

        let manual = sweep.release("lease-manual", 3_000).await.unwrap();
        let swept = sweep.sweep(3_000).await;

        assert_eq!(manual.trigger, RollbackTrigger::Manual);
        assert_eq!(manual.completed_at_ms, 3_000);
        assert_eq!(swept.receipts.len(), 1);
        assert_eq!(swept.receipts[0].trigger, RollbackTrigger::Expiry);

        // Both went through the executor, in the order the two triggers fired,
        // stamped with the instant each was told to act at. A manual path that
        // closed the lease without executing would show one call here.
        let seen = executor.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                ("lease-manual".to_string(), RollbackTrigger::Manual, 3_000),
                ("lease-expiry".to_string(), RollbackTrigger::Expiry, 3_000),
            ]
        );
        assert!(store.open_leases().unwrap().is_empty());
        assert_eq!(store.closed_receipts().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn releasing_an_unknown_lease_is_an_error_not_a_silent_success() {
        let executor = Arc::new(RecordingExecutor::default());
        let (_store, sweep) = sweep_with(executor.clone());
        let error = sweep.release("nope", 1_000).await.unwrap_err();
        assert!(
            matches!(error, ContainmentReleaseError::UnknownLease { .. }),
            "unexpected error: {error}"
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_irreversible_lease_closes_but_its_receipt_reports_no_restoration() {
        let store = Arc::new(MemoryContainmentLeaseStore::new());
        let sweep = ContainmentSweep::new(
            store.clone(),
            Arc::new(SandboxRollbackExecutor),
            ExecutionMode::Enforced,
        );
        let mut irreversible = preview();
        irreversible.rollback.required = false;
        irreversible.rollback.steps = vec![ResponseRollbackStep {
            kind: ResponseRollbackStepKind::ReauthenticateUserSession,
            summary: "allow the principal to authenticate again".to_string(),
        }];
        store
            .open_lease(
                &ContainmentLease::open(
                    "lease-session",
                    ResponseAction::TerminateUserSession {
                        host_id: "host-1".to_string(),
                        session_id: "sess-1".to_string(),
                    },
                    "resp:lease-session",
                    None,
                    &irreversible,
                    1_000,
                    ContainmentTtl::from_config_ms(1_000).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();

        let report = sweep.sweep(5_000).await;
        assert_eq!(report.expired, 1);
        assert_eq!(report.receipts.len(), 1);
        assert_eq!(
            report.restored(),
            0,
            "the sweep must not count an irreversible action as restored"
        );
        assert_eq!(report.receipts[0].status, ResponseStatus::Failed);
        assert!(!report.receipts[0].fully_reversed());
        assert!(store.open_leases().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_background_loop_releases_an_expired_lease_with_no_operator_action() {
        let executor = Arc::new(RecordingExecutor::default());
        let (store, sweep) = sweep_with(executor.clone());
        // Already expired against any plausible wall clock: `now_ms()` is
        // milliseconds since the epoch, and this lease lapsed in 1970.
        store.open_lease(&lease("lease-1", 1_000, 1_000)).unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let loop_sweep = sweep.clone();
        let handle = tokio::spawn(async move {
            loop_sweep.run_until_shutdown(5, shutdown_rx).await;
        });

        // DELIBERATE: no assertion is made on elapsed time. The 10s is a hang
        // detector, not a verdict on speed -- "the loop closed it without an
        // operator" is monotone in time and cannot flip on a slow runner.
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if store.open_leases().unwrap().is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "the background sweep never released the expired lease"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

        let receipts = store.closed_receipts().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].trigger, RollbackTrigger::Expiry);
        assert!(executor.calls.load(Ordering::SeqCst) >= 1);
    }
}
