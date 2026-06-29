//! The fail-closed single-hop admission verifier.

use std::collections::BTreeSet;

use swarm_crypto::PublicKey;

use crate::epoch::{SwarmRevocationEpoch, verify_epoch};
use crate::error::{AuthorityError, DenyReason};
use crate::token::{BudgetLease, CONTINUATION_TOKEN_SCHEMA, ContinuationMode, SwarmContinuationToken, verify_token_signature};

/// Caller-owned single-use ledger (the verifier-owned "consumed" set).
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    seen: BTreeSet<String>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn contains(&self, nonce: &str) -> bool {
        self.seen.contains(nonce)
    }
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
    fn record(&mut self, nonce: &str) -> bool {
        self.seen.insert(nonce.to_string())
    }
}

/// Operational bindings the caller asserts at admission time.
#[derive(Clone, Debug, Default)]
pub struct AdmissionContext {
    pub now_unix_ms: u64,
    pub expected_operation_id: Option<String>,
    pub expected_vector_id: Option<String>,
    pub expected_vector_scope_hash: Option<String>,
}

/// What a successful admission grants the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub token_id: String,
    pub operation_id: String,
    pub vector_id: String,
    pub vector_scope_hash: String,
    pub budget_lease: BudgetLease,
    pub epoch_number: u64,
    pub consumed: bool,
}

/// Fail-closed single-hop admission. Trust comes ONLY from `trusted_keys`; the token/epoch carry no
/// trust material, so request-smuggled keys are structurally impossible. Single-use tokens are
/// consumed into `replay` on success.
pub fn verify_admission(
    token: &SwarmContinuationToken,
    epoch: &SwarmRevocationEpoch,
    trusted_keys: &[PublicKey],
    ctx: &AdmissionContext,
    replay: &mut ReplayGuard,
) -> Result<Admission, AuthorityError> {
    // 0. fail-closed: no pinned keys => deny.
    if trusted_keys.is_empty() {
        return Err(AuthorityError::denied(DenyReason::NoTrustedKeys));
    }

    // 1. schema + signatures under pinned keys (token AND epoch).
    if token.schema != CONTINUATION_TOKEN_SCHEMA {
        return Err(AuthorityError::denied(DenyReason::UnsupportedSchema(token.schema.clone())));
    }
    verify_token_signature(token, trusted_keys)?;
    verify_epoch(epoch, trusted_keys)?;

    // 2. operation + lineage binding.
    if token.operation_id != epoch.operation_id {
        return Err(AuthorityError::denied(DenyReason::OperationMismatch));
    }
    if token.revocation_epoch_id != epoch.epoch_id || token.revocation_epoch_anchor != epoch.genesis_root_hash {
        return Err(AuthorityError::denied(DenyReason::EpochLineageMismatch));
    }

    // 3. recall: monotonic epoch (no rollback) + revoked-set membership.
    if epoch.epoch_number < token.min_epoch_number {
        return Err(AuthorityError::denied(DenyReason::StaleEpoch {
            min_epoch: token.min_epoch_number,
            presented_epoch: epoch.epoch_number,
        }));
    }
    if epoch.revoked_vector_ids.iter().any(|v| v == &token.vector_id) {
        return Err(AuthorityError::denied(DenyReason::VectorRevoked));
    }
    if epoch.revoked_token_ids.iter().any(|t| t == &token.token_id) {
        return Err(AuthorityError::denied(DenyReason::TokenRevoked));
    }

    // 4. validity windows.
    let now = ctx.now_unix_ms;
    if now < token.issued_at_unix_ms {
        return Err(AuthorityError::denied(DenyReason::TokenNotYetValid));
    }
    if now >= token.expires_at_unix_ms {
        return Err(AuthorityError::denied(DenyReason::TokenExpired));
    }
    if now < epoch.issued_at_unix_ms || now >= epoch.valid_until_unix_ms {
        return Err(AuthorityError::denied(DenyReason::EpochExpired));
    }

    // 5. caller-asserted bindings.
    if let Some(op) = &ctx.expected_operation_id
        && op != &token.operation_id
    {
        return Err(AuthorityError::denied(DenyReason::OperationMismatch));
    }
    if let Some(v) = &ctx.expected_vector_id
        && v != &token.vector_id
    {
        return Err(AuthorityError::denied(DenyReason::VectorMismatch));
    }
    if let Some(h) = &ctx.expected_vector_scope_hash
        && h != &token.vector_scope_hash
    {
        return Err(AuthorityError::denied(DenyReason::ScopeMismatch));
    }

    // 6. single-use replay-deny (consume last, only on full success).
    let consumed = match token.mode {
        ContinuationMode::SingleUse => {
            if replay.contains(&token.nonce) {
                return Err(AuthorityError::denied(DenyReason::Replay));
            }
            replay.record(&token.nonce);
            true
        }
        ContinuationMode::Resumable => false,
    };

    Ok(Admission {
        token_id: token.token_id.clone(),
        operation_id: token.operation_id.clone(),
        vector_id: token.vector_id.clone(),
        vector_scope_hash: token.vector_scope_hash.clone(),
        budget_lease: token.budget_lease.clone(),
        epoch_number: epoch.epoch_number,
        consumed,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::epoch::{OpenEpochRequest, open_epoch, revoke_token, revoke_vector};
    use crate::token::{IssueTokenRequest, issue_token, vector_scope_hash};
    use swarm_crypto::Keypair;

    const NOW: u64 = 1_750_000_000_000;
    const WINDOW: u64 = 3_600_000;

    fn lease() -> BudgetLease {
        BudgetLease { lease_id: "lease-1".into(), dimension: "actions".into(), max_units: 100 }
    }

    fn epoch_for(signer: &Keypair) -> SwarmRevocationEpoch {
        open_epoch(
            OpenEpochRequest {
                epoch_id: "ep-1".into(),
                operation_id: "op-1".into(),
                issued_at_unix_ms: NOW - 1_000,
                valid_until_unix_ms: NOW + WINDOW,
            },
            signer,
        )
        .unwrap()
    }

    fn token_for(signer: &Keypair, epoch: &SwarmRevocationEpoch, min_epoch: u64, mode: ContinuationMode) -> SwarmContinuationToken {
        issue_token(
            IssueTokenRequest {
                token_id: "tok-1".into(),
                operation_id: "op-1".into(),
                vector_id: "vec-01".into(),
                vector_scope_hash: vector_scope_hash(&serde_json::json!({ "objective": "recon" })).unwrap(),
                budget_lease: lease(),
                revocation_epoch_id: epoch.epoch_id.clone(),
                revocation_epoch_anchor: epoch.genesis_root_hash.clone(),
                min_epoch_number: min_epoch,
                nonce: "nonce-1".into(),
                mode,
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: NOW + WINDOW,
            },
            signer,
        )
        .unwrap()
    }

    fn harness() -> (Keypair, SwarmRevocationEpoch, SwarmContinuationToken, Vec<PublicKey>) {
        let op = Keypair::generate();
        let epoch = epoch_for(&op);
        let token = token_for(&op, &epoch, 0, ContinuationMode::SingleUse);
        let pinned = vec![op.public_key()];
        (op, epoch, token, pinned)
    }

    fn ctx() -> AdmissionContext {
        AdmissionContext { now_unix_ms: NOW, ..Default::default() }
    }

    #[test]
    fn valid_admission_grants() {
        let (_op, epoch, token, pinned) = harness();
        let adm = verify_admission(&token, &epoch, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap();
        assert_eq!(adm.vector_id, "vec-01");
        assert_eq!(adm.epoch_number, 0);
        assert!(adm.consumed);
    }

    #[test]
    fn revoked_epoch_denies() {
        let (op, epoch, token, pinned) = harness();
        let bumped = revoke_vector(&epoch, "vec-01", NOW, NOW + WINDOW, &op).unwrap();
        let err = verify_admission(&token, &bumped, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::VectorRevoked)));

        let bumped_tok = revoke_token(&epoch, "tok-1", NOW, NOW + WINDOW, &op).unwrap();
        let err = verify_admission(&token, &bumped_tok, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::TokenRevoked)));
    }

    #[test]
    fn untrusted_key_denies() {
        let (_op, epoch, token, _pinned) = harness();
        let other = vec![Keypair::generate().public_key()];
        let err = verify_admission(&token, &epoch, &other, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::UntrustedTokenIssuer)));
        let err = verify_admission(&token, &epoch, &[], &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::NoTrustedKeys)));
    }

    #[test]
    fn smuggled_issuer_denies() {
        // attacker mints a fully self-consistent token + epoch with valid attacker signatures,
        // but is not in the operator-only pinned set -> structurally rejected.
        let operator = Keypair::generate();
        let attacker = Keypair::generate();
        let att_epoch = epoch_for(&attacker);
        let att_token = token_for(&attacker, &att_epoch, 0, ContinuationMode::SingleUse);
        let pinned = vec![operator.public_key()];
        let err = verify_admission(&att_token, &att_epoch, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::UntrustedTokenIssuer)));
    }

    #[test]
    fn replay_denies_single_use_and_allows_resumable() {
        let (op, epoch, token, pinned) = harness();
        let mut guard = ReplayGuard::new();
        assert!(verify_admission(&token, &epoch, &pinned, &ctx(), &mut guard).is_ok());
        let err = verify_admission(&token, &epoch, &pinned, &ctx(), &mut guard).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::Replay)));

        let resumable = token_for(&op, &epoch, 0, ContinuationMode::Resumable);
        let mut guard2 = ReplayGuard::new();
        let a = verify_admission(&resumable, &epoch, &pinned, &ctx(), &mut guard2).unwrap();
        assert!(!a.consumed);
        assert!(verify_admission(&resumable, &epoch, &pinned, &ctx(), &mut guard2).is_ok());
    }

    #[test]
    fn tamper_denies() {
        let (_op, epoch, mut token, pinned) = harness();
        token.budget_lease.max_units = 1_000_000; // flip after signing
        let err = verify_admission(&token, &epoch, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::TokenSignatureInvalid)));

        let (_op, mut epoch, token, pinned) = harness();
        epoch.revoked_vector_ids.push("vec-01".into()); // tamper without re-rooting
        let err = verify_admission(&token, &epoch, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::EpochTampered)));
    }

    #[test]
    fn stale_epoch_rollback_denies() {
        let op = Keypair::generate();
        let epoch = epoch_for(&op); // number 0
        let token = token_for(&op, &epoch, 2, ContinuationMode::SingleUse); // requires epoch >= 2
        let pinned = vec![op.public_key()];
        let err = verify_admission(&token, &epoch, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::StaleEpoch { .. })));
    }

    #[test]
    fn expired_windows_deny() {
        let (_op, epoch, token, pinned) = harness();
        let late = AdmissionContext { now_unix_ms: NOW + WINDOW + 1, ..Default::default() };
        let err = verify_admission(&token, &epoch, &pinned, &late, &mut ReplayGuard::new()).unwrap_err();
        // both the token and epoch windows have closed; token is checked first.
        assert!(matches!(
            err,
            AuthorityError::Denied(DenyReason::TokenExpired) | AuthorityError::Denied(DenyReason::EpochExpired)
        ));
    }

    #[test]
    fn lineage_and_scope_mismatch_deny() {
        let (op, _epoch, token, pinned) = harness();
        // a different-lineage epoch (different epoch_id) signed by the same pinned operator
        let other_epoch = open_epoch(
            OpenEpochRequest {
                epoch_id: "ep-2".into(),
                operation_id: "op-1".into(),
                issued_at_unix_ms: NOW - 1_000,
                valid_until_unix_ms: NOW + WINDOW,
            },
            &op,
        )
        .unwrap();
        let err = verify_admission(&token, &other_epoch, &pinned, &ctx(), &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::EpochLineageMismatch)));

        let (_op2, epoch2, token2, pinned2) = harness();
        let mismatch = AdmissionContext {
            now_unix_ms: NOW,
            expected_vector_scope_hash: Some("0".repeat(64)),
            ..Default::default()
        };
        let err = verify_admission(&token2, &epoch2, &pinned2, &mismatch, &mut ReplayGuard::new()).unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::ScopeMismatch)));
    }
}
