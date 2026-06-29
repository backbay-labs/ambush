//! The per-Vector signed continuation token (single-hop capability).

use serde::{Deserialize, Serialize};
use swarm_crypto::{Keypair, PublicKey, Signature, canonical_json_string};

use crate::error::{AuthorityError, DenyReason};
use crate::util::{
    digest_hex, is_pinned, issuer_did, issuer_public_key, require_non_empty, require_sha256,
    signature_body,
};

pub const CONTINUATION_TOKEN_SCHEMA: &str = "ambush.swarm.continuation-token.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationMode {
    SingleUse,
    Resumable,
}

/// A self-contained budget lease carried inside the token (collapses the reference budget pool).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetLease {
    pub lease_id: String,
    pub dimension: String,
    pub max_units: u64,
}

/// One signed continuation token, issued per Vector at deploy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmContinuationToken {
    pub schema: String,
    pub token_id: String,
    pub operation_id: String,
    pub vector_id: String,
    pub vector_scope_hash: String,
    pub budget_lease: BudgetLease,
    pub revocation_epoch_id: String,
    pub revocation_epoch_anchor: String,
    pub min_epoch_number: u64,
    pub nonce: String,
    pub mode: ContinuationMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub issuer: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct IssueTokenRequest {
    pub token_id: String,
    pub operation_id: String,
    pub vector_id: String,
    pub vector_scope_hash: String,
    pub budget_lease: BudgetLease,
    pub revocation_epoch_id: String,
    pub revocation_epoch_anchor: String,
    pub min_epoch_number: u64,
    pub nonce: String,
    pub mode: ContinuationMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// 64-hex sha256 over any serializable vector scope object (objective, worktree, allowed tools, …).
pub fn vector_scope_hash<T: Serialize>(scope: &T) -> Result<String, AuthorityError> {
    digest_hex(scope)
}

/// Canonical signing body for a token: the struct as a JSON object minus its `signature` field.
pub fn continuation_token_signature_body(
    token: &SwarmContinuationToken,
) -> Result<serde_json::Value, AuthorityError> {
    signature_body(token, "continuation token signature body")
}

/// Sign a fully-populated token; the signer must match the token's self-certifying issuer.
pub fn sign_continuation_token(
    token: &SwarmContinuationToken,
    signer: &Keypair,
) -> Result<String, AuthorityError> {
    let issuer_key = issuer_public_key(&token.issuer).map_err(AuthorityError::Denied)?;
    if issuer_key != signer.public_key() {
        return Err(AuthorityError::Invalid("token signer does not match issuer".into()));
    }
    let body = continuation_token_signature_body(token)?;
    let canonical = canonical_json_string(&body).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    Ok(signer.sign(canonical.as_bytes()).to_hex())
}

/// Validate, issue, and sign a token (root authority mints one per Vector at deploy).
pub fn issue_token(req: IssueTokenRequest, signer: &Keypair) -> Result<SwarmContinuationToken, AuthorityError> {
    require_non_empty(&req.token_id, "token id")?;
    require_non_empty(&req.operation_id, "operation id")?;
    require_non_empty(&req.vector_id, "vector id")?;
    require_sha256(&req.vector_scope_hash, "vector scope hash")?;
    require_non_empty(&req.budget_lease.lease_id, "budget lease id")?;
    require_non_empty(&req.budget_lease.dimension, "budget lease dimension")?;
    if req.budget_lease.max_units == 0 {
        return Err(AuthorityError::Invalid("budget lease max_units must be positive".into()));
    }
    require_non_empty(&req.revocation_epoch_id, "revocation epoch id")?;
    require_sha256(&req.revocation_epoch_anchor, "revocation epoch anchor")?;
    require_non_empty(&req.nonce, "nonce")?;
    if req.expires_at_unix_ms <= req.issued_at_unix_ms {
        return Err(AuthorityError::Invalid("token expiry must be after issue time".into()));
    }
    let mut token = SwarmContinuationToken {
        schema: CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: req.token_id,
        operation_id: req.operation_id,
        vector_id: req.vector_id,
        vector_scope_hash: req.vector_scope_hash,
        budget_lease: req.budget_lease,
        revocation_epoch_id: req.revocation_epoch_id,
        revocation_epoch_anchor: req.revocation_epoch_anchor,
        min_epoch_number: req.min_epoch_number,
        nonce: req.nonce,
        mode: req.mode,
        issued_at_unix_ms: req.issued_at_unix_ms,
        expires_at_unix_ms: req.expires_at_unix_ms,
        issuer: issuer_did(&signer.public_key()),
        signature: String::new(),
    };
    token.signature = sign_continuation_token(&token, signer)?;
    Ok(token)
}

/// Verify a token's signature under a pinned key (fail-closed).
pub(crate) fn verify_token_signature(
    token: &SwarmContinuationToken,
    trusted_keys: &[PublicKey],
) -> Result<(), AuthorityError> {
    let key = issuer_public_key(&token.issuer).map_err(AuthorityError::Denied)?;
    if !is_pinned(&key, trusted_keys) {
        return Err(AuthorityError::denied(DenyReason::UntrustedTokenIssuer));
    }
    let sig = Signature::from_hex(&token.signature)
        .map_err(|_| AuthorityError::denied(DenyReason::TokenSignatureInvalid))?;
    let body = continuation_token_signature_body(token)?;
    let canonical = canonical_json_string(&body).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    if key.verify(canonical.as_bytes(), &sig) {
        Ok(())
    } else {
        Err(AuthorityError::denied(DenyReason::TokenSignatureInvalid))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn lease() -> BudgetLease {
        BudgetLease { lease_id: "lease-1".into(), dimension: "actions".into(), max_units: 100 }
    }

    fn req(scope_hash: String, anchor: String) -> IssueTokenRequest {
        IssueTokenRequest {
            token_id: "tok-1".into(),
            operation_id: "op-1".into(),
            vector_id: "vec-01".into(),
            vector_scope_hash: scope_hash,
            budget_lease: lease(),
            revocation_epoch_id: "ep-1".into(),
            revocation_epoch_anchor: anchor,
            min_epoch_number: 0,
            nonce: "nonce-1".into(),
            mode: ContinuationMode::SingleUse,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        }
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let signer = Keypair::generate();
        let scope = vector_scope_hash(&serde_json::json!({ "objective": "recon" })).unwrap();
        let anchor = vector_scope_hash(&serde_json::json!({ "epochId": "ep-1" })).unwrap();
        let token = issue_token(req(scope, anchor), &signer).unwrap();
        let pinned = vec![signer.public_key()];
        assert!(verify_token_signature(&token, &pinned).is_ok());
    }

    #[test]
    fn issue_rejects_zero_budget_and_bad_window() {
        let signer = Keypair::generate();
        let scope = vector_scope_hash(&serde_json::json!({ "objective": "recon" })).unwrap();
        let anchor = scope.clone();
        let mut r = req(scope, anchor);
        r.budget_lease.max_units = 0;
        assert!(matches!(issue_token(r, &signer), Err(AuthorityError::Invalid(_))));

        let scope = vector_scope_hash(&serde_json::json!({ "objective": "recon" })).unwrap();
        let mut r = req(scope.clone(), scope);
        r.expires_at_unix_ms = r.issued_at_unix_ms;
        assert!(matches!(issue_token(r, &signer), Err(AuthorityError::Invalid(_))));
    }
}
