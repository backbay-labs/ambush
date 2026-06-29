//! Fail-closed admission errors and the typed deny reasons.

/// Why an admission was denied. Every denial is fail-closed and explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// Caller supplied an empty pinned-key set (fail-closed; no implicit trust).
    NoTrustedKeys,
    /// Token or epoch `issuer` is not a valid self-certifying public key.
    MalformedIssuer,
    /// Token `issuer` key is not in the caller's pinned `trusted_keys`.
    UntrustedTokenIssuer,
    /// Epoch `issuer` key is not in the caller's pinned `trusted_keys`.
    UntrustedEpochIssuer,
    /// Token signature does not verify under its (pinned) issuer key.
    TokenSignatureInvalid,
    /// Epoch signature does not verify under its (pinned) issuer key.
    EpochSignatureInvalid,
    /// Unknown / unsupported schema tag on token or epoch.
    UnsupportedSchema(String),
    /// Epoch presented does not belong to the token's revocation lineage.
    EpochLineageMismatch,
    /// Epoch `root_hash` does not recompute from its content (tamper).
    EpochTampered,
    /// Epoch is older than the epoch the token was issued under (rollback to dodge recall).
    StaleEpoch { min_epoch: u64, presented_epoch: u64 },
    /// Token's vector is in the epoch's revoked-vector set (recall).
    VectorRevoked,
    /// Token id is in the epoch's revoked-token set (targeted recall).
    TokenRevoked,
    /// Token and epoch are scoped to different operations.
    OperationMismatch,
    /// Caller-provided expected vector id did not match the token.
    VectorMismatch,
    /// Caller-provided expected scope hash did not match the token.
    ScopeMismatch,
    /// Epoch validity window does not contain `now`.
    EpochExpired,
    /// Token validity window does not contain `now`.
    TokenExpired,
    /// Token is not yet valid at `now`.
    TokenNotYetValid,
    /// Single-use token nonce already consumed (replay).
    Replay,

    // ---- Multi-hop delegation (witness chain) deny reasons. ----
    /// A witness `issuer` is not a valid self-certifying public key.
    MalformedWitnessIssuer,
    /// The chain-root (hop 0) witness issuer is not in the caller's pinned `trusted_keys`.
    UntrustedWitnessIssuer,
    /// A witness signature does not verify under its issuer key.
    WitnessSignatureInvalid,
    /// The delegation chain carried no hops.
    WitnessChainEmpty,
    /// Hop indices are not sequential from zero.
    WitnessHopIndexMismatch,
    /// The chain/operation/root binding on a hop or chain does not match the root token.
    WitnessChainMismatch,
    /// The chain and the root token are scoped to different operations.
    WitnessOperationMismatch,
    /// A hop's delegator key does not match the prior hop's delegatee, or the parent vector
    /// does not match the prior hop's child (broken delegation link).
    WitnessChainBroken,
    /// A hop's parent scope hash does not equal the prior hop's child scope hash.
    WitnessScopeDiscontinuity,
    /// Hop 0's parent scope hash does not equal the root token's `vector_scope_hash`.
    WitnessRootScopeMismatch,
    /// A hop's recomputed scope hash does not match its declared hash (scope inflation/tamper).
    WitnessScopeHashMismatch,
    /// A hop's child scope is not a subset of its parent scope (a widening).
    WitnessScopeWidens,
    /// A hop's child vector is in the epoch's revoked-vector set (recall mid-chain).
    WitnessVectorRevoked,
    /// A hop's validity window does not yet contain `now`.
    WitnessNotYetValid,
    /// A hop's validity window has closed.
    WitnessExpired,
    /// A hop's expiry extends beyond its parent's expiry (time widening).
    WitnessExpiryWidens,
    /// A single-use witness nonce was already consumed (replay).
    WitnessReplay,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    /// Fail-closed admission denial with a typed reason.
    #[error("admission denied: {0:?}")]
    Denied(DenyReason),
    /// Canonical-JSON serialization failed (internal).
    #[error("swarm authority canonical JSON failed: {0}")]
    Canonical(String),
    /// Issuance / recall request was malformed.
    #[error("invalid swarm authority request: {0}")]
    Invalid(String),
}

impl AuthorityError {
    pub(crate) fn denied(reason: DenyReason) -> Self {
        Self::Denied(reason)
    }
}
