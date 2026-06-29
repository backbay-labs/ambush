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
