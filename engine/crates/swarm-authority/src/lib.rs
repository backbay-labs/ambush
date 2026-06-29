//! Single-hop swarm authority: per-Vector signed continuation tokens + cryptographic recall.
//!
//! Carved from the Arc/Chio `chio-swarm-authority` and collapsed to one hop, rebuilt on swarm-crypto.
//! The operation root (operator/governor key) mints ONE [`SwarmContinuationToken`] per Vector at
//! deploy, bound to a vector scope hash, a budget lease, and a [`SwarmRevocationEpoch`] lineage.
//! Recall = bump the signed epoch (add the vector/token to the revoked set, re-sign); the next
//! [`verify_admission`] against the bumped epoch fails closed. Trust is supplied ONLY via the
//! `trusted_keys` argument, so request-smuggled keys are structurally impossible; single-use tokens
//! are replay-denied via a caller-owned [`ReplayGuard`].

pub mod admission;
pub mod epoch;
pub mod error;
pub mod token;
pub mod witness;
mod util;

pub use admission::{Admission, AdmissionContext, ReplayGuard, verify_admission};
pub use epoch::{
    OpenEpochRequest, REVOCATION_EPOCH_SCHEMA, SwarmRevocationEpoch, epoch_root_hash, lineage_anchor,
    open_epoch, revocation_epoch_signature_body, revoke_token, revoke_vector, sign_revocation_epoch,
};
pub use error::{AuthorityError, DenyReason};
pub use token::{
    BudgetLease, CONTINUATION_TOKEN_SCHEMA, ContinuationMode, IssueTokenRequest, SwarmContinuationToken,
    continuation_token_signature_body, issue_token, sign_continuation_token, vector_scope_hash,
};
pub use witness::{
    DELEGATION_CHAIN_SCHEMA, DELEGATION_WITNESS_SCHEMA, DelegateRequest, DelegatedAdmission,
    DelegatedAdmissionContext, DelegationChain, DelegationWitness, VectorScope, delegate,
    delegation_witness_signature_body, sign_delegation_witness, verify_delegated_admission,
    witness_scope_hash,
};
pub use util::DID_AMBUSH_PREFIX;
