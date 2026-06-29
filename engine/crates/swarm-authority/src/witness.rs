//! Verifiable multi-hop delegation (Vector -> sub-Vector), additive over the single-hop core.
//!
//! The single-hop [`crate::verify_admission`] admits ONE operator-issued
//! [`SwarmContinuationToken`] for ONE Vector. This module extends that to a verifiable
//! delegation chain: a parent token-holder hands a NARROWED scope to a child Vector, each hop
//! signed by the parent key, the chain ROOTED in the operator-issued token (whose issuer the
//! single-hop verifier already pins to a trusted key).
//!
//! A [`DelegationWitness`] is one signed link: `parent_vector -> child_vector`, carrying both the
//! normalized parent and child [`VectorScope`]s plus their hashes. Verification recomputes the
//! hashes from the carried scopes (closing the parent-scope-inflation gap), enforces monotonic
//! attenuation (child capabilities MUST be a subset of the parent's), and walks the chain checking
//! key-connectivity (`hop[i].issuer == hop[i-1].delegatee`), scope-continuity
//! (`hop[i].parent == hop[i-1].child`), the existing revocation-epoch rules, validity windows
//! (monotonically narrowing), and single-use replay AT EVERY HOP.
//!
//! Trust enters ONLY via `trusted_keys`: the chain root (hop 0) must be signed by a pinned key and
//! must pin its parent scope to the root token's `vector_scope_hash`. Downstream hops inherit
//! authority purely by delegation, so a request-smuggled witness is structurally impossible.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use swarm_crypto::{Keypair, PublicKey, Signature, canonical_json_string};

use crate::admission::{Admission, AdmissionContext, ReplayGuard, verify_admission};
use crate::epoch::SwarmRevocationEpoch;
use crate::error::{AuthorityError, DenyReason};
use crate::token::{ContinuationMode, SwarmContinuationToken};
use crate::util::{
    digest_hex, is_pinned, issuer_did, issuer_public_key, require_non_empty, signature_body,
};

pub const DELEGATION_WITNESS_SCHEMA: &str = "ambush.swarm.delegation-witness.v1";
pub const DELEGATION_CHAIN_SCHEMA: &str = "ambush.swarm.delegation-chain.v1";

/// Upper bound on delegation chain length, bounding signature-verification work per admission.
pub const MAX_DELEGATION_HOPS: usize = 16;

/// A set-based capability scope. Narrowing is set containment: removing capabilities narrows,
/// adding any capability the parent lacks widens. A `BTreeSet` serializes as a sorted JSON array,
/// so its canonical hash is stable.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VectorScope {
    pub capabilities: BTreeSet<String>,
}

impl VectorScope {
    /// True when every capability of `self` is also held by `parent` (monotonic attenuation).
    #[must_use]
    pub fn is_subset_of(&self, parent: &VectorScope) -> bool {
        self.capabilities.is_subset(&parent.capabilities)
    }
}

/// One signed delegation link: the holder of `parent_scope` (signer `issuer`) narrows it to
/// `child_scope` for `child_vector_id`, naming `delegatee` (the child key authorized to delegate
/// the next hop). Each hop carries the normalized scopes so a verifier can recompute the declared
/// hashes and check the subset relation without external state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationWitness {
    pub schema: String,
    pub chain_id: String,
    pub operation_id: String,
    pub hop_index: u64,
    pub parent_vector_id: String,
    pub child_vector_id: String,
    pub parent_scope_hash: String,
    pub child_scope_hash: String,
    pub parent_scope: VectorScope,
    pub child_scope: VectorScope,
    /// Self-certifying DID of the child key authorized to sign the NEXT hop.
    pub delegatee: String,
    pub nonce: String,
    pub mode: ContinuationMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    /// Self-certifying DID of the delegator (parent) key that signed this hop.
    pub issuer: String,
    pub signature: String,
}

/// An ordered chain of witnesses, bound to one operator-issued root token + operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationChain {
    pub schema: String,
    pub chain_id: String,
    pub operation_id: String,
    pub root_token_id: String,
    pub root_vector_id: String,
    pub hops: Vec<DelegationWitness>,
}

/// Operational bindings the caller asserts about the delegated (leaf) admission.
#[derive(Clone, Debug, Default)]
pub struct DelegatedAdmissionContext {
    pub now_unix_ms: u64,
    pub expected_operation_id: Option<String>,
    pub expected_leaf_vector_id: Option<String>,
    pub expected_leaf_scope_hash: Option<String>,
    /// The live revocation-epoch number the caller knows; denies a rolled-back older epoch.
    pub expected_min_epoch: Option<u64>,
}

/// What a successful delegated admission grants: the root single-hop admission plus the
/// narrowed leaf authority the chain resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedAdmission {
    pub root: Admission,
    pub leaf_vector_id: String,
    pub leaf_scope_hash: String,
    pub hops: usize,
    pub epoch_number: u64,
}

/// A delegation-mint request (the parent narrows `parent_scope` to `child_scope`).
#[derive(Clone, Debug)]
pub struct DelegateRequest {
    pub chain_id: String,
    pub operation_id: String,
    pub hop_index: u64,
    pub parent_vector_id: String,
    pub child_vector_id: String,
    pub parent_scope: VectorScope,
    pub child_scope: VectorScope,
    pub delegatee: PublicKey,
    pub nonce: String,
    pub mode: ContinuationMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// 64-hex sha256 over a canonicalized [`VectorScope`].
pub fn witness_scope_hash(scope: &VectorScope) -> Result<String, AuthorityError> {
    digest_hex(scope)
}

/// Canonical signing body for a witness: the struct as a JSON object minus its `signature` field.
pub fn delegation_witness_signature_body(
    witness: &DelegationWitness,
) -> Result<serde_json::Value, AuthorityError> {
    signature_body(witness, "delegation witness signature body")
}

/// Sign a fully-populated witness; the signer must match the witness's self-certifying issuer.
pub fn sign_delegation_witness(
    witness: &DelegationWitness,
    signer: &Keypair,
) -> Result<String, AuthorityError> {
    let issuer_key = issuer_public_key(&witness.issuer).map_err(AuthorityError::Denied)?;
    if issuer_key != signer.public_key() {
        return Err(AuthorityError::Invalid("witness signer does not match issuer".into()));
    }
    let body = delegation_witness_signature_body(witness)?;
    let canonical = canonical_json_string(&body).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    Ok(signer.sign(canonical.as_bytes()).to_hex())
}

/// Mint one delegation hop: validate the narrowing fail-closed, then sign with the parent key.
///
/// Denies when the child scope is not a subset of the parent (a widening), the window is empty,
/// or any identity field is empty. The delegator key becomes the self-certifying `issuer`.
pub fn delegate(req: DelegateRequest, delegator: &Keypair) -> Result<DelegationWitness, AuthorityError> {
    require_non_empty(&req.chain_id, "chain id")?;
    require_non_empty(&req.operation_id, "operation id")?;
    require_non_empty(&req.parent_vector_id, "parent vector id")?;
    require_non_empty(&req.child_vector_id, "child vector id")?;
    require_non_empty(&req.nonce, "witness nonce")?;
    if req.expires_at_unix_ms <= req.issued_at_unix_ms {
        return Err(AuthorityError::Invalid("witness expiry must be after issue time".into()));
    }
    if !req.child_scope.is_subset_of(&req.parent_scope) {
        return Err(AuthorityError::Invalid(
            "child scope must be a subset of parent scope (delegation may only narrow)".into(),
        ));
    }
    let parent_scope_hash = witness_scope_hash(&req.parent_scope)?;
    let child_scope_hash = witness_scope_hash(&req.child_scope)?;
    let mut witness = DelegationWitness {
        schema: DELEGATION_WITNESS_SCHEMA.to_string(),
        chain_id: req.chain_id,
        operation_id: req.operation_id,
        hop_index: req.hop_index,
        parent_vector_id: req.parent_vector_id,
        child_vector_id: req.child_vector_id,
        parent_scope_hash,
        child_scope_hash,
        parent_scope: req.parent_scope,
        child_scope: req.child_scope,
        delegatee: issuer_did(&req.delegatee),
        nonce: req.nonce,
        mode: req.mode,
        issued_at_unix_ms: req.issued_at_unix_ms,
        expires_at_unix_ms: req.expires_at_unix_ms,
        issuer: issuer_did(&delegator.public_key()),
        signature: String::new(),
    };
    witness.signature = sign_delegation_witness(&witness, delegator)?;
    Ok(witness)
}

/// Verify a hop's signature under an already-parsed issuer key (fail-closed).
fn verify_witness_signature(
    witness: &DelegationWitness,
    issuer_key: &PublicKey,
) -> Result<(), AuthorityError> {
    let sig = Signature::from_hex(&witness.signature)
        .map_err(|_| AuthorityError::denied(DenyReason::WitnessSignatureInvalid))?;
    let body = delegation_witness_signature_body(witness)?;
    let canonical = canonical_json_string(&body).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    if issuer_key.verify(canonical.as_bytes(), &sig) {
        Ok(())
    } else {
        Err(AuthorityError::denied(DenyReason::WitnessSignatureInvalid))
    }
}

/// Fail-closed multi-hop admission. Verifies the operator-issued root token + epoch via the
/// single-hop [`verify_admission`] (signatures under pinned keys, lineage, recall, windows, root
/// replay), then walks the witness chain enforcing, at every hop: chain/operation binding, scope
/// attenuation (subset) with hash recompute, key-connectivity, scope-continuity, the
/// revocation-epoch revoked-vector set, monotonically narrowing windows, and single-use replay.
///
/// Trust comes ONLY from `trusted_keys`; hop 0 must be signed by a pinned key and must pin its
/// parent scope to the root token's `vector_scope_hash`.
pub fn verify_delegated_admission(
    token: &SwarmContinuationToken,
    chain: &DelegationChain,
    epoch: &SwarmRevocationEpoch,
    trusted_keys: &[PublicKey],
    ctx: &DelegatedAdmissionContext,
    replay: &mut ReplayGuard,
) -> Result<DelegatedAdmission, AuthorityError> {
    // 0. fail-closed: no pinned keys => deny.
    if trusted_keys.is_empty() {
        return Err(AuthorityError::denied(DenyReason::NoTrustedKeys));
    }

    // 1. chain schema + binding to the root token/operation.
    if chain.schema != DELEGATION_CHAIN_SCHEMA {
        return Err(AuthorityError::denied(DenyReason::UnsupportedSchema(chain.schema.clone())));
    }
    if chain.operation_id != token.operation_id {
        return Err(AuthorityError::denied(DenyReason::WitnessOperationMismatch));
    }
    if chain.root_token_id != token.token_id || chain.root_vector_id != token.vector_id {
        return Err(AuthorityError::denied(DenyReason::WitnessChainMismatch));
    }
    if chain.hops.is_empty() {
        return Err(AuthorityError::denied(DenyReason::WitnessChainEmpty));
    }
    if chain.hops.len() > MAX_DELEGATION_HOPS {
        return Err(AuthorityError::denied(DenyReason::WitnessChainTooLong));
    }

    // Validate the WHOLE chain against a SCRATCH replay clone and commit the consumed nonces back
    // only on full success — so a failure mid-walk never irreversibly burns the single-use root
    // token or earlier hop nonces (preserving "consume last, only on full success").
    let mut scratch = replay.clone();

    // 2. root single-hop admission (reuses all token + epoch checks, incl. root replay).
    let root_ctx = AdmissionContext {
        now_unix_ms: ctx.now_unix_ms,
        expected_operation_id: ctx.expected_operation_id.clone(),
        expected_vector_id: Some(chain.root_vector_id.clone()),
        expected_vector_scope_hash: None,
        expected_min_epoch: ctx.expected_min_epoch,
    };
    let root = verify_admission(token, epoch, trusted_keys, &root_ctx, &mut scratch)?;

    // 3. walk the witness chain.
    let now = ctx.now_unix_ms;
    let mut previous: Option<&DelegationWitness> = None;
    let mut expected_index: u64 = 0;
    let mut parent_expires = token.expires_at_unix_ms;

    for hop in &chain.hops {
        // 3a. schema + chain/operation + ordering.
        if hop.schema != DELEGATION_WITNESS_SCHEMA {
            return Err(AuthorityError::denied(DenyReason::UnsupportedSchema(hop.schema.clone())));
        }
        if hop.chain_id != chain.chain_id || hop.operation_id != chain.operation_id {
            return Err(AuthorityError::denied(DenyReason::WitnessChainMismatch));
        }
        if hop.hop_index != expected_index {
            return Err(AuthorityError::denied(DenyReason::WitnessHopIndexMismatch));
        }

        // 3b. recompute the declared hashes from the carried scopes (anti-inflation).
        if witness_scope_hash(&hop.parent_scope)? != hop.parent_scope_hash
            || witness_scope_hash(&hop.child_scope)? != hop.child_scope_hash
        {
            return Err(AuthorityError::denied(DenyReason::WitnessScopeHashMismatch));
        }

        // 3c. monotonic attenuation: the child scope must be a subset of the parent scope.
        if !hop.child_scope.is_subset_of(&hop.parent_scope) {
            return Err(AuthorityError::denied(DenyReason::WitnessScopeWidens));
        }

        // 3d. validity windows, narrowing monotonically toward the leaf.
        if now < hop.issued_at_unix_ms {
            return Err(AuthorityError::denied(DenyReason::WitnessNotYetValid));
        }
        if now >= hop.expires_at_unix_ms {
            return Err(AuthorityError::denied(DenyReason::WitnessExpired));
        }
        if hop.expires_at_unix_ms > parent_expires {
            return Err(AuthorityError::denied(DenyReason::WitnessExpiryWidens));
        }

        // 3e. signature under the hop's self-certifying issuer key.
        let issuer_key = issuer_public_key(&hop.issuer).map_err(AuthorityError::Denied)?;
        verify_witness_signature(hop, &issuer_key)?;

        // 3f. trust binding: root hop pins to a trusted key + the root token scope; downstream
        //     hops inherit authority by key-connectivity + scope-continuity.
        match previous {
            None => {
                if !is_pinned(&issuer_key, trusted_keys) {
                    return Err(AuthorityError::denied(DenyReason::UntrustedWitnessIssuer));
                }
                if hop.parent_vector_id != token.vector_id {
                    return Err(AuthorityError::denied(DenyReason::WitnessChainMismatch));
                }
                if hop.parent_scope_hash != token.vector_scope_hash {
                    return Err(AuthorityError::denied(DenyReason::WitnessRootScopeMismatch));
                }
            }
            Some(prev) => {
                let expected_issuer =
                    issuer_public_key(&prev.delegatee).map_err(AuthorityError::Denied)?;
                if issuer_key != expected_issuer {
                    return Err(AuthorityError::denied(DenyReason::WitnessChainBroken));
                }
                if hop.parent_vector_id != prev.child_vector_id {
                    return Err(AuthorityError::denied(DenyReason::WitnessChainBroken));
                }
                if hop.parent_scope_hash != prev.child_scope_hash {
                    return Err(AuthorityError::denied(DenyReason::WitnessScopeDiscontinuity));
                }
            }
        }

        // 3g. recall at every hop: the child vector must not be revoked in the epoch.
        if epoch.revoked_vector_ids.iter().any(|v| v == &hop.child_vector_id) {
            return Err(AuthorityError::denied(DenyReason::WitnessVectorRevoked));
        }

        // 3h. single-use replay-deny at every hop (namespaced from token nonces). Recorded into the
        // scratch guard; committed only if the whole chain validates (see step 4).
        if let ContinuationMode::SingleUse = hop.mode {
            let key = format!("witness-nonce:{}", hop.nonce);
            if !scratch.observe(&key) {
                return Err(AuthorityError::denied(DenyReason::WitnessReplay));
            }
        }

        parent_expires = hop.expires_at_unix_ms;
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| AuthorityError::Canonical("hop index overflow".into()))?;
        previous = Some(hop);
    }

    // 4. resolve the leaf and apply caller-asserted leaf bindings.
    let Some(leaf) = chain.hops.last() else {
        return Err(AuthorityError::denied(DenyReason::WitnessChainEmpty));
    };
    if let Some(v) = &ctx.expected_leaf_vector_id
        && v != &leaf.child_vector_id
    {
        return Err(AuthorityError::denied(DenyReason::VectorMismatch));
    }
    if let Some(h) = &ctx.expected_leaf_scope_hash
        && h != &leaf.child_scope_hash
    {
        return Err(AuthorityError::denied(DenyReason::ScopeMismatch));
    }

    // Full chain validated — commit the consumed nonces (root + hops) into the caller's guard.
    *replay = scratch;

    let epoch_number = root.epoch_number;
    Ok(DelegatedAdmission {
        root,
        leaf_vector_id: leaf.child_vector_id.clone(),
        leaf_scope_hash: leaf.child_scope_hash.clone(),
        hops: chain.hops.len(),
        epoch_number,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::epoch::{OpenEpochRequest, open_epoch, revoke_vector};
    use crate::token::{BudgetLease, IssueTokenRequest, SwarmContinuationToken, issue_token};

    const NOW: u64 = 1_750_000_000_000;
    const WINDOW: u64 = 3_600_000;

    fn scope(caps: &[&str]) -> VectorScope {
        VectorScope { capabilities: caps.iter().map(|c| (*c).to_string()).collect() }
    }

    fn lease() -> BudgetLease {
        BudgetLease { lease_id: "lease-1".into(), dimension: "actions".into(), max_units: 100 }
    }

    fn root_token(
        operator: &Keypair,
        epoch: &SwarmRevocationEpoch,
        root_scope: &VectorScope,
        mode: ContinuationMode,
    ) -> SwarmContinuationToken {
        issue_token(
            IssueTokenRequest {
                token_id: "tok-root".into(),
                operation_id: "op-1".into(),
                vector_id: "vec-root".into(),
                vector_scope_hash: witness_scope_hash(root_scope).unwrap(),
                budget_lease: lease(),
                revocation_epoch_id: epoch.epoch_id.clone(),
                revocation_epoch_anchor: epoch.genesis_root_hash.clone(),
                min_epoch_number: 0,
                nonce: "root-nonce".into(),
                mode,
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: NOW + WINDOW,
            },
            operator,
        )
        .unwrap()
    }

    fn epoch_for(operator: &Keypair) -> SwarmRevocationEpoch {
        open_epoch(
            OpenEpochRequest {
                epoch_id: "ep-1".into(),
                operation_id: "op-1".into(),
                issued_at_unix_ms: NOW - 1_000,
                valid_until_unix_ms: NOW + WINDOW,
            },
            operator,
        )
        .unwrap()
    }

    /// Construct + sign a hop with arbitrary scopes (bypasses `delegate`'s subset check so we can
    /// craft widening / tampered hops for negative tests).
    #[allow(clippy::too_many_arguments)]
    fn signed_hop(
        index: u64,
        parent_vector: &str,
        child_vector: &str,
        parent_scope: VectorScope,
        child_scope: VectorScope,
        delegatee: &PublicKey,
        nonce: &str,
        mode: ContinuationMode,
        delegator: &Keypair,
    ) -> DelegationWitness {
        let parent_scope_hash = witness_scope_hash(&parent_scope).unwrap();
        let child_scope_hash = witness_scope_hash(&child_scope).unwrap();
        let mut witness = DelegationWitness {
            schema: DELEGATION_WITNESS_SCHEMA.to_string(),
            chain_id: "chain-1".into(),
            operation_id: "op-1".into(),
            hop_index: index,
            parent_vector_id: parent_vector.into(),
            child_vector_id: child_vector.into(),
            parent_scope_hash,
            child_scope_hash,
            parent_scope,
            child_scope,
            delegatee: issuer_did(delegatee),
            nonce: nonce.into(),
            mode,
            issued_at_unix_ms: NOW - 1_000,
            expires_at_unix_ms: NOW + WINDOW,
            issuer: issuer_did(&delegator.public_key()),
            signature: String::new(),
        };
        witness.signature = sign_delegation_witness(&witness, delegator).unwrap();
        witness
    }

    struct Harness {
        operator: Keypair,
        mid: Keypair,
        leaf: Keypair,
        token: SwarmContinuationToken,
        epoch: SwarmRevocationEpoch,
        chain: DelegationChain,
        pinned: Vec<PublicKey>,
        leaf_scope: VectorScope,
    }

    fn harness(root_mode: ContinuationMode) -> Harness {
        let operator = Keypair::generate();
        let mid = Keypair::generate();
        let leaf = Keypair::generate();

        let root_scope = scope(&["a", "b", "c"]);
        let mid_scope = scope(&["a", "b"]);
        let leaf_scope = scope(&["a"]);

        let epoch = epoch_for(&operator);
        let token = root_token(&operator, &epoch, &root_scope, root_mode);

        // hop 0: operator (pinned root) narrows root -> mid for vec-mid, delegating to `mid`.
        let hop0 = signed_hop(
            0,
            "vec-root",
            "vec-mid",
            root_scope,
            mid_scope.clone(),
            &mid.public_key(),
            "hop0-nonce",
            ContinuationMode::SingleUse,
            &operator,
        );
        // hop 1: `mid` narrows mid -> leaf for vec-leaf, delegating to `leaf`.
        let hop1 = signed_hop(
            1,
            "vec-mid",
            "vec-leaf",
            mid_scope,
            leaf_scope.clone(),
            &leaf.public_key(),
            "hop1-nonce",
            ContinuationMode::SingleUse,
            &mid,
        );
        let chain = DelegationChain {
            schema: DELEGATION_CHAIN_SCHEMA.to_string(),
            chain_id: "chain-1".into(),
            operation_id: "op-1".into(),
            root_token_id: "tok-root".into(),
            root_vector_id: "vec-root".into(),
            hops: vec![hop0, hop1],
        };
        let pinned = vec![operator.public_key()];
        Harness { operator, mid, leaf, token, epoch, chain, pinned, leaf_scope }
    }

    fn ctx(h: &Harness) -> DelegatedAdmissionContext {
        DelegatedAdmissionContext {
            now_unix_ms: NOW,
            expected_operation_id: Some("op-1".into()),
            expected_leaf_vector_id: Some("vec-leaf".into()),
            expected_leaf_scope_hash: Some(witness_scope_hash(&h.leaf_scope).unwrap()),
            expected_min_epoch: None,
        }
    }

    #[test]
    fn valid_two_hop_chain_admits() {
        let h = harness(ContinuationMode::SingleUse);
        let adm = verify_delegated_admission(
            &h.token,
            &h.chain,
            &h.epoch,
            &h.pinned,
            &ctx(&h),
            &mut ReplayGuard::new(),
        )
        .unwrap();
        assert_eq!(adm.leaf_vector_id, "vec-leaf");
        assert_eq!(adm.hops, 2);
        assert_eq!(adm.epoch_number, 0);
        assert_eq!(adm.root.vector_id, "vec-root");
        assert_eq!(adm.leaf_scope_hash, witness_scope_hash(&h.leaf_scope).unwrap());
    }

    #[test]
    fn failed_chain_does_not_burn_replay_nonces() {
        let mut h = harness(ContinuationMode::SingleUse);
        // Make hop 1 widen scope so the chain fails AT hop 1 (after the root + hop 0 were checked).
        h.chain.hops[1] = signed_hop(
            1,
            "vec-mid",
            "vec-leaf",
            scope(&["a", "b"]),
            scope(&["a", "b", "d"]),
            &h.leaf.public_key(),
            "hop1-nonce",
            ContinuationMode::SingleUse,
            &h.mid,
        );
        let mut guard = ReplayGuard::new();
        assert!(
            verify_delegated_admission(&h.token, &h.chain, &h.epoch, &h.pinned, &ctx(&h), &mut guard).is_err()
        );
        // No nonce (root or hop) may be consumed when the chain fails mid-walk.
        assert!(guard.is_empty(), "a failed chain must not burn any replay nonce");
    }

    #[test]
    fn widening_hop_is_denied() {
        let mut h = harness(ContinuationMode::SingleUse);
        // Replace hop 1 with a child scope that WIDENS the mid scope {a,b} by adding `d`.
        let widened = signed_hop(
            1,
            "vec-mid",
            "vec-leaf",
            scope(&["a", "b"]),
            scope(&["a", "b", "d"]),
            &h.leaf.public_key(),
            "hop1-nonce",
            ContinuationMode::SingleUse,
            &h.mid,
        );
        h.chain.hops[1] = widened;
        let err = verify_delegated_admission(
            &h.token,
            &h.chain,
            &h.epoch,
            &h.pinned,
            &ctx(&h),
            &mut ReplayGuard::new(),
        )
        .unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::WitnessScopeWidens)));
    }

    #[test]
    fn untrusted_root_witness_is_denied() {
        let mut h = harness(ContinuationMode::SingleUse);
        // Re-sign hop 0 with an attacker key (self-consistent, but not pinned).
        let attacker = Keypair::generate();
        let forged_root = signed_hop(
            0,
            "vec-root",
            "vec-mid",
            scope(&["a", "b", "c"]),
            scope(&["a", "b"]),
            &h.mid.public_key(),
            "hop0-nonce",
            ContinuationMode::SingleUse,
            &attacker,
        );
        h.chain.hops[0] = forged_root;
        let err = verify_delegated_admission(
            &h.token,
            &h.chain,
            &h.epoch,
            &h.pinned,
            &ctx(&h),
            &mut ReplayGuard::new(),
        )
        .unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::UntrustedWitnessIssuer)));
    }

    #[test]
    fn forged_root_signature_is_denied() {
        let h = harness(ContinuationMode::SingleUse);
        // Keep the operator DID as issuer but swap in a signature made by an attacker key.
        let attacker = Keypair::generate();
        let mut forged = h.chain.hops[0].clone();
        let body = delegation_witness_signature_body(&forged).unwrap();
        let canonical = canonical_json_string(&body).unwrap();
        forged.signature = attacker.sign(canonical.as_bytes()).to_hex();
        let mut chain = h.chain.clone();
        chain.hops[0] = forged;
        let err = verify_delegated_admission(
            &h.token,
            &chain,
            &h.epoch,
            &h.pinned,
            &ctx(&h),
            &mut ReplayGuard::new(),
        )
        .unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::WitnessSignatureInvalid)));
    }

    #[test]
    fn revoked_middle_hop_is_denied() {
        let h = harness(ContinuationMode::SingleUse);
        // Recall the middle vector (the child of hop 0) by bumping the signed epoch.
        let bumped = revoke_vector(&h.epoch, "vec-mid", NOW, NOW + WINDOW, &h.operator).unwrap();
        let err = verify_delegated_admission(
            &h.token,
            &h.chain,
            &bumped,
            &h.pinned,
            &ctx(&h),
            &mut ReplayGuard::new(),
        )
        .unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::WitnessVectorRevoked)));
    }

    #[test]
    fn tampered_scope_hash_is_denied() {
        let mut h = harness(ContinuationMode::SingleUse);
        // Flip the declared child hash on hop 1 without re-deriving it from the scope.
        h.chain.hops[1].child_scope_hash = "0".repeat(64);
        let err = verify_delegated_admission(
            &h.token,
            &h.chain,
            &h.epoch,
            &h.pinned,
            &ctx(&h),
            &mut ReplayGuard::new(),
        )
        .unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::WitnessScopeHashMismatch)));
    }

    #[test]
    fn single_use_hop_replay_is_denied() {
        // Resumable root so the second pass clears root admission and reaches the hop replay check.
        let h = harness(ContinuationMode::Resumable);
        let mut guard = ReplayGuard::new();
        assert!(
            verify_delegated_admission(
                &h.token,
                &h.chain,
                &h.epoch,
                &h.pinned,
                &ctx(&h),
                &mut guard,
            )
            .is_ok()
        );
        let err = verify_delegated_admission(
            &h.token,
            &h.chain,
            &h.epoch,
            &h.pinned,
            &ctx(&h),
            &mut guard,
        )
        .unwrap_err();
        assert!(matches!(err, AuthorityError::Denied(DenyReason::WitnessReplay)));
    }

    #[test]
    fn delegate_helper_rejects_widening() {
        let parent = Keypair::generate();
        let child = Keypair::generate();
        let req = DelegateRequest {
            chain_id: "chain-1".into(),
            operation_id: "op-1".into(),
            hop_index: 0,
            parent_vector_id: "vec-root".into(),
            child_vector_id: "vec-mid".into(),
            parent_scope: scope(&["a", "b"]),
            child_scope: scope(&["a", "b", "c"]), // widens
            delegatee: child.public_key(),
            nonce: "n".into(),
            mode: ContinuationMode::SingleUse,
            issued_at_unix_ms: NOW - 1_000,
            expires_at_unix_ms: NOW + WINDOW,
        };
        assert!(matches!(delegate(req, &parent), Err(AuthorityError::Invalid(_))));
    }
}
