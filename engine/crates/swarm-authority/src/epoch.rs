//! The per-operation signed revocation epoch — the recall ledger.

use serde::{Deserialize, Serialize};
use swarm_crypto::{Keypair, PublicKey, Signature, canonical_json_string};

use crate::error::{AuthorityError, DenyReason};
use crate::util::{digest_hex, is_pinned, issuer_did, issuer_public_key, require_non_empty, signature_body};

pub const REVOCATION_EPOCH_SCHEMA: &str = "ambush.swarm.revocation-epoch.v1";

/// The recall ledger for one operation. Recall = `revoke_vector`/`revoke_token` -> new epoch with
/// `epoch_number + 1` and the subject added to the revoked set, re-signed. `genesis_root_hash` is
/// the stable lineage anchor pinned into every token at issue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmRevocationEpoch {
    pub schema: String,
    pub epoch_id: String,
    pub epoch_number: u64,
    pub operation_id: String,
    pub genesis_root_hash: String,
    pub revoked_vector_ids: Vec<String>,
    pub revoked_token_ids: Vec<String>,
    pub root_hash: String,
    pub issued_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub issuer: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct OpenEpochRequest {
    pub epoch_id: String,
    pub operation_id: String,
    pub issued_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
}

/// Stable lineage anchor: sha256 over the lineage identity only (id + operation). Non-circular.
pub fn lineage_anchor(epoch_id: &str, operation_id: &str) -> Result<String, AuthorityError> {
    digest_hex(&serde_json::json!({ "epochId": epoch_id, "operationId": operation_id }))
}

/// Recompute an epoch's `root_hash` over its content with `rootHash` and `signature` removed.
pub fn epoch_root_hash(epoch: &SwarmRevocationEpoch) -> Result<String, AuthorityError> {
    let mut body = serde_json::to_value(epoch).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    let obj = body.as_object_mut().ok_or_else(|| AuthorityError::Canonical("epoch not object".into()))?;
    obj.remove("rootHash");
    obj.remove("signature");
    digest_hex(&body)
}

pub fn revocation_epoch_signature_body(
    epoch: &SwarmRevocationEpoch,
) -> Result<serde_json::Value, AuthorityError> {
    signature_body(epoch, "revocation epoch signature body")
}

pub fn sign_revocation_epoch(epoch: &SwarmRevocationEpoch, signer: &Keypair) -> Result<String, AuthorityError> {
    let issuer_key = issuer_public_key(&epoch.issuer).map_err(AuthorityError::Denied)?;
    if issuer_key != signer.public_key() {
        return Err(AuthorityError::Invalid("epoch signer does not match issuer".into()));
    }
    let body = revocation_epoch_signature_body(epoch)?;
    let canonical = canonical_json_string(&body).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    Ok(signer.sign(canonical.as_bytes()).to_hex())
}

/// Open the genesis epoch (number 0, empty revoked sets) for an operation.
pub fn open_epoch(req: OpenEpochRequest, signer: &Keypair) -> Result<SwarmRevocationEpoch, AuthorityError> {
    require_non_empty(&req.epoch_id, "epoch id")?;
    require_non_empty(&req.operation_id, "operation id")?;
    if req.valid_until_unix_ms <= req.issued_at_unix_ms {
        return Err(AuthorityError::Invalid("epoch valid_until must be after issued_at".into()));
    }
    let anchor = lineage_anchor(&req.epoch_id, &req.operation_id)?;
    let mut epoch = SwarmRevocationEpoch {
        schema: REVOCATION_EPOCH_SCHEMA.to_string(),
        epoch_id: req.epoch_id,
        epoch_number: 0,
        operation_id: req.operation_id,
        genesis_root_hash: anchor,
        revoked_vector_ids: Vec::new(),
        revoked_token_ids: Vec::new(),
        root_hash: String::new(),
        issued_at_unix_ms: req.issued_at_unix_ms,
        valid_until_unix_ms: req.valid_until_unix_ms,
        issuer: issuer_did(&signer.public_key()),
        signature: String::new(),
    };
    epoch.root_hash = epoch_root_hash(&epoch)?;
    epoch.signature = sign_revocation_epoch(&epoch, signer)?;
    Ok(epoch)
}

/// Recall a Vector: bump number, add to revoked-vector set, recompute root, re-sign.
pub fn revoke_vector(
    current: &SwarmRevocationEpoch,
    vector_id: &str,
    now_unix_ms: u64,
    valid_until_unix_ms: u64,
    signer: &Keypair,
) -> Result<SwarmRevocationEpoch, AuthorityError> {
    bump(current, Some(vector_id), None, now_unix_ms, valid_until_unix_ms, signer)
}

/// Targeted recall of a single token id.
pub fn revoke_token(
    current: &SwarmRevocationEpoch,
    token_id: &str,
    now_unix_ms: u64,
    valid_until_unix_ms: u64,
    signer: &Keypair,
) -> Result<SwarmRevocationEpoch, AuthorityError> {
    bump(current, None, Some(token_id), now_unix_ms, valid_until_unix_ms, signer)
}

fn bump(
    current: &SwarmRevocationEpoch,
    add_vector: Option<&str>,
    add_token: Option<&str>,
    now_unix_ms: u64,
    valid_until_unix_ms: u64,
    signer: &Keypair,
) -> Result<SwarmRevocationEpoch, AuthorityError> {
    if valid_until_unix_ms <= now_unix_ms {
        return Err(AuthorityError::Invalid("epoch valid_until must be after now".into()));
    }
    let mut next = current.clone();
    next.epoch_number = current
        .epoch_number
        .checked_add(1)
        .ok_or_else(|| AuthorityError::Invalid("epoch number overflow".into()))?;
    if let Some(v) = add_vector
        && !next.revoked_vector_ids.iter().any(|x| x == v)
    {
        next.revoked_vector_ids.push(v.to_string());
    }
    if let Some(t) = add_token
        && !next.revoked_token_ids.iter().any(|x| x == t)
    {
        next.revoked_token_ids.push(t.to_string());
    }
    next.revoked_vector_ids.sort();
    next.revoked_vector_ids.dedup();
    next.revoked_token_ids.sort();
    next.revoked_token_ids.dedup();
    next.issued_at_unix_ms = now_unix_ms;
    next.valid_until_unix_ms = valid_until_unix_ms;
    next.issuer = issuer_did(&signer.public_key());
    next.signature = String::new();
    next.root_hash = epoch_root_hash(&next)?; // genesis_root_hash preserved from `current`
    next.signature = sign_revocation_epoch(&next, signer)?;
    Ok(next)
}

/// Verify an epoch: pinned issuer, recomputed root hash (tamper), valid signature.
pub(crate) fn verify_epoch(epoch: &SwarmRevocationEpoch, trusted_keys: &[PublicKey]) -> Result<(), AuthorityError> {
    if epoch.schema != REVOCATION_EPOCH_SCHEMA {
        return Err(AuthorityError::denied(DenyReason::UnsupportedSchema(epoch.schema.clone())));
    }
    let key = issuer_public_key(&epoch.issuer).map_err(AuthorityError::Denied)?;
    if !is_pinned(&key, trusted_keys) {
        return Err(AuthorityError::denied(DenyReason::UntrustedEpochIssuer));
    }
    if epoch_root_hash(epoch)? != epoch.root_hash {
        return Err(AuthorityError::denied(DenyReason::EpochTampered));
    }
    let sig = Signature::from_hex(&epoch.signature)
        .map_err(|_| AuthorityError::denied(DenyReason::EpochSignatureInvalid))?;
    let body = revocation_epoch_signature_body(epoch)?;
    let canonical = canonical_json_string(&body).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    if key.verify(canonical.as_bytes(), &sig) {
        Ok(())
    } else {
        Err(AuthorityError::denied(DenyReason::EpochSignatureInvalid))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn open() -> (Keypair, SwarmRevocationEpoch) {
        let signer = Keypair::generate();
        let epoch = open_epoch(
            OpenEpochRequest {
                epoch_id: "ep-1".into(),
                operation_id: "op-1".into(),
                issued_at_unix_ms: 1_000,
                valid_until_unix_ms: 100_000,
            },
            &signer,
        )
        .unwrap();
        (signer, epoch)
    }

    #[test]
    fn genesis_self_roots_and_verifies() {
        let (signer, epoch) = open();
        assert_eq!(epoch.epoch_number, 0);
        assert_eq!(epoch_root_hash(&epoch).unwrap(), epoch.root_hash);
        assert!(verify_epoch(&epoch, &[signer.public_key()]).is_ok());
    }

    #[test]
    fn revoke_bumps_preserves_anchor_and_reverifies() {
        let (signer, epoch) = open();
        let anchor = epoch.genesis_root_hash.clone();
        let bumped = revoke_vector(&epoch, "vec-01", 2_000, 100_000, &signer).unwrap();
        assert_eq!(bumped.epoch_number, 1);
        assert_eq!(bumped.genesis_root_hash, anchor);
        assert!(bumped.revoked_vector_ids.contains(&"vec-01".to_string()));
        assert!(verify_epoch(&bumped, &[signer.public_key()]).is_ok());
    }
}
