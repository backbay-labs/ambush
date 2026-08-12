//! Signature envelopes for portable review capsules and delegation packets.

use super::types::{
    ReviewCapsule, ReviewDelegationPacket, ReviewSessionExport, ReviewSessionResolved,
};
use serde::Serialize;
use swarm_crypto::{CryptoError, Ed25519Signer, canonical_json_bytes};
use swarm_evolution::evidence::{EvidenceRelatedRef, EvidenceSignature};

#[derive(Debug, Serialize)]
struct ReviewCapsuleSignatureStatement<'a> {
    capsule_id: &'a str,
    schema_version: &'a str,
    created_at_ms: i64,
    session_id: &'a str,
    source_kind: &'a str,
    source_id: &'a str,
    payload_sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct ReviewDelegationSignatureStatement<'a> {
    delegation_id: &'a str,
    schema_version: &'a str,
    created_at_ms: i64,
    session_id: &'a str,
    source_kind: &'a str,
    source_capsule_id: &'a str,
    source_import_id: Option<&'a str>,
    payload_sha256: &'a str,
}

pub(super) fn collect_related_refs_from_export(
    export: &ReviewSessionExport,
) -> Vec<EvidenceRelatedRef> {
    let mut refs = Vec::new();
    for bundle in &export.evidence_bundles {
        push_unique_related_ref(
            &mut refs,
            bundle.subject_kind.as_str(),
            bundle.subject_id.clone(),
        );
        push_unique_related_ref(&mut refs, "evidence_bundle", bundle.bundle_id.clone());
        if let Some(verification_id) = bundle.latest_verification_id.as_ref() {
            push_unique_related_ref(&mut refs, "evidence_verification", verification_id.clone());
        }
        for related in &bundle.related_refs {
            push_unique_related_ref(&mut refs, &related.kind, related.id.clone());
        }
    }
    for packet in &export.promotion_packets {
        push_unique_related_ref(
            &mut refs,
            "promotion_evidence_packet",
            packet.packet_id.clone(),
        );
        push_unique_related_ref(
            &mut refs,
            "production_promotion",
            packet.promotion_id.clone(),
        );
        push_unique_related_ref(&mut refs, "canary_run", packet.canary_run_id.clone());
        push_unique_related_ref(
            &mut refs,
            "evidence_verification",
            packet.verification_id.clone(),
        );
        push_unique_related_ref(&mut refs, "strategy_shadow", packet.shadow_id.clone());
    }
    refs
}

pub(super) fn collect_related_refs_from_resolved(
    resolved: &ReviewSessionResolved,
) -> Vec<EvidenceRelatedRef> {
    let mut refs = Vec::new();
    for bundle in &resolved.evidence_bundles {
        push_unique_related_ref(
            &mut refs,
            bundle.record.subject_kind.as_str(),
            bundle.record.subject_id.clone(),
        );
        push_unique_related_ref(
            &mut refs,
            "evidence_bundle",
            bundle.record.bundle_id.clone(),
        );
        if let Some(verification_id) = bundle.record.latest_verification_id.as_ref() {
            push_unique_related_ref(&mut refs, "evidence_verification", verification_id.clone());
        }
        for related in &bundle.bundle.subject.related_refs {
            push_unique_related_ref(&mut refs, &related.kind, related.id.clone());
        }
    }
    for packet in &resolved.promotion_packets {
        push_unique_related_ref(
            &mut refs,
            "promotion_evidence_packet",
            packet.packet.packet_id.clone(),
        );
        push_unique_related_ref(
            &mut refs,
            "production_promotion",
            packet.packet.promotion_id.clone(),
        );
    }
    refs
}

fn push_unique_related_ref(
    target: &mut Vec<EvidenceRelatedRef>,
    kind: impl Into<String>,
    id: impl Into<String>,
) {
    let kind = kind.into();
    let id = id.into();
    if kind.trim().is_empty() || id.trim().is_empty() {
        return;
    }
    if !target
        .iter()
        .any(|existing| existing.kind == kind && existing.id == id)
    {
        target.push(EvidenceRelatedRef { kind, id });
    }
}

pub(super) fn review_capsule_signature_statement_bytes(
    capsule: &ReviewCapsule,
) -> Result<Vec<u8>, CryptoError> {
    canonical_json_bytes(&ReviewCapsuleSignatureStatement {
        capsule_id: &capsule.capsule_id,
        schema_version: &capsule.schema_version,
        created_at_ms: capsule.created_at_ms,
        session_id: &capsule.session_id,
        source_kind: capsule.source_kind.as_str(),
        source_id: &capsule.source_id,
        payload_sha256: &capsule.payload_sha256,
    })
}

pub(super) fn review_delegation_signature_statement_bytes(
    packet: &ReviewDelegationPacket,
) -> Result<Vec<u8>, CryptoError> {
    canonical_json_bytes(&ReviewDelegationSignatureStatement {
        delegation_id: &packet.delegation_id,
        schema_version: &packet.schema_version,
        created_at_ms: packet.created_at_ms,
        session_id: &packet.session_id,
        source_kind: packet.source_kind.as_str(),
        source_capsule_id: &packet.source_capsule_id,
        source_import_id: packet.source_import_id.as_deref(),
        payload_sha256: &packet.payload_sha256,
    })
}

pub(super) fn signature_from_detached(
    signer_id: String,
    detached: swarm_crypto::DetachedSignature,
) -> EvidenceSignature {
    EvidenceSignature {
        signer_id,
        algorithm: detached.algorithm,
        key_id: detached.key_id,
        public_key_hex: detached.public_key_hex,
        signature_hex: detached.signature_hex,
    }
}

pub(super) fn signature_to_detached(
    signature: &EvidenceSignature,
) -> swarm_crypto::DetachedSignature {
    swarm_crypto::DetachedSignature {
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        public_key_hex: signature.public_key_hex.clone(),
        signature_hex: signature.signature_hex.clone(),
    }
}

pub(super) fn resolve_trusted_key_id(
    signing_key_env: &str,
    expected_key_id: Option<&str>,
) -> Option<String> {
    if let Some(expected_key_id) = expected_key_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(expected_key_id.to_string());
    }
    std::env::var(signing_key_env)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|secret_material| Ed25519Signer::from_secret_material(&secret_material))
        .map(|signer| signer.key_id().to_string())
}

pub(super) fn empty_signature_placeholder() -> EvidenceSignature {
    EvidenceSignature {
        signer_id: String::new(),
        algorithm: String::new(),
        key_id: String::new(),
        public_key_hex: String::new(),
        signature_hex: String::new(),
    }
}
