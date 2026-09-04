//! Verifying a spine envelope, in the console's own process.
//!
//! LOCAL COMPUTATION. It issues no request to any host, so it is outside
//! INV-01 for the same reason the sidecar commands are: INV-01 is a claim
//! about the set of non-GET requests this process can make to a daemon, and
//! this one makes none.
//!
//! # What a tier means, and why three fields rather than a boolean
//!
//! A tier badge says an operator may rely on a chain of evidence, and there
//! are three independent ways that reliance can fail. The hash can disagree
//! with the bytes (the body was edited), the signature can fail (the issuer
//! did not sign these bytes), and the link can not continue the chain (a
//! replay, a gap, or a fork). An operator told only "invalid" cannot tell
//! which happened, and the three need different responses: re-fetch, distrust
//! the issuer, or go looking for the missing card.
//!
//! So the result carries all three, and the TIER is derived from them here
//! rather than in the renderer — a renderer that computed its own tier could
//! disagree with the one the badge names.

use serde::{Deserialize, Serialize};
use swarm_perch_wire::envelope::{
    canonical_bytes, compute_envelope_hash_hex, unsigned_envelope_value, verify_chain_link,
    CardEnvelope, ChainLinkVerdict, IssuerChainHead,
};

/// What the console learned about one envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerchEnvelopeVerification {
    /// The `envelope_hash` recomputed over the canonical bytes matches the one
    /// the envelope carries. Keyless: this alone proves the body was not
    /// edited after it was hashed.
    pub hash_matches: bool,
    /// The envelope carries a signature at all. `false` is not a failure — it
    /// is a tier-0 envelope, which is a real state and not a broken one.
    pub signature_present: bool,
    /// Ed25519 over the same canonical bytes verified against the issuer's
    /// key. `None` when there is no signature to check, so absent and failed
    /// stay apart.
    pub signature_valid: Option<bool>,
    /// Whether this link continues the chain the console last saw, and if not,
    /// how it failed. `None` when the console has no head for this issuer —
    /// the first card it ever sees continues nothing, and calling that a fork
    /// would make every cold start look like an attack.
    pub chain: Option<ChainLinkVerdict>,
    /// The tier this envelope supports, derived from the three above.
    pub tier: u8,
    /// Why the tier is what it is, in the console's own words.
    pub reason: String,
}

/// The issuer's Ed25519 key, decoded from `swarm:ed25519:{64 hex}`.
///
/// The prefix is required rather than tolerated: an issuer string that is bare
/// hex is a different identity format, and accepting one would let a card
/// choose which scheme verifies it.
fn issuer_verifying_key(issuer: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let hex = issuer.strip_prefix("swarm:ed25519:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        bytes[index] = u8::from_str_radix(text, 16).ok()?;
    }
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

fn decode_signature(signature: &str) -> Option<ed25519_dalek::Signature> {
    if signature.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for (index, pair) in signature.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        bytes[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(ed25519_dalek::Signature::from_bytes(&bytes))
}

/// Verify one envelope against an optional remembered chain head.
///
/// Pure, so the whole tier derivation is testable without a Tauri app.
pub fn verify_envelope(
    envelope: &serde_json::Value,
    head: Option<&IssuerChainHead>,
) -> Result<PerchEnvelopeVerification, String> {
    let parsed: CardEnvelope = serde_json::from_value(envelope.clone())
        .map_err(|error| format!("not a spine envelope: {error}"))?;

    // Keyless first. If the bytes do not hash to what the envelope claims,
    // nothing after it means anything — a signature over different bytes is
    // still a valid signature, over something else.
    let recomputed = compute_envelope_hash_hex(envelope)
        .map_err(|error| format!("could not hash the envelope: {error}"))?;
    let hash_matches = recomputed == parsed.envelope_hash;

    let signature_present = parsed.signature.is_some();
    let signature_valid = match parsed.signature.as_deref() {
        None => None,
        Some(signature) => {
            let unsigned = unsigned_envelope_value(envelope)
                .map_err(|error| format!("could not rebuild the signed bytes: {error}"))?;
            let bytes = canonical_bytes(&unsigned)
                .map_err(|error| format!("could not canonicalize: {error}"))?;
            Some(
                match (
                    issuer_verifying_key(&parsed.issuer),
                    decode_signature(signature),
                ) {
                    (Some(key), Some(signature)) => {
                        use ed25519_dalek::Verifier as _;
                        key.verify(&bytes, &signature).is_ok()
                    }
                    // An issuer or signature this console cannot decode is a
                    // failed verification, never an absent one: "we could not
                    // check" must not read as "there was nothing to check".
                    _ => false,
                },
            )
        }
    };

    let chain = head.map(|head| verify_chain_link(head, &parsed));

    let (tier, reason) = derive_tier(hash_matches, signature_valid, chain.as_ref());
    Ok(PerchEnvelopeVerification {
        hash_matches,
        signature_present,
        signature_valid,
        chain,
        tier,
        reason,
    })
}

/// The tier, and the sentence that explains it.
///
/// Tier 2 requires all three: the bytes hash, the issuer signed them, and the
/// link continues the chain. Any one missing drops the claim rather than
/// discounting it, because a partial chain of evidence is not a weaker
/// guarantee — it is a different one, and the badge must not blur them.
///
/// A BROKEN CHAIN IS REPORTED WHETHER OR NOT THE ENVELOPE IS SIGNED. A gap is
/// a missing card either way, and an unsigned envelope whose reason mentioned
/// only the missing signature would hide it.
fn derive_tier(
    hash_matches: bool,
    signature_valid: Option<bool>,
    chain: Option<&ChainLinkVerdict>,
) -> (u8, String) {
    if !hash_matches {
        return (
            0,
            "the envelope hash does not match its own bytes; this body was changed after it was \
             hashed"
                .to_string(),
        );
    }
    if signature_valid == Some(false) {
        return (
            0,
            "the signature does not verify against the issuer's key".to_string(),
        );
    }

    let signed = signature_valid == Some(true);
    let head = if signed {
        "the issuer signed this body"
    } else {
        "attestation matches this body; the envelope carries no signature"
    };

    let chain_note = match chain {
        Some(ChainLinkVerdict::Valid) => None,
        Some(ChainLinkVerdict::SequenceGap) => {
            Some("a card is missing between it and the last one seen")
        }
        Some(ChainLinkVerdict::HashMismatch) => {
            Some("it does not follow the last card seen — two chains claim the same position")
        }
        Some(ChainLinkVerdict::IssuerMismatch) => {
            Some("it belongs to a different chain than the last card seen")
        }
        // The first card from an issuer continues nothing, and calling that a
        // fork would make every cold start look like an attack.
        None => Some(
            "no earlier card from this issuer has been seen, so the chain is not yet established",
        ),
    };

    match (signed, chain_note) {
        (true, None) => (
            2,
            "attestation matches this body, the issuer signed it, and it continues the chain"
                .to_string(),
        ),
        (_, None) => (1, head.to_string()),
        (_, Some(note)) => (1, format!("{head}, but {note}")),
    }
}

#[tauri::command]
pub async fn perch_verify_envelope(
    envelope: serde_json::Value,
    head: Option<IssuerChainHead>,
) -> Result<PerchEnvelopeVerification, String> {
    verify_envelope(&envelope, head.as_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "perch_verify_tests.rs"]
mod tests;
