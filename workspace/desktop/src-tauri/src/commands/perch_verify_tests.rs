use super::*;

use swarm_perch_wire::envelope::ENVELOPE_SCHEMA_V1;

/// A well-formed unsigned envelope whose hash is correct.
fn envelope(seq: u64, prev: Option<&str>) -> serde_json::Value {
    let mut value = serde_json::json!({
        "schema": ENVELOPE_SCHEMA_V1,
        "issuer": "swarm:ed25519:".to_string() + &"ab".repeat(32),
        "seq": seq,
        "prev_envelope_hash": prev,
        "issued_at": "2026-09-04T12:00:00Z",
        "capability_token": serde_json::Value::Null,
        "fact": { "schema": "swarm.finding.v1", "finding_id": "f1" },
        "envelope_hash": "",
    });
    let hash = compute_envelope_hash_hex(&value).expect("a hash");
    value["envelope_hash"] = serde_json::Value::String(hash);
    value
}

fn head_for(envelope: &serde_json::Value) -> IssuerChainHead {
    IssuerChainHead {
        issuer: envelope["issuer"].as_str().expect("issuer").to_string(),
        seq: envelope["seq"].as_u64().expect("seq"),
        envelope_hash: envelope["envelope_hash"]
            .as_str()
            .expect("hash")
            .to_string(),
    }
}

#[test]
fn an_unsigned_envelope_whose_hash_matches_is_tier_one() {
    // Tier 0 would be wrong: the keyless hash DOES prove the body was not
    // edited. Tier 2 would be wrong: nobody signed it.
    let verified = verify_envelope(&envelope(1, None), None).expect("verified");
    assert!(verified.hash_matches);
    assert!(!verified.signature_present);
    assert_eq!(verified.signature_valid, None);
    assert_eq!(verified.tier, 1);
    assert!(verified.reason.contains("carries no signature"));
}

#[test]
fn an_edited_body_is_tier_zero_and_says_so() {
    let mut value = envelope(1, None);
    value["fact"]["finding_id"] = serde_json::Value::String("f2".into());
    let verified = verify_envelope(&value, None).expect("verified");
    assert!(!verified.hash_matches);
    assert_eq!(verified.tier, 0);
    assert!(
        verified.reason.contains("changed after it was hashed"),
        "{}",
        verified.reason
    );
}

#[test]
fn a_signature_over_different_bytes_fails_rather_than_being_absent() {
    // A signature this console cannot verify must not read as "there was
    // nothing to check".
    let mut value = envelope(1, None);
    value["signature"] = serde_json::Value::String("cd".repeat(64));
    // The hash covers the envelope WITHOUT the signature, so it still matches.
    let verified = verify_envelope(&value, None).expect("verified");
    assert!(verified.hash_matches);
    assert!(verified.signature_present);
    assert_eq!(verified.signature_valid, Some(false));
    assert_eq!(verified.tier, 0);
}

#[test]
fn an_undecodable_issuer_fails_verification_rather_than_skipping_it() {
    let mut value = envelope(1, None);
    value["issuer"] = serde_json::Value::String("not-a-swarm-issuer".into());
    value["envelope_hash"] =
        serde_json::Value::String(compute_envelope_hash_hex(&value).expect("hash"));
    value["signature"] = serde_json::Value::String("cd".repeat(64));
    let verified = verify_envelope(&value, None).expect("verified");
    assert_eq!(verified.signature_valid, Some(false));
    assert_eq!(verified.tier, 0);
}

#[test]
fn a_real_signature_over_the_canonical_bytes_verifies() {
    use ed25519_dalek::{Signer as _, SigningKey};

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let issuer = format!(
        "swarm:ed25519:{}",
        signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut value = envelope(1, None);
    value["issuer"] = serde_json::Value::String(issuer);
    value["envelope_hash"] =
        serde_json::Value::String(compute_envelope_hash_hex(&value).expect("hash"));

    let unsigned = unsigned_envelope_value(&value).expect("unsigned");
    let bytes = canonical_bytes(&unsigned).expect("canonical");
    let signature = signing.sign(&bytes);
    value["signature"] = serde_json::Value::String(
        signature
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );

    let verified = verify_envelope(&value, None).expect("verified");
    assert!(verified.hash_matches);
    assert_eq!(verified.signature_valid, Some(true));
    // Signed and self-consistent, but no head: the first card from an issuer
    // continues nothing, and calling that a fork would make every cold start
    // look like an attack.
    assert_eq!(verified.tier, 1);
    assert!(
        verified.reason.contains("no earlier card from this issuer"),
        "{}",
        verified.reason
    );
    assert!(verified.reason.contains("the issuer signed this body"));
}

#[test]
fn the_three_chain_failures_are_reported_apart() {
    let first = envelope(1, None);
    let head = head_for(&first);

    // A gap: seq jumped.
    let gap = envelope(5, Some(&head.envelope_hash));
    assert_eq!(
        verify_envelope(&gap, Some(&head)).expect("v").chain,
        Some(ChainLinkVerdict::SequenceGap)
    );

    // A fork: right seq, wrong back-pointer.
    let fork = envelope(2, Some(&"00".repeat(32)));
    assert_eq!(
        verify_envelope(&fork, Some(&head)).expect("v").chain,
        Some(ChainLinkVerdict::HashMismatch)
    );

    // A different chain entirely.
    let mut other = envelope(2, Some(&head.envelope_hash));
    other["issuer"] = serde_json::Value::String(format!("swarm:ed25519:{}", "cd".repeat(32)));
    other["envelope_hash"] =
        serde_json::Value::String(compute_envelope_hash_hex(&other).expect("hash"));
    assert_eq!(
        verify_envelope(&other, Some(&head)).expect("v").chain,
        Some(ChainLinkVerdict::IssuerMismatch)
    );
}

#[test]
fn a_chain_failure_never_reaches_tier_two_but_keeps_the_signature_it_earned() {
    // An operator told only "invalid" cannot tell a gap from a fork, and the
    // two need different responses: go looking for a card, or distrust an
    // issuer. Both keep tier 1 — the body IS signed.
    let first = envelope(1, None);
    let head = head_for(&first);
    let gap = envelope(5, Some(&head.envelope_hash));
    let verified = verify_envelope(&gap, Some(&head)).expect("verified");
    assert_eq!(verified.tier, 1);
    assert!(
        verified.reason.contains("a card is missing"),
        "{}",
        verified.reason
    );
}

#[test]
fn a_broken_hash_outranks_everything_after_it() {
    // A signature over different bytes is still a valid signature -- over
    // something else. So the hash check comes first and its failure wins.
    let mut value = envelope(1, None);
    value["envelope_hash"] = serde_json::Value::String("00".repeat(32));
    value["signature"] = serde_json::Value::String("cd".repeat(64));
    let verified = verify_envelope(&value, None).expect("verified");
    assert_eq!(verified.tier, 0);
    assert!(verified.reason.contains("does not match its own bytes"));
}

#[test]
fn something_that_is_not_an_envelope_is_refused_rather_than_scored() {
    assert!(verify_envelope(&serde_json::json!({"hello": "world"}), None).is_err());
}

#[test]
fn an_unsigned_envelope_still_reports_a_broken_chain() {
    // The defect this test found: the unsigned branch ignored the chain, so a
    // missing card was hidden behind "carries no signature". A gap is a
    // missing card whether or not anyone signed the envelope.
    let first = envelope(1, None);
    let head = head_for(&first);
    let gap = envelope(5, Some(&head.envelope_hash));
    let verified = verify_envelope(&gap, Some(&head)).expect("verified");
    assert_eq!(verified.signature_valid, None);
    assert_eq!(verified.tier, 1);
    assert!(
        verified.reason.contains("carries no signature"),
        "{}",
        verified.reason
    );
    assert!(
        verified.reason.contains("a card is missing"),
        "{}",
        verified.reason
    );
}

#[test]
fn a_valid_link_on_an_unsigned_envelope_is_still_only_tier_one() {
    let first = envelope(1, None);
    let head = head_for(&first);
    let next = envelope(2, Some(&head.envelope_hash));
    let verified = verify_envelope(&next, Some(&head)).expect("verified");
    assert_eq!(verified.chain, Some(ChainLinkVerdict::Valid));
    // A chain of unsigned envelopes proves ordering, not authorship. Tier 2
    // requires the signature.
    assert_eq!(verified.tier, 1);
}
