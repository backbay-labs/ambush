//! Negative falsifiability tests for the `swarm-spine` rows of
//! `docs/assurance/MAPPING.md` (FALSIFY-02).
//!
//! See the header of `crates/swarm-policy/tests/negative_policy_gates.rs` for
//! the three-step shape every test in this family follows (real function
//! denies; unmutated mirror reproduces it; mutated mirror permits).
//!
//! # Why the envelope rows are two rows and not one
//!
//! `verify_envelope` carries two independent checks and NEITHER implies the
//! other, which is only visible once you look at what is signed:
//! `envelope_signing_bytes` canonicalizes the envelope with `envelope_hash` and
//! `signature` REMOVED. So
//!
//!   - rewriting `envelope_hash` alone leaves the signature verifying, and only
//!     the hash comparison refuses it; and
//!   - rewriting `issuer` and recomputing `envelope_hash` -- which any attacker
//!     can do, sha256 needs no key -- leaves the hash comparison satisfied, and
//!     only the signature check refuses it.
//!
//! One test per check, each mutating only the check it is about.

#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate swarm_spine as __phase285_swarm_spine;

#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;

use serde_json::{Value, json};
use swarm_crypto::hashing::sha256_hex as sha256_hex_prefixed;
use swarm_crypto::{Keypair, PublicKey, Signature};
use swarm_spine::chain::{ChainLinkVerdict, IssuerChainHead, verify_chain_link};
use swarm_spine::envelope::{
    build_signed_envelope, envelope_signing_bytes, parse_issuer_pubkey_hex, verify_envelope,
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// A fixed seed, so a failure names a reproducible envelope rather than a
/// different random one each run.
fn signing_keypair(seed_byte: u8) -> Keypair {
    Keypair::from_seed(&[seed_byte; 32])
}

fn envelope(keypair: &Keypair, seq: u64, prev: Option<String>) -> Value {
    build_signed_envelope(
        keypair,
        seq,
        prev,
        json!({"type": "policy.update", "data": {"version": seq}}),
        "2026-08-13T00:00:00Z".to_string(),
    )
    .expect("the fixture envelope is well formed")
}

fn envelope_hash_of(envelope: &Value) -> String {
    envelope
        .get("envelope_hash")
        .and_then(Value::as_str)
        .expect("a signed envelope carries its hash")
        .to_string()
}

// ---------------------------------------------------------------------------
// The mirror of `swarm_spine::envelope::verify_envelope`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeMutation {
    /// No mutation. The control.
    None,
    /// The `computed_hash != claimed_hash` comparison deleted.
    SkipHashBinding,
    /// The final `public_key.verify(..)` replaced by an unconditional `true`.
    SkipSignatureCheck,
    /// A missing `envelope_hash` is defaulted to the computed digest.
    SkipHashFieldRequired,
    /// A missing issuer is recovered from the authentic signing key.
    SkipIssuerFieldRequired,
    /// A missing signature is recovered from the authentic signing key.
    SkipSignatureFieldRequired,
    /// Malformed issuer material is replaced by the authentic issuer.
    SkipIssuerKeyValidation,
    /// Malformed signature material is replaced by an authentic signature.
    SkipSignatureWellFormed,
}

/// Mirror of `verify_envelope`, copied from
/// `crates/swarm-spine/src/envelope.rs` with one check removable.
///
/// Returns `Ok(true)` for "this envelope is accepted", matching the real
/// function's contract: `Err` and `Ok(false)` are both refusals, and only
/// `Ok(true)` admits an envelope into a chain.
fn mirrored_verify_envelope(envelope: &Value, mutation: EnvelopeMutation) -> Result<bool, String> {
    let mut working = envelope.clone();
    if matches!(
        mutation,
        EnvelopeMutation::SkipIssuerFieldRequired | EnvelopeMutation::SkipIssuerKeyValidation
    ) {
        working["issuer"] = json!(format!(
            "swarm:ed25519:{}",
            signing_keypair(7).public_key().to_hex()
        ));
    }
    let issuer = working
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or("missing issuer")?;
    let signature_hex = working.get("signature").and_then(Value::as_str);
    if signature_hex.is_none() && mutation != EnvelopeMutation::SkipSignatureFieldRequired {
        return Err("missing signature".to_string());
    }
    let claimed_hash = working
        .get("envelope_hash")
        .and_then(Value::as_str)
        .map(str::to_string);
    if claimed_hash.is_none() && mutation != EnvelopeMutation::SkipHashFieldRequired {
        return Err("missing envelope_hash".to_string());
    }

    let pubkey_hex = parse_issuer_pubkey_hex(issuer).map_err(|error| error.to_string())?;
    let public_key = PublicKey::from_hex(&pubkey_hex).map_err(|error| error.to_string())?;
    let mut unsigned = working.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("envelope_hash");
        object.remove("signature");
    }

    let bytes = envelope_signing_bytes(&unsigned).map_err(|error| error.to_string())?;
    let signature = match signature_hex {
        Some(value) => match Signature::from_hex(value) {
            Ok(signature) => signature,
            Err(_) if mutation == EnvelopeMutation::SkipSignatureWellFormed => {
                signing_keypair(7).sign(&bytes)
            }
            Err(error) => return Err(error.to_string()),
        },
        None if mutation == EnvelopeMutation::SkipSignatureFieldRequired => {
            signing_keypair(7).sign(&bytes)
        }
        None => return Err("missing signature".to_string()),
    };
    let computed_hash = sha256_hex_prefixed(&bytes);
    let claimed_hash = claimed_hash.unwrap_or_else(|| computed_hash.clone());
    if mutation != EnvelopeMutation::SkipHashBinding && computed_hash != claimed_hash {
        return Err(format!(
            "hash mismatch: expected {claimed_hash}, computed {computed_hash}"
        ));
    }

    if mutation == EnvelopeMutation::SkipSignatureCheck {
        return Ok(true);
    }
    Ok(public_key.verify(&bytes, &signature))
}

// ---------------------------------------------------------------------------
// SPINE-ENVELOPE-HASH-FIELD-REQUIRED
// ---------------------------------------------------------------------------

#[test]
fn broken_hash_field_requirement_admits_an_envelope_with_no_claimed_identity() {
    let keypair = signing_keypair(7);
    let mut missing = envelope(&keypair, 1, None);
    missing.as_object_mut().unwrap().remove("envelope_hash");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_HASH_FIELD_REQUIRED,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipHashFieldRequired,
        state: {},
        probe: Value = missing,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

fn admitted(result: &Result<bool, String>) -> bool {
    matches!(result, Ok(true))
}

// ---------------------------------------------------------------------------
// SPINE-ENVELOPE-HASH-BOUND
// ---------------------------------------------------------------------------

#[test]
fn broken_hash_binding_admits_the_forged_envelope_id_the_real_verifier_refuses() {
    let keypair = signing_keypair(7);
    let mut forged = envelope(&keypair, 1, None);
    let genuine_hash = envelope_hash_of(&forged);

    // The attacker does not touch the body and does not touch the signature.
    // Only the envelope's IDENTITY is rewritten -- and that identity is what
    // `chain_head_from_envelope` records and what the next envelope's
    // `prev_envelope_hash` has to match, so choosing it freely is choosing where
    // the chain points.
    let forged_hash = "0x".to_string() + &"ab".repeat(32);
    assert_ne!(forged_hash, genuine_hash);
    forged["envelope_hash"] = json!(forged_hash);

    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_HASH_BOUND,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipHashBinding,
        state: {},
        probe: Value = forged,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }

    // Control in the other direction: the untouched envelope is admitted by
    // both. Without this, a verifier that refused everything would pass the
    // assertions above.
    let genuine = envelope(&keypair, 1, None);
    assert!(verify_envelope(&genuine).expect("a well-formed envelope verifies"));
    assert!(admitted(&mirrored_verify_envelope(
        &genuine,
        EnvelopeMutation::None
    )));
}

// ---------------------------------------------------------------------------
// SPINE-ENVELOPE-{ISSUER,SIGNATURE}-FIELD-REQUIRED and decoding guards
// ---------------------------------------------------------------------------

#[test]
fn broken_issuer_field_requirement_accepts_an_envelope_with_no_issuer() {
    let keypair = signing_keypair(7);
    let mut missing = envelope(&keypair, 1, None);
    missing.as_object_mut().unwrap().remove("issuer");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_ISSUER_FIELD_REQUIRED,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipIssuerFieldRequired,
        state: {},
        probe: Value = missing,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_signature_field_requirement_accepts_an_unsigned_envelope() {
    let keypair = signing_keypair(7);
    let mut missing = envelope(&keypair, 1, None);
    missing.as_object_mut().unwrap().remove("signature");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_SIGNATURE_FIELD_REQUIRED,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipSignatureFieldRequired,
        state: {},
        probe: Value = missing,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_issuer_key_validation_accepts_malformed_key_material() {
    let keypair = signing_keypair(7);
    let mut malformed = envelope(&keypair, 1, None);
    malformed["issuer"] = json!("swarm:ed25519:not-a-key");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_ISSUER_KEY_VALID,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipIssuerKeyValidation,
        state: {},
        probe: Value = malformed,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_signature_decoding_accepts_malformed_signature_material() {
    let keypair = signing_keypair(7);
    let mut malformed = envelope(&keypair, 1, None);
    malformed["signature"] = json!("not-a-signature");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_SIGNATURE_WELL_FORMED,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipSignatureWellFormed,
        state: {},
        probe: Value = malformed,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// SPINE-ENVELOPE-SIGNATURE-VALID
// ---------------------------------------------------------------------------

#[test]
fn broken_signature_check_admits_the_reattributed_envelope_the_real_verifier_refuses() {
    let author = signing_keypair(7);
    let victim = signing_keypair(9);
    assert_ne!(author.public_key().to_hex(), victim.public_key().to_hex());

    // The author signs a fact, then the envelope is re-attributed to the victim
    // and its hash RECOMPUTED so the hash binding is satisfied. sha256 needs no
    // key, so this is inside any tamperer's reach; the signature check is the
    // only thing standing in the way.
    let mut forged = envelope(&author, 1, None);
    forged["issuer"] = json!(format!("swarm:ed25519:{}", victim.public_key().to_hex()));
    let mut unsigned = forged.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("envelope_hash");
        object.remove("signature");
    }
    let recomputed = sha256_hex_prefixed(&envelope_signing_bytes(&unsigned).unwrap());
    forged["envelope_hash"] = json!(recomputed);

    negative_protocol::assert_registered_negative_case! {
        case: SPINE_ENVELOPE_SIGNATURE_VALID,
        mutation: EnvelopeMutation,
        control: EnvelopeMutation::None,
        broken: EnvelopeMutation::SkipSignatureCheck,
        state: {},
        probe: Value = forged,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::envelope::verify_envelope,
        arguments: (probe),
        call: sync,
        normalize: |production_result| production_result.unwrap_or(false),
        mirror: |_state, probe, mutation| admitted(&mirrored_verify_envelope(probe, mutation)),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// The mirror of `swarm_spine::chain::verify_chain_link`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainMutation {
    /// No mutation. The control.
    None,
    /// The `seq != 1` guard on a new chain deleted.
    SkipFirstSequence,
    /// The `prev_hash_str.is_some()` guard on a new chain deleted.
    SkipFirstPreviousHash,
    /// The `envelope_issuer_norm != head_issuer_norm` guard deleted.
    SkipIssuerBinding,
    /// The `seq != expected_seq` guard deleted.
    SkipSequenceBinding,
    /// The `actual_prev_hash != head.envelope_hash` guard deleted.
    SkipPrevHashBinding,
    /// A missing `prev_envelope_hash` field is treated as JSON null.
    SkipPreviousHashFieldRequired,
    /// A missing issuer is recovered from the held head.
    SkipIssuerFieldRequired,
    /// A missing sequence is recovered from the expected next value.
    SkipSequenceFieldRequired,
    /// A non-string predecessor is recovered from the held head.
    SkipPreviousHashTypeValidation,
    /// Head increment uses wrapping arithmetic instead of refusing overflow.
    WrapHeadSequence,
}

/// Mirror of `verify_chain_link`, copied from
/// `crates/swarm-spine/src/chain.rs` with one guard removable.
fn mirrored_verify_chain_link(
    envelope: &Value,
    known_head: Option<&IssuerChainHead>,
    mutation: ChainMutation,
) -> Result<ChainLinkVerdict, String> {
    let envelope_issuer = match envelope.get("issuer").and_then(Value::as_str) {
        Some(issuer) => issuer.to_string(),
        None if mutation == ChainMutation::SkipIssuerFieldRequired => known_head
            .map(|head| head.issuer.clone())
            .unwrap_or_else(|| {
                format!("swarm:ed25519:{}", signing_keypair(7).public_key().to_hex())
            }),
        None => return Err("missing issuer".to_string()),
    };
    let seq = match envelope.get("seq").and_then(Value::as_u64) {
        Some(seq) => seq,
        None if mutation == ChainMutation::SkipSequenceFieldRequired => known_head
            .map(|head| head.seq.saturating_add(1))
            .unwrap_or(1),
        None => return Err("missing seq".to_string()),
    };
    let missing_prev = Value::Null;
    let prev_hash = match envelope.get("prev_envelope_hash") {
        Some(value) => value,
        None if mutation == ChainMutation::SkipPreviousHashFieldRequired => &missing_prev,
        None => return Err("missing prev_envelope_hash".to_string()),
    };

    let prev_hash_str: Option<String> = if prev_hash.is_null() {
        None
    } else {
        match prev_hash.as_str() {
            Some(value) => Some(value.to_string()),
            None if mutation == ChainMutation::SkipPreviousHashTypeValidation => {
                known_head.map(|head| head.envelope_hash.clone())
            }
            None => return Err("prev_envelope_hash is not a string".to_string()),
        }
    };

    let normalize = |issuer: &str| {
        parse_issuer_pubkey_hex(issuer)
            .map(|hex| hex.to_ascii_lowercase())
            .unwrap_or_else(|_| issuer.to_ascii_lowercase())
    };

    match known_head {
        None => {
            if mutation != ChainMutation::SkipFirstSequence && seq != 1 {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!("first envelope must have seq=1, got seq={seq}"),
                });
            }
            if mutation != ChainMutation::SkipFirstPreviousHash && prev_hash_str.is_some() {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: "first envelope must have null prev_envelope_hash".to_string(),
                });
            }
            Ok(ChainLinkVerdict::NewChain)
        }
        Some(head) => {
            if mutation != ChainMutation::SkipIssuerBinding
                && normalize(&envelope_issuer) != normalize(&head.issuer)
            {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!(
                        "issuer mismatch: envelope issuer {envelope_issuer} does not match \
                         head issuer {}",
                        head.issuer
                    ),
                });
            }

            let expected_seq = if mutation == ChainMutation::WrapHeadSequence {
                head.seq.wrapping_add(1)
            } else {
                let Some(expected_seq) = head.seq.checked_add(1) else {
                    return Ok(ChainLinkVerdict::InvalidChainHead {
                        reason: format!("known head sequence overflow for issuer {}", head.issuer),
                    });
                };
                expected_seq
            };
            if mutation != ChainMutation::SkipSequenceBinding && seq != expected_seq {
                return Ok(ChainLinkVerdict::SequenceMismatch {
                    expected_seq,
                    actual_seq: seq,
                });
            }

            let actual_prev_hash = prev_hash_str.as_deref().unwrap_or("");
            if mutation != ChainMutation::SkipPrevHashBinding
                && actual_prev_hash != head.envelope_hash
            {
                return Ok(ChainLinkVerdict::HashMismatch {
                    expected_prev_hash: head.envelope_hash.clone(),
                    actual_prev_hash: actual_prev_hash.to_string(),
                });
            }

            Ok(ChainLinkVerdict::ValidContinuation)
        }
    }
}

struct ChainProbe {
    envelope: Value,
    head: Option<IssuerChainHead>,
}

fn mirrored_chain_admitted(probe: &ChainProbe, mutation: ChainMutation) -> bool {
    mirrored_verify_chain_link(&probe.envelope, probe.head.as_ref(), mutation)
        .map(|verdict| verdict.is_valid())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-PREV-FIELD-REQUIRED
// ---------------------------------------------------------------------------

#[test]
fn broken_previous_hash_field_requirement_admits_an_ambiguous_first_link() {
    let keypair = signing_keypair(7);
    let mut missing = envelope(&keypair, 1, None);
    missing
        .as_object_mut()
        .unwrap()
        .remove("prev_envelope_hash");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_PREV_FIELD_REQUIRED,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipPreviousHashFieldRequired,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: missing, head: None },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-HEAD-NOT-OVERFLOWED
// ---------------------------------------------------------------------------

#[test]
fn broken_head_overflow_guard_wraps_the_chain_back_to_zero() {
    let keypair = signing_keypair(7);
    let head = IssuerChainHead {
        issuer: format!("swarm:ed25519:{}", keypair.public_key().to_hex()),
        seq: u64::MAX,
        envelope_hash: "0x".to_string() + &"aa".repeat(32),
    };
    let wrapped = envelope(&keypair, 0, Some(head.envelope_hash.clone()));
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_HEAD_NOT_OVERFLOWED,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::WrapHeadSequence,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: wrapped, head: Some(head) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

fn head_of(envelope: &Value) -> IssuerChainHead {
    IssuerChainHead {
        issuer: envelope
            .get("issuer")
            .and_then(Value::as_str)
            .expect("issuer")
            .to_string(),
        seq: envelope.get("seq").and_then(Value::as_u64).expect("seq"),
        envelope_hash: envelope_hash_of(envelope),
    }
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-{ISSUER,SEQ}-FIELD-REQUIRED and predecessor type
// ---------------------------------------------------------------------------

#[test]
fn broken_chain_issuer_requirement_accepts_a_continuation_with_no_issuer() {
    let keypair = signing_keypair(7);
    let first = envelope(&keypair, 1, None);
    let head = head_of(&first);
    let mut missing = envelope(&keypair, 2, Some(head.envelope_hash.clone()));
    missing.as_object_mut().unwrap().remove("issuer");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_ISSUER_FIELD_REQUIRED,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipIssuerFieldRequired,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: missing, head: Some(head) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_chain_sequence_requirement_accepts_a_continuation_with_no_sequence() {
    let keypair = signing_keypair(7);
    let first = envelope(&keypair, 1, None);
    let head = head_of(&first);
    let mut missing = envelope(&keypair, 2, Some(head.envelope_hash.clone()));
    missing.as_object_mut().unwrap().remove("seq");
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_SEQ_FIELD_REQUIRED,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipSequenceFieldRequired,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: missing, head: Some(head) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_predecessor_type_guard_accepts_a_non_string_chain_reference() {
    let keypair = signing_keypair(7);
    let first = envelope(&keypair, 1, None);
    let head = head_of(&first);
    let mut wrong_type = envelope(&keypair, 2, Some(head.envelope_hash.clone()));
    wrong_type["prev_envelope_hash"] = json!(7);
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_PREV_TYPE_VALID,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipPreviousHashTypeValidation,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: wrong_type, head: Some(head) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-PREV-HASH-BOUND
// ---------------------------------------------------------------------------

#[test]
fn broken_prev_hash_binding_admits_the_forked_link_the_real_verifier_rejects() {
    let keypair = signing_keypair(7);
    let first = envelope(&keypair, 1, None);
    let head = head_of(&first);

    // A genuinely signed seq=2 envelope from the same issuer that continues a
    // DIFFERENT history. Everything about it verifies; it simply is not the
    // successor of the head we hold.
    let forked = envelope(&keypair, 2, Some("0x".to_string() + &"cd".repeat(32)));
    assert!(verify_envelope(&forked).expect("the fork is correctly signed"));

    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_PREV_HASH_BOUND,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipPrevHashBinding,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: forked, head: Some(head.clone()) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }

    // The real successor is accepted by both, so neither is refusing everything.
    let successor = envelope(&keypair, 2, Some(head.envelope_hash.clone()));
    assert_eq!(
        verify_chain_link(&successor, Some(&head)).expect("a verdict"),
        ChainLinkVerdict::ValidContinuation
    );
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-SEQ-MONOTONIC
// ---------------------------------------------------------------------------

#[test]
fn broken_sequence_binding_admits_the_replayed_envelope_the_real_verifier_rejects() {
    let keypair = signing_keypair(7);
    let first = envelope(&keypair, 1, None);
    let head = head_of(&first);
    let second = envelope(&keypair, 2, Some(head.envelope_hash.clone()));
    let head_at_two = head_of(&second);

    // Wrong sequence, RIGHT previous hash. Every remaining continuation guard
    // is satisfied, so deleting only the sequence comparison must admit this
    // exact probe. A byte-identical replay does not isolate the sequence guard:
    // its previous hash names the old head, so the prev-hash guard still refuses
    // it after the sequence guard is removed.
    let wrong_sequence = envelope(&keypair, 2, Some(head_at_two.envelope_hash.clone()));
    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_SEQ_MONOTONIC,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipSequenceBinding,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: wrong_sequence, head: Some(head_at_two) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-ISSUER-BOUND
// ---------------------------------------------------------------------------

#[test]
fn broken_issuer_binding_admits_the_cross_issuer_splice_the_real_verifier_rejects() {
    let ours = signing_keypair(7);
    let theirs = signing_keypair(9);
    let our_first = envelope(&ours, 1, None);
    let head = head_of(&our_first);

    // A different issuer's genuinely signed seq=2 envelope, crafted to name our
    // head. Sequence and prev-hash both line up; only the issuer differs, so
    // this probe isolates the issuer guard.
    let theirs_second = envelope(&theirs, 2, Some(head.envelope_hash.clone()));
    assert!(verify_envelope(&theirs_second).expect("their envelope is correctly signed"));

    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_ISSUER_BOUND,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipIssuerBinding,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: theirs_second, head: Some(head) },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-FIRST-SEQ
// ---------------------------------------------------------------------------

#[test]
fn broken_first_sequence_guard_admits_the_truncated_history_the_real_verifier_rejects() {
    let keypair = signing_keypair(7);

    // No known head -- a fresh verifier meeting this issuer for the first time.
    // The envelope claims to be the 99th, so accepting it silently concedes 98
    // records that were never seen and can never be audited.
    let truncated = envelope(&keypair, 99, None);
    assert!(verify_envelope(&truncated).expect("the envelope is correctly signed"));

    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_FIRST_SEQ,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipFirstSequence,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: truncated, head: None },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }

    // A real first envelope is accepted by both.
    let genuine_first = envelope(&keypair, 1, None);
    assert_eq!(
        verify_chain_link(&genuine_first, None).expect("a verdict"),
        ChainLinkVerdict::NewChain
    );
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-FIRST-PREV-NULL
// ---------------------------------------------------------------------------

#[test]
fn broken_first_previous_hash_guard_admits_a_new_chain_linked_to_hidden_history() {
    let keypair = signing_keypair(7);
    let linked_first = envelope(&keypair, 1, Some("0x".to_string() + &"ef".repeat(32)));
    assert!(verify_envelope(&linked_first).expect("the envelope is correctly signed"));

    negative_protocol::assert_registered_negative_case! {
        case: SPINE_CHAIN_FIRST_PREV_NULL,
        mutation: ChainMutation,
        control: ChainMutation::None,
        broken: ChainMutation::SkipFirstPreviousHash,
        state: {},
        probe: ChainProbe = ChainProbe { envelope: linked_first, head: None },
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_spine::chain::verify_chain_link,
        arguments: (&probe.envelope, probe.head.as_ref()),
        call: sync,
        normalize: |production_result| production_result.map(|verdict| verdict.is_valid()).unwrap_or(false),
        mirror: |_state, probe, mutation| mirrored_chain_admitted(probe, mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
