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
}

/// Mirror of `verify_envelope`, copied from
/// `crates/swarm-spine/src/envelope.rs` with one check removable.
///
/// Returns `Ok(true)` for "this envelope is accepted", matching the real
/// function's contract: `Err` and `Ok(false)` are both refusals, and only
/// `Ok(true)` admits an envelope into a chain.
fn mirrored_verify_envelope(envelope: &Value, mutation: EnvelopeMutation) -> Result<bool, String> {
    let issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or("missing issuer")?;
    let signature_hex = envelope
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("missing signature")?;
    let claimed_hash = envelope
        .get("envelope_hash")
        .and_then(Value::as_str)
        .ok_or("missing envelope_hash")?;

    let pubkey_hex = parse_issuer_pubkey_hex(issuer).map_err(|error| error.to_string())?;
    let public_key = PublicKey::from_hex(&pubkey_hex).map_err(|error| error.to_string())?;
    let signature = Signature::from_hex(signature_hex).map_err(|error| error.to_string())?;

    let mut unsigned = envelope.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("envelope_hash");
        object.remove("signature");
    }

    let bytes = envelope_signing_bytes(&unsigned).map_err(|error| error.to_string())?;
    let computed_hash = sha256_hex_prefixed(&bytes);
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

    let real = verify_envelope(&forged);
    assert!(
        real.is_err(),
        "the shipped verifier must refuse an envelope whose claimed hash is not \
         the hash of its body, got {real:?}"
    );

    let control = mirrored_verify_envelope(&forged, EnvelopeMutation::None);
    assert!(
        !admitted(&control),
        "the unmutated mirror must refuse it too; if it does not the mutation \
         below proves nothing"
    );

    let broken = mirrored_verify_envelope(&forged, EnvelopeMutation::SkipHashBinding);
    assert!(
        admitted(&broken),
        "without the hash comparison the signature alone verifies -- it is taken \
         over the envelope MINUS envelope_hash and signature -- so a chain link \
         pointing anywhere the attacker chooses is admitted: {broken:?}"
    );

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
// SPINE-ENVELOPE-SIGNATURE-REQUIRED
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

    let real = verify_envelope(&forged);
    assert_eq!(
        real.ok(),
        Some(false),
        "the shipped verifier must reach the signature check -- not a hash \
         mismatch -- and refuse there"
    );

    let control = mirrored_verify_envelope(&forged, EnvelopeMutation::None);
    assert!(!admitted(&control), "the unmutated mirror must refuse too");

    let broken = mirrored_verify_envelope(&forged, EnvelopeMutation::SkipSignatureCheck);
    assert!(
        admitted(&broken),
        "without the signature check an envelope is attributed to whichever \
         issuer the bytes claim, and the victim's key never touched it: {broken:?}"
    );
}

// ---------------------------------------------------------------------------
// The mirror of `swarm_spine::chain::verify_chain_link`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainMutation {
    /// No mutation. The control.
    None,
    /// The `seq != 1 || prev_hash.is_some()` guard on a NEW chain deleted.
    SkipFirstEnvelopeShape,
    /// The `envelope_issuer_norm != head_issuer_norm` guard deleted.
    SkipIssuerBinding,
    /// The `seq != expected_seq` guard deleted.
    SkipSequenceBinding,
    /// The `actual_prev_hash != head.envelope_hash` guard deleted.
    SkipPrevHashBinding,
}

/// Mirror of `verify_chain_link`, copied from
/// `crates/swarm-spine/src/chain.rs` with one guard removable.
fn mirrored_verify_chain_link(
    envelope: &Value,
    known_head: Option<&IssuerChainHead>,
    mutation: ChainMutation,
) -> Result<ChainLinkVerdict, String> {
    let envelope_issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or("missing issuer")?;
    let seq = envelope
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or("missing seq")?;
    let prev_hash = envelope
        .get("prev_envelope_hash")
        .ok_or("missing prev_envelope_hash")?;

    let prev_hash_str = if prev_hash.is_null() {
        None
    } else {
        Some(
            prev_hash
                .as_str()
                .ok_or("prev_envelope_hash is not a string")?,
        )
    };

    let normalize = |issuer: &str| {
        parse_issuer_pubkey_hex(issuer)
            .map(|hex| hex.to_ascii_lowercase())
            .unwrap_or_else(|_| issuer.to_ascii_lowercase())
    };

    match known_head {
        None => {
            if mutation != ChainMutation::SkipFirstEnvelopeShape {
                if seq != 1 {
                    return Ok(ChainLinkVerdict::InvalidChainHead {
                        reason: format!("first envelope must have seq=1, got seq={seq}"),
                    });
                }
                if prev_hash_str.is_some() {
                    return Ok(ChainLinkVerdict::InvalidChainHead {
                        reason: "first envelope must have null prev_envelope_hash".to_string(),
                    });
                }
            }
            Ok(ChainLinkVerdict::NewChain)
        }
        Some(head) => {
            if mutation != ChainMutation::SkipIssuerBinding
                && normalize(envelope_issuer) != normalize(&head.issuer)
            {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!(
                        "issuer mismatch: envelope issuer {envelope_issuer} does not match \
                         head issuer {}",
                        head.issuer
                    ),
                });
            }

            let Some(expected_seq) = head.seq.checked_add(1) else {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!("known head sequence overflow for issuer {}", head.issuer),
                });
            };
            if mutation != ChainMutation::SkipSequenceBinding && seq != expected_seq {
                return Ok(ChainLinkVerdict::SequenceMismatch {
                    expected_seq,
                    actual_seq: seq,
                });
            }

            let actual_prev_hash = prev_hash_str.unwrap_or("");
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

    let real = verify_chain_link(&forked, Some(&head)).expect("a verdict");
    assert!(
        matches!(real, ChainLinkVerdict::HashMismatch { .. }),
        "the shipped verifier must refuse a link that does not name our head, got {real:?}"
    );
    assert!(!real.is_valid());

    let control =
        mirrored_verify_chain_link(&forked, Some(&head), ChainMutation::None).expect("a verdict");
    assert_eq!(
        control, real,
        "the unmutated mirror must reproduce the real verdict"
    );

    let broken =
        mirrored_verify_chain_link(&forked, Some(&head), ChainMutation::SkipPrevHashBinding)
            .expect("a verdict");
    assert_eq!(
        broken,
        ChainLinkVerdict::ValidContinuation,
        "without the prev-hash comparison a validly signed envelope continuing \
         some other history is accepted as ours"
    );
    assert!(broken.is_valid());

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

    // Replay: `second` is re-presented after it has already been accepted. It is
    // byte-identical to a record that verified, so signature and prev-hash both
    // still pass against the OLD head -- but its prev-hash does not name the new
    // head, which is why the probe below asserts on the sequence verdict
    // specifically.
    let real = verify_chain_link(&second, Some(&head_at_two)).expect("a verdict");
    assert_eq!(
        real,
        ChainLinkVerdict::SequenceMismatch {
            expected_seq: 3,
            actual_seq: 2,
        },
        "the shipped verifier must refuse a replay at the sequence check"
    );
    assert!(!real.is_valid());

    let control = mirrored_verify_chain_link(&second, Some(&head_at_two), ChainMutation::None)
        .expect("a verdict");
    assert_eq!(
        control, real,
        "the unmutated mirror must reproduce the real verdict"
    );

    let broken = mirrored_verify_chain_link(
        &second,
        Some(&head_at_two),
        ChainMutation::SkipSequenceBinding,
    )
    .expect("a verdict");
    assert!(
        !matches!(broken, ChainLinkVerdict::SequenceMismatch { .. }),
        "deleting the sequence guard must stop the replay being caught there, got {broken:?}"
    );
    assert_eq!(
        broken,
        ChainLinkVerdict::HashMismatch {
            expected_prev_hash: head_at_two.envelope_hash.clone(),
            actual_prev_hash: head.envelope_hash.clone(),
        },
        "and what is left is the prev-hash guard -- which is exactly why these \
         are two rows: each alone is the only thing standing between a replay \
         and the chain"
    );
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

    let real = verify_chain_link(&theirs_second, Some(&head)).expect("a verdict");
    assert!(
        matches!(real, ChainLinkVerdict::InvalidChainHead { .. }),
        "the shipped verifier must refuse another issuer's envelope on our chain, got {real:?}"
    );
    assert!(!real.is_valid());

    let control = mirrored_verify_chain_link(&theirs_second, Some(&head), ChainMutation::None)
        .expect("a verdict");
    assert_eq!(
        control, real,
        "the unmutated mirror must reproduce the real verdict"
    );

    let broken = mirrored_verify_chain_link(
        &theirs_second,
        Some(&head),
        ChainMutation::SkipIssuerBinding,
    )
    .expect("a verdict");
    assert_eq!(
        broken,
        ChainLinkVerdict::ValidContinuation,
        "without the issuer guard any keyholder can extend any issuer's chain, \
         because every other check is satisfiable from public data"
    );
    assert!(broken.is_valid());
}

// ---------------------------------------------------------------------------
// SPINE-CHAIN-FIRST-LINK-SHAPE
// ---------------------------------------------------------------------------

#[test]
fn broken_first_envelope_shape_admits_the_truncated_history_the_real_verifier_rejects() {
    let keypair = signing_keypair(7);

    // No known head -- a fresh verifier meeting this issuer for the first time.
    // The envelope claims to be the 99th, so accepting it silently concedes 98
    // records that were never seen and can never be audited.
    let truncated = envelope(&keypair, 99, None);
    assert!(verify_envelope(&truncated).expect("the envelope is correctly signed"));

    let real = verify_chain_link(&truncated, None).expect("a verdict");
    assert!(
        matches!(real, ChainLinkVerdict::InvalidChainHead { .. }),
        "a chain a verifier has never seen must start at seq=1, got {real:?}"
    );
    assert!(!real.is_valid());

    let control =
        mirrored_verify_chain_link(&truncated, None, ChainMutation::None).expect("a verdict");
    assert_eq!(
        control, real,
        "the unmutated mirror must reproduce the real verdict"
    );

    let broken =
        mirrored_verify_chain_link(&truncated, None, ChainMutation::SkipFirstEnvelopeShape)
            .expect("a verdict");
    assert_eq!(
        broken,
        ChainLinkVerdict::NewChain,
        "without the shape guard an issuer can join at any height it likes and \
         the missing prefix is never noticed"
    );
    assert!(broken.is_valid());

    // A real first envelope is accepted by both.
    let genuine_first = envelope(&keypair, 1, None);
    assert_eq!(
        verify_chain_link(&genuine_first, None).expect("a verdict"),
        ChainLinkVerdict::NewChain
    );
}
