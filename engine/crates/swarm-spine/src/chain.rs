//! Per-issuer hash chain verification for spine envelopes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::envelope::parse_issuer_pubkey_hex;
use crate::spine_error::{SpineError, SpineResult};

/// Persisted state for the head of an issuer's envelope chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerChainHead {
    pub issuer: String,
    pub seq: u64,
    pub envelope_hash: String,
}

/// Result of verifying an envelope against its issuer's known chain head.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ChainLinkVerdict {
    NewChain,
    ValidContinuation,
    HashMismatch {
        expected_prev_hash: String,
        actual_prev_hash: String,
    },
    SequenceMismatch {
        expected_seq: u64,
        actual_seq: u64,
    },
    InvalidChainHead {
        reason: String,
    },
}

fn normalize_issuer_for_compare(issuer: &str) -> String {
    parse_issuer_pubkey_hex(issuer)
        .map(|hex| hex.to_ascii_lowercase())
        .unwrap_or_else(|_| issuer.to_ascii_lowercase())
}

impl ChainLinkVerdict {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::NewChain | Self::ValidContinuation)
    }

    pub fn into_result(self, issuer: &str) -> SpineResult<()> {
        match self {
            Self::NewChain | Self::ValidContinuation => Ok(()),
            Self::HashMismatch {
                expected_prev_hash,
                actual_prev_hash,
            } => Err(SpineError::ChainIntegrityViolation {
                issuer: issuer.to_string(),
                reason: format!(
                    "prev_envelope_hash mismatch: expected {expected_prev_hash}, got {actual_prev_hash}"
                ),
            }),
            Self::SequenceMismatch {
                expected_seq,
                actual_seq,
            } => Err(SpineError::ChainIntegrityViolation {
                issuer: issuer.to_string(),
                reason: format!("sequence mismatch: expected {expected_seq}, got {actual_seq}"),
            }),
            Self::InvalidChainHead { reason } => Err(SpineError::ChainIntegrityViolation {
                issuer: issuer.to_string(),
                reason,
            }),
        }
    }
}

/// Verify that an envelope correctly continues an issuer chain.
pub fn verify_chain_link(
    envelope: &Value,
    known_head: Option<&IssuerChainHead>,
) -> SpineResult<ChainLinkVerdict> {
    let envelope_issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("issuer"))?;
    let seq = envelope
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or(SpineError::MissingField("seq"))?;
    let prev_hash = envelope
        .get("prev_envelope_hash")
        .ok_or(SpineError::MissingField("prev_envelope_hash"))?;

    let prev_hash_str = if prev_hash.is_null() {
        None
    } else {
        Some(
            prev_hash
                .as_str()
                .ok_or(SpineError::MissingField("prev_envelope_hash"))?,
        )
    };

    match known_head {
        None => {
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
            Ok(ChainLinkVerdict::NewChain)
        }
        Some(head) => {
            let envelope_issuer_norm = normalize_issuer_for_compare(envelope_issuer);
            let head_issuer_norm = normalize_issuer_for_compare(&head.issuer);
            if envelope_issuer_norm != head_issuer_norm {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!(
                        "issuer mismatch: envelope issuer {envelope_issuer} does not match head issuer {}",
                        head.issuer
                    ),
                });
            }

            let Some(expected_seq) = head.seq.checked_add(1) else {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!("known head sequence overflow for issuer {}", head.issuer),
                });
            };
            if seq != expected_seq {
                return Ok(ChainLinkVerdict::SequenceMismatch {
                    expected_seq,
                    actual_seq: seq,
                });
            }

            let actual_prev_hash = prev_hash_str.unwrap_or("");
            if actual_prev_hash != head.envelope_hash {
                return Ok(ChainLinkVerdict::HashMismatch {
                    expected_prev_hash: head.envelope_hash.clone(),
                    actual_prev_hash: actual_prev_hash.to_string(),
                });
            }

            Ok(ChainLinkVerdict::ValidContinuation)
        }
    }
}

/// Extract an [`IssuerChainHead`] from an envelope.
pub fn chain_head_from_envelope(envelope: &Value) -> SpineResult<IssuerChainHead> {
    let issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("issuer"))?
        .to_string();
    let seq = envelope
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or(SpineError::MissingField("seq"))?;
    let envelope_hash = envelope
        .get("envelope_hash")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("envelope_hash"))?
        .to_string();

    Ok(IssuerChainHead {
        issuer,
        seq,
        envelope_hash,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{build_signed_envelope, issuer_from_keypair, now_rfc3339};
    use serde_json::json;
    use swarm_crypto::Keypair;

    fn make_envelope(keypair: &Keypair, seq: u64, prev: Option<String>) -> Value {
        build_signed_envelope(
            keypair,
            seq,
            prev,
            json!({"type": "chain_test", "seq": seq}),
            now_rfc3339(),
        )
        .unwrap()
    }

    #[test]
    fn new_chain() {
        let keypair = Keypair::generate();
        let envelope = make_envelope(&keypair, 1, None);
        let verdict = verify_chain_link(&envelope, None).unwrap();

        assert_eq!(verdict, ChainLinkVerdict::NewChain);
        assert!(verdict.is_valid());
    }

    #[test]
    fn valid_continuation() {
        let keypair = Keypair::generate();
        let first = make_envelope(&keypair, 1, None);
        let head = chain_head_from_envelope(&first).unwrap();
        let second = make_envelope(&keypair, 2, Some(head.envelope_hash.clone()));
        let verdict = verify_chain_link(&second, Some(&head)).unwrap();

        assert_eq!(verdict, ChainLinkVerdict::ValidContinuation);
    }

    #[test]
    fn hash_mismatch() {
        let keypair = Keypair::generate();
        let first = make_envelope(&keypair, 1, None);
        let head = chain_head_from_envelope(&first).unwrap();
        let second = make_envelope(&keypair, 2, Some("0xdeadbeef".to_string()));
        let verdict = verify_chain_link(&second, Some(&head)).unwrap();

        assert!(matches!(verdict, ChainLinkVerdict::HashMismatch { .. }));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn seq_gap() {
        let keypair = Keypair::generate();
        let first = make_envelope(&keypair, 1, None);
        let head = chain_head_from_envelope(&first).unwrap();
        let third = make_envelope(&keypair, 3, Some(head.envelope_hash.clone()));
        let verdict = verify_chain_link(&third, Some(&head)).unwrap();

        assert!(matches!(
            verdict,
            ChainLinkVerdict::SequenceMismatch {
                expected_seq: 2,
                actual_seq: 3,
            }
        ));
    }

    #[test]
    fn seq_regression() {
        let keypair = Keypair::generate();
        let first = make_envelope(&keypair, 1, None);
        let head1 = chain_head_from_envelope(&first).unwrap();
        let second = make_envelope(&keypair, 2, Some(head1.envelope_hash.clone()));
        let head2 = chain_head_from_envelope(&second).unwrap();
        let replay = make_envelope(&keypair, 2, Some(head2.envelope_hash.clone()));
        let verdict = verify_chain_link(&replay, Some(&head2)).unwrap();

        assert!(matches!(
            verdict,
            ChainLinkVerdict::SequenceMismatch {
                expected_seq: 3,
                actual_seq: 2,
            }
        ));
    }

    #[test]
    fn invalid_chain_head_wrong_seq() {
        let keypair = Keypair::generate();
        let envelope = make_envelope(&keypair, 5, None);
        let verdict = verify_chain_link(&envelope, None).unwrap();

        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
    }

    #[test]
    fn invalid_chain_head_non_null_prev() {
        let keypair = Keypair::generate();
        let envelope = make_envelope(&keypair, 1, Some("0xabc123".to_string()));
        let verdict = verify_chain_link(&envelope, None).unwrap();

        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
    }

    #[test]
    fn per_issuer_isolation() {
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();

        let a1 = make_envelope(&keypair_a, 1, None);
        let head_a = chain_head_from_envelope(&a1).unwrap();
        let b1 = make_envelope(&keypair_b, 1, None);
        let verdict_b = verify_chain_link(&b1, None).unwrap();
        let a2 = make_envelope(&keypair_a, 2, Some(head_a.envelope_hash.clone()));
        let verdict_a2 = verify_chain_link(&a2, Some(&head_a)).unwrap();

        assert_eq!(verdict_b, ChainLinkVerdict::NewChain);
        assert_eq!(verdict_a2, ChainLinkVerdict::ValidContinuation);
    }

    #[test]
    fn issuer_mismatch_rejected_even_when_seq_and_prev_match() {
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();

        let b1 = make_envelope(&keypair_b, 1, None);
        let head_b = chain_head_from_envelope(&b1).unwrap();
        let a2 = make_envelope(&keypair_a, 2, Some(head_b.envelope_hash.clone()));
        let verdict = verify_chain_link(&a2, Some(&head_b)).unwrap();

        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
    }

    #[test]
    fn max_sequence_head_rejected_without_overflow() {
        let keypair = Keypair::generate();
        let head = IssuerChainHead {
            issuer: issuer_from_keypair(&keypair),
            seq: u64::MAX,
            envelope_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        };
        let envelope = make_envelope(&keypair, u64::MAX, Some(head.envelope_hash.clone()));
        let verdict = verify_chain_link(&envelope, Some(&head)).unwrap();

        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
    }

    #[test]
    fn chain_head_from_envelope_extracts_fields() {
        let keypair = Keypair::generate();
        let envelope = make_envelope(&keypair, 42, Some("0xprevhash".to_string()));
        let head = chain_head_from_envelope(&envelope).unwrap();

        assert_eq!(head.issuer, issuer_from_keypair(&keypair));
        assert_eq!(head.seq, 42);
        assert!(!head.envelope_hash.is_empty());
    }

    #[test]
    fn issuer_chain_head_serde_roundtrip() {
        let head = IssuerChainHead {
            issuer:
                "swarm:ed25519:aabbccddee001122aabbccddee001122aabbccddee001122aabbccddee001122"
                    .to_string(),
            seq: 7,
            envelope_hash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
        };
        let json = serde_json::to_string(&head).unwrap();
        let restored: IssuerChainHead = serde_json::from_str(&json).unwrap();

        assert_eq!(head, restored);
    }
}
