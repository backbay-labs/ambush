//! The four-member decision preimage both legs sign and verify (W3-16).
//!
//! RFC 8785 canonical JSON of `{decided_at_ms, decision, hold_id,
//! rationale_sha256}`. The console signs these bytes with the operator's
//! Ed25519 key; the daemon rebuilds them from its OWN stored `hold_id` and the
//! body's other three members and verifies. Two implementations therefore have
//! to agree byte for byte, which is why this goes through
//! `serde_json_canonicalizer` rather than relying on struct field order:
//! declaration order happens to be lexicographic here, and a later field
//! rename or insertion would silently break the contract if that coincidence
//! were the mechanism.
//!
//! `hold_id` is constrained to `[A-Za-z0-9_-]` by the R-3 pattern, so no
//! string escaping can differ between implementations. The engine side asserts
//! byte equality against `swarm_crypto::canonical_json_bytes` in
//! `swarm-ingest-runtime`'s tests.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// The four signed members. Field order is the canonical order, and the
/// canonicalizer enforces it independently.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionPreimage<'a> {
    /// The decision instant the console claims. The daemon records its own
    /// compare-and-set instant separately; this one is only ever a signed
    /// input, never the authority.
    pub decided_at_ms: i64,
    /// `grant` or `refuse`.
    pub decision: &'a str,
    /// The hold this decision is about.
    pub hold_id: &'a str,
    /// Lowercase hex SHA-256 of the rationale, or `None`.
    pub rationale_sha256: Option<&'a str>,
}

/// The exact bytes the operator signs and the daemon verifies.
///
/// Returns an empty vector only if canonicalization fails, which cannot happen
/// for these four value types (an integer, two ASCII tokens and a hex digest or
/// null). The fallback keeps this crate free of `unwrap`/`expect`; an empty
/// preimage verifies against nothing, so the failure mode is a refused
/// signature rather than a forged one.
pub fn decision_preimage_bytes(
    decided_at_ms: i64,
    decision: &str,
    hold_id: &str,
    rationale_sha256: Option<&str>,
) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&DecisionPreimage {
        decided_at_ms,
        decision,
        hold_id,
        rationale_sha256,
    })
    .unwrap_or_default()
}

/// Lowercase hex SHA-256 of the rationale's UTF-8 bytes, or `None` when the
/// operator wrote none.
///
/// The digest, not the text, is what the signature covers, so a rationale
/// swapped after signing fails verification.
pub fn rationale_sha256_hex(rationale: Option<&str>) -> Option<String> {
    rationale.map(|text| hex::encode(Sha256::digest(text.as_bytes())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_preimage_is_exactly_the_rfc_8785_form_of_four_sorted_members() {
        let bytes = decision_preimage_bytes(
            1_773_738_979_000,
            "grant",
            "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13",
            Some("f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"),
        );
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"decided_at_ms":1773738979000,"decision":"grant","hold_id":"hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13","rationale_sha256":"f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"}"#
        );
        let none = decision_preimage_bytes(1, "refuse", "h_a07aeacf", None);
        assert_eq!(
            std::str::from_utf8(&none).unwrap(),
            r#"{"decided_at_ms":1,"decision":"refuse","hold_id":"h_a07aeacf","rationale_sha256":null}"#
        );
    }

    #[test]
    fn the_rationale_digest_is_lowercase_sha256_of_the_utf8_bytes_or_none() {
        assert_eq!(rationale_sha256_hex(None), None);
        assert_eq!(
            rationale_sha256_hex(Some("hello")).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    /// Every member is load-bearing: changing any one of the four changes the
    /// bytes, so a signature cannot be replayed onto a different decision, a
    /// different hold, a different instant or a different rationale.
    #[test]
    fn each_of_the_four_members_changes_the_preimage() {
        let base = decision_preimage_bytes(1, "grant", "h_a07aeacf", Some("ab"));
        for other in [
            decision_preimage_bytes(2, "grant", "h_a07aeacf", Some("ab")),
            decision_preimage_bytes(1, "refuse", "h_a07aeacf", Some("ab")),
            decision_preimage_bytes(1, "grant", "h_b07aeacf", Some("ab")),
            decision_preimage_bytes(1, "grant", "h_a07aeacf", Some("cd")),
            decision_preimage_bytes(1, "grant", "h_a07aeacf", None),
        ] {
            assert_ne!(base, other);
        }
    }
}
