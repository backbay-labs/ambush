//! B6: the spine signing identities and the seal step.
//!
//! One configured secret root, one Ed25519 keypair per bridge identity slot,
//! derived the way the Nostr keys are but under a DIFFERENT domain string, so
//! the two chains can never share key material:
//!
//! ```text
//! spine_secret[slot] =
//!   SHA-256( b"swarm.perch.bridge.spine.v1" || 0x00 || root || 0x00 || colony_id || 0x00 || slot )
//! ```
//!
//! The root comes from `perch.spine_seed_env`, never from a public identifier.
//! Deriving signing material from something an observer already knows is the
//! exact forgery this module exists to prevent.

use std::collections::BTreeMap;

use serde_json::Value;
use swarm_crypto::{Keypair, sha256};
use swarm_perch_wire::envelope::IssuerChainHead;
use swarm_perch_wire::{CardEnvelope, CardKind};
use swarm_spine::envelope::{
    build_signed_envelope, issuer_from_keypair, now_rfc3339, verify_envelope,
};

use crate::error::BridgeError;
use crate::spool::chain_heads::ChainHeadStore;

const DOMAIN: &[u8] = b"swarm.perch.bridge.spine.v1";

/// The per-slot spine keypairs. Holds secret material; never prints it.
pub struct SpineSigner {
    keys: BTreeMap<String, Keypair>,
    issuers: BTreeMap<String, String>,
}

impl std::fmt::Debug for SpineSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Slots only. A `Debug` that reached the keys would put signing
        // material in every log line that formats this struct.
        f.debug_struct("SpineSigner")
            .field("slots", &self.issuers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SpineSigner {
    /// Read the root from the environment variable `config.spine_seed_env` names.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MissingSpineSeed`] when the variable is unset, empty, not
    /// hex, or shorter than 32 bytes. Starting without it is refused rather
    /// than degraded: a bridge that published unsigned envelopes under a
    /// signing profile would emit a chain nobody could tell from a forged one.
    pub fn from_config(
        config: &swarm_core::config::PerchBridgeConfig,
        colony_id: &str,
        slots: &[String],
    ) -> Result<Self, BridgeError> {
        let env = config.spine_seed_env.trim().to_string();
        let raw =
            std::env::var(&env).map_err(|_| BridgeError::MissingSpineSeed { env: env.clone() })?;
        Self::from_seed_hex(raw.trim(), colony_id, slots)
            .map_err(|_| BridgeError::MissingSpineSeed { env })
    }

    /// Derive every slot's keypair from at least 32 bytes of hex.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MissingSpineSeed`] with an empty `env` when `seed_hex` is
    /// not hex or is shorter than 32 bytes.
    pub fn from_seed_hex(
        seed_hex: &str,
        colony_id: &str,
        slots: &[String],
    ) -> Result<Self, BridgeError> {
        let root = hex::decode(seed_hex)
            .map_err(|_| BridgeError::MissingSpineSeed { env: String::new() })?;
        if root.len() < 32 {
            return Err(BridgeError::MissingSpineSeed { env: String::new() });
        }
        let mut keys = BTreeMap::new();
        let mut issuers = BTreeMap::new();
        for slot in slots {
            let mut preimage =
                Vec::with_capacity(DOMAIN.len() + root.len() + colony_id.len() + slot.len() + 3);
            preimage.extend_from_slice(DOMAIN);
            preimage.push(0);
            preimage.extend_from_slice(&root);
            preimage.push(0);
            preimage.extend_from_slice(colony_id.as_bytes());
            preimage.push(0);
            preimage.extend_from_slice(slot.as_bytes());
            let keypair = Keypair::from_seed(sha256(&preimage).as_bytes());
            issuers.insert(slot.clone(), issuer_from_keypair(&keypair));
            keys.insert(slot.clone(), keypair);
        }
        Ok(Self { keys, issuers })
    }

    /// The `swarm:ed25519:<hex>` issuer for a slot.
    ///
    /// An unknown slot yields the empty string, which [`Self::seal`] refuses;
    /// this never panics.
    #[must_use]
    pub fn issuer(&self, slot: &str) -> &str {
        self.issuers.get(slot).map_or("", String::as_str)
    }

    /// Sign one envelope at an explicit `(seq, prev)`, touching no store.
    ///
    /// # Why this exists beside [`Self::seal`]
    ///
    /// The pacer restores `prev_envelope_hash` when a frame is not
    /// acknowledged, so an unpublished card must not advance the chain. A seal
    /// that wrote the durable head immediately would advance it for a card the
    /// relay never took, and the next real card would chain from a link nobody
    /// can fetch. Callers on that path sign here and commit the head on ACK;
    /// callers that publish synchronously use [`Self::seal`].
    ///
    /// # Errors
    ///
    /// [`BridgeError::UnknownSlot`] for a slot with no key, and
    /// [`BridgeError::Envelope`] when the fact's schema does not match `kind`,
    /// the spine refuses, or the result does not decode.
    pub fn seal_at(
        &self,
        slot: &str,
        kind: CardKind,
        seq: u64,
        prev: Option<String>,
        fact: Value,
    ) -> Result<CardEnvelope, BridgeError> {
        let keypair = self
            .keys
            .get(slot)
            .ok_or_else(|| BridgeError::UnknownSlot {
                slot: slot.to_string(),
            })?;
        // The envelope says which card it carries; a fact of another kind under
        // that claim is a mislabelled record, not a formatting slip.
        let found = fact
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if found != kind.fact_schema() {
            return Err(BridgeError::Envelope(format!(
                "fact schema {found:?} does not match {}",
                kind.fact_schema()
            )));
        }
        let value = build_signed_envelope(keypair, seq, prev, fact, now_rfc3339())
            .map_err(|error| BridgeError::Envelope(error.to_string()))?;
        // Verify what we just signed. A signer that emits something its own
        // verifier rejects has produced a record no reader can check, and the
        // cheapest place to notice is here.
        if !verify_envelope(&value).map_err(|error| BridgeError::Envelope(error.to_string()))? {
            return Err(BridgeError::Envelope(
                "the spine rejected its own newly signed envelope".to_string(),
            ));
        }
        serde_json::from_value(value).map_err(|error| BridgeError::Envelope(error.to_string()))
    }

    /// Seal `fact` under `slot`, advancing that issuer's chain head.
    ///
    /// `seq` is the head's plus one (or 1), `prev_envelope_hash` is the head's
    /// hash, and the head advances only AFTER the envelope is built and
    /// verified — a failed seal leaves the chain exactly where it was, so a
    /// retry continues rather than forks.
    ///
    /// # Errors
    ///
    /// [`BridgeError::UnknownSlot`] for a slot with no key;
    /// [`BridgeError::Envelope`] when the fact's schema does not match `kind`,
    /// or the spine refuses, or the result does not decode; and the chain-head
    /// store's own errors.
    pub fn seal(
        &self,
        slot: &str,
        kind: CardKind,
        heads: &mut ChainHeadStore,
        fact: Value,
    ) -> Result<CardEnvelope, BridgeError> {
        let issuer = self.issuer(slot).to_string();
        let (seq, prev) = match heads.head(&issuer) {
            Some(head) => (head.seq + 1, Some(head.envelope_hash.clone())),
            None => (1, None),
        };
        let envelope = self.seal_at(slot, kind, seq, prev, fact)?;
        heads.advance(IssuerChainHead {
            issuer,
            seq,
            envelope_hash: envelope.envelope_hash.clone(),
        })?;
        Ok(envelope)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_perch_wire::envelope::{ChainLinkVerdict, verify_chain_link};

    const SEED: &str = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100";

    fn fact(n: u64) -> Value {
        serde_json::json!({
            "schema": "swarm.perch.hold.v1",
            "issuer": { "swarm_agent_id": "x", "role": null },
            "emitted_at_ms": n
        })
    }

    /// Derivation is deterministic, per-slot, and per-colony.
    ///
    /// Two slots sharing an issuer would merge two streams into one chain; two
    /// colonies sharing one would let a spool copied between them look
    /// continuous. Both are false continuity, which is worse than a visible gap
    /// because nothing shows.
    #[test]
    fn slots_derive_distinct_issuers_deterministically() {
        let slots = vec!["perch-alarm".to_string(), "perch-telemetry".to_string()];
        let a = SpineSigner::from_seed_hex(SEED, "colony-a", &slots).unwrap();
        let b = SpineSigner::from_seed_hex(SEED, "colony-a", &slots).unwrap();
        assert_eq!(a.issuer("perch-alarm"), b.issuer("perch-alarm"));
        assert_ne!(a.issuer("perch-alarm"), a.issuer("perch-telemetry"));
        assert!(a.issuer("perch-alarm").starts_with("swarm:ed25519:"));

        let other = SpineSigner::from_seed_hex(SEED, "colony-b", &slots).unwrap();
        assert_ne!(
            a.issuer("perch-alarm"),
            other.issuer("perch-alarm"),
            "the colony id is in the derivation"
        );

        // A different root gives different identities under the same slot.
        let rerooted = SpineSigner::from_seed_hex(&"11".repeat(32), "colony-a", &slots).unwrap();
        assert_ne!(a.issuer("perch-alarm"), rerooted.issuer("perch-alarm"));
    }

    /// A seed that cannot produce 32 bytes is refused, never padded.
    #[test]
    fn a_short_or_malformed_seed_is_refused() {
        let slots = vec!["perch-alarm".to_string()];
        assert!(matches!(
            SpineSigner::from_seed_hex("abcd", "colony-a", &slots),
            Err(BridgeError::MissingSpineSeed { .. })
        ));
        assert!(matches!(
            SpineSigner::from_seed_hex("not hex at all", "colony-a", &slots),
            Err(BridgeError::MissingSpineSeed { .. })
        ));
    }

    /// Each seal continues the chain, and the spine verifies what it signed.
    #[test]
    fn seal_chains_per_issuer_and_the_spine_verifies_every_link() {
        let dir = tempfile::tempdir().unwrap();
        let signer =
            SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".to_string()]).unwrap();
        let mut heads = ChainHeadStore::open(dir.path(), "colony-a").unwrap();

        let first = signer
            .seal("perch-alarm", CardKind::Hold, &mut heads, fact(1))
            .unwrap();
        let second = signer
            .seal("perch-alarm", CardKind::Hold, &mut heads, fact(2))
            .unwrap();

        assert_eq!(first.seq, 1);
        assert!(
            first.prev_envelope_hash.is_none(),
            "the first link has no parent"
        );
        assert_eq!(second.seq, 2);
        assert_eq!(
            second.prev_envelope_hash.as_deref(),
            Some(first.envelope_hash.as_str())
        );

        let head = IssuerChainHead {
            issuer: first.issuer.clone(),
            seq: first.seq,
            envelope_hash: first.envelope_hash.clone(),
        };
        assert_eq!(verify_chain_link(&head, &second), ChainLinkVerdict::Valid);
        assert!(
            verify_envelope(&serde_json::to_value(&second).unwrap()).unwrap(),
            "the spine must verify its own signature"
        );
    }

    /// A fact of one kind sealed under another is a mislabelled record.
    #[test]
    fn a_fact_whose_schema_disagrees_with_the_kind_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let signer =
            SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".to_string()]).unwrap();
        let mut heads = ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        assert!(matches!(
            signer.seal("perch-alarm", CardKind::Finding, &mut heads, fact(1)),
            Err(BridgeError::Envelope(_))
        ));
        // And a refused seal left the chain where it was, so the next real one
        // is still seq 1 rather than a gap.
        assert!(heads.head(signer.issuer("perch-alarm")).is_none());
    }

    /// An unknown slot is a typed refusal, not a panic and not a silent unsigned
    /// envelope.
    #[test]
    fn an_unknown_slot_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let signer =
            SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".to_string()]).unwrap();
        let mut heads = ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        assert!(matches!(
            signer.seal("nobody", CardKind::Hold, &mut heads, fact(1)),
            Err(BridgeError::UnknownSlot { .. })
        ));
    }

    /// `Debug` must not print key material.
    #[test]
    fn debug_shows_slots_and_no_secrets() {
        let signer =
            SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".to_string()]).unwrap();
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("perch-alarm"));
        assert!(!rendered.contains(SEED));
        assert!(!rendered.to_lowercase().contains("secret"));
    }
}
