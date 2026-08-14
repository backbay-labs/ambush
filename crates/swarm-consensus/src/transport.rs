//! Transport seam for a consensus round, and the driver that runs one round
//! against it (BFT-03, BFT-04).
//!
//! # Why this module exists
//!
//! Before this module, `swarm-agents`' `GovernancePolicy` reached a governance
//! decision by calling a function that took `&BTreeMap<AgentId, SigningKey>` --
//! every committee member's PRIVATE key -- built one [`ConsensusNode`] per key
//! in-process, and hand-delivered envelopes between them. That is a simulator,
//! not a protocol: a governor holding its peers' keys can produce any quorum it
//! likes, so the receipt proves only that one process was willing to sign.
//!
//! [`drive_round`] replaces it with the shape a real deployment needs: ONE
//! locally owned node, holding ONE signing key, publishing signed envelopes to
//! a [`ConsensusTransport`] and consuming what the transport delivers.
//!
//! # What ships here, and what deliberately does not
//!
//! The only transport in this crate is [`SoloGovernorTransport`], and it
//! REFUSES any committee with more than one member. That refusal is the
//! load-bearing part. A transport that accepted a real `3f+1` committee and
//! then delivered nothing would let a multi-governor deployment run rounds that
//! silently degenerate to "one node agreed with itself" -- and such a receipt
//! would pass every downstream gate. `ConsensusGovernanceReceipt::verify`
//! checks only that the receipt is internally consistent, and
//! `verify_signed_by` adds only that the signer is a configured governor (ADR
//! 0011) -- which the local governor of a degenerate round IS. Neither reads
//! `prevote_tally`, `precommit_tally` or `committee_members`, so no verifier
//! downstream can tell a real quorum from a self-satisfied one. Refusing at
//! bind time makes the degenerate case unreachable instead of undetectable.
//!
//! A networked transport (pheromone-substrate or JetStream backed) is NOT in
//! this module. It cannot be, at this signature: the trait is synchronous, and
//! a real transport must wait for peers, which means `async`. Making
//! `GovernancePolicy::can_act` async is the open half of BFT-04; see
//! `.planning/ROADMAP.md` phase 321. What is here is the seam, the single-key
//! node, and the refusal.
//!
//! # The synchronous shape is a mailbox, not a network call
//!
//! [`ConsensusTransport::publish`] hands an envelope to an outbox and
//! [`ConsensusTransport::drain`] takes whatever has already arrived. Neither
//! blocks and neither waits. For a solo committee that is exact -- there is
//! nobody to wait for, and the round commits inside `queue_proposal`. For any
//! larger committee it is wrong, which is why [`SoloGovernorTransport`] is the
//! only implementation and why `accept_committee` exists.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::{
    ConsensusCommit, ConsensusCommittee, ConsensusError, ConsensusNode, ConsensusProposal,
    ConsensusSignedEnvelope,
};

/// Carries signed consensus envelopes between the members of one committee.
///
/// Implementations are shared across threads behind an `Arc` and must be
/// prepared for `accept_committee` to be called before every round.
pub trait ConsensusTransport: Send + Sync + std::fmt::Debug {
    /// Refuse committees this transport cannot actually serve.
    ///
    /// Called by [`drive_round`] before a single envelope is produced. An
    /// implementation that cannot reach every member of `committee` MUST return
    /// an error here rather than accept the round and deliver nothing: a round
    /// that produces no peer messages is indistinguishable, at the receipt
    /// layer, from a round whose peers all agreed.
    fn accept_committee(&self, committee: &ConsensusCommittee) -> Result<(), ConsensusError>;

    /// Hand a locally produced, locally signed envelope to the committee.
    fn publish(&self, envelope: &ConsensusSignedEnvelope) -> Result<(), ConsensusError>;

    /// Take every envelope that has arrived since the previous drain.
    ///
    /// Returning an empty vector means "nothing has arrived", which the driver
    /// treats as a reason to let the round clock advance. It must never be used
    /// to mean "this transport is not wired up" -- that is an error.
    fn drain(&self) -> Result<Vec<ConsensusSignedEnvelope>, ConsensusError>;
}

/// The transport for a committee of exactly one governor.
///
/// A one-member committee has `threshold() == 1` and the sole member is its own
/// proposer, so the round commits without any message ever leaving the process.
/// `publish` therefore records the envelope and drops it, and `drain` correctly
/// returns nothing -- both are exact for this committee size and wrong for any
/// other, which is what [`Self::accept_committee`] enforces.
#[derive(Debug, Default)]
pub struct SoloGovernorTransport {
    recent: Mutex<VecDeque<ConsensusSignedEnvelope>>,
    published_total: Mutex<u64>,
}

/// How many published envelopes [`SoloGovernorTransport`] keeps for inspection.
///
/// Bounded on purpose: `TomAgent::tick` re-issues up to twelve contingency
/// leases per tick, each a governance round, so an unbounded log would be a
/// slow memory leak in the daemon rather than a diagnostic.
const SOLO_TRANSPORT_RECENT_CAPACITY: usize = 64;

impl SoloGovernorTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// The most recent published envelopes, oldest first, capped at
    /// [`SOLO_TRANSPORT_RECENT_CAPACITY`].
    ///
    /// Exposed so a test can assert that every envelope a round produced was
    /// signed by the LOCAL governor and by nobody else.
    pub fn recent_published(&self) -> Vec<ConsensusSignedEnvelope> {
        self.recent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Total envelopes ever published, including those aged out of the window.
    pub fn published_total(&self) -> u64 {
        *self
            .published_total
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ConsensusTransport for SoloGovernorTransport {
    fn accept_committee(&self, committee: &ConsensusCommittee) -> Result<(), ConsensusError> {
        let size = committee.members().len();
        if size > 1 {
            return Err(ConsensusError::InvalidCommittee(format!(
                "SoloGovernorTransport cannot serve a committee of {size} members: it delivers \
                 no messages, so every peer vote would be missing and the round would either \
                 stall or commit on the local vote alone. Wire a networked transport."
            )));
        }
        Ok(())
    }

    fn publish(&self, envelope: &ConsensusSignedEnvelope) -> Result<(), ConsensusError> {
        let mut recent = self
            .recent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        recent.push_back(envelope.clone());
        while recent.len() > SOLO_TRANSPORT_RECENT_CAPACITY {
            recent.pop_front();
        }
        drop(recent);
        let mut total = self
            .published_total
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *total = total.saturating_add(1);
        Ok(())
    }

    fn drain(&self) -> Result<Vec<ConsensusSignedEnvelope>, ConsensusError> {
        Ok(Vec::new())
    }
}

/// Run one consensus round to a commit, or fail.
///
/// `node` is the ONLY node this process owns; its signing key is the only key
/// involved. Outbound envelopes are signed by the node itself
/// ([`ConsensusNode::sign_outbound`]) so no `SigningKey` is handled here.
///
/// The budget is rounds `0..=max_faulty` -- `max_faulty + 1` rounds of
/// `round_timeout_ms` each, the bound BFT-05's harness measures against. A
/// round that exhausts it returns `Err`, and every caller in `swarm-agents`
/// turns that into a `Veto`. It never returns a synthesized commit.
///
/// # Time
///
/// This function does not sleep and reads no clock. It drains what the
/// transport already holds, feeds it to the node, and advances the node's own
/// round timer with [`ConsensusNode::tick`]. For the solo committee this crate
/// ships that is exact: the commit is produced by `queue_proposal` before the
/// loop is entered.
///
/// # Refusing to spin
///
/// A transport whose `drain` keeps returning envelopes the node has already
/// seen would otherwise loop here forever -- `handle_signed_envelope` dedups
/// them, so there is no commit and no new outbound to break the cycle. The
/// number of inbound envelopes is therefore capped at what a legitimate round
/// can involve: three message kinds from each member, in each round of the
/// budget, plus slack. Exceeding it is an error, not a longer wait.
pub fn drive_round(
    node: &mut ConsensusNode,
    transport: &dyn ConsensusTransport,
    proposal: ConsensusProposal,
    started_at_ms: i64,
) -> Result<ConsensusCommit, ConsensusError> {
    transport.accept_committee(node.committee())?;

    let round_timeout_ms = node.round_timeout_ms();
    // Rounds `0..=max_faulty`, which is `max_faulty + 1` rounds, each lasting
    // `round_timeout_ms`. Expressed as a ROUND count rather than a wall-clock
    // deadline so the driver cannot enter round `f + 1`: a time comparison
    // written the obvious way lets the last tick start a round strictly after
    // the bound and then reports the bound anyway.
    let last_round = node.committee().max_faulty() as u64;
    let budget_ms = round_timeout_ms.saturating_mul(last_round.saturating_add(1) as i64);

    let mut now_ms = started_at_ms;
    let mut outbound = VecDeque::new();
    let max_inbound = last_round
        .saturating_add(1)
        .saturating_mul(3)
        .saturating_mul(node.committee().members().len() as u64)
        .saturating_add(8);
    let mut handled_inbound = 0u64;

    let progress = node.queue_proposal(proposal, now_ms)?;
    if let Some(commit) = progress.commits.into_iter().next() {
        for envelope in progress.outbound {
            transport.publish(&node.sign_outbound(envelope)?)?;
        }
        return Ok(commit);
    }
    outbound.extend(progress.outbound);

    loop {
        while let Some(envelope) = outbound.pop_front() {
            transport.publish(&node.sign_outbound(envelope)?)?;
        }

        let inbound = transport.drain()?;
        let made_progress = !inbound.is_empty();
        for envelope in inbound {
            handled_inbound = handled_inbound.saturating_add(1);
            if handled_inbound > max_inbound {
                return Err(ConsensusError::Transport(format!(
                    "transport delivered more than {max_inbound} envelopes for one round of a                      {}-member committee; refusing to spin",
                    node.committee().members().len(),
                )));
            }
            let progress = node.handle_signed_envelope(&envelope, now_ms)?;
            if let Some(commit) = progress.commits.into_iter().next() {
                for envelope in progress.outbound {
                    transport.publish(&node.sign_outbound(envelope)?)?;
                }
                return Ok(commit);
            }
            outbound.extend(progress.outbound);
        }
        if made_progress {
            continue;
        }

        if node.round() >= last_round {
            break;
        }
        now_ms = now_ms.saturating_add(round_timeout_ms);
        let progress = node.tick(now_ms)?;
        if let Some(commit) = progress.commits.into_iter().next() {
            for envelope in progress.outbound {
                transport.publish(&node.sign_outbound(envelope)?)?;
            }
            return Ok(commit);
        }
        outbound.extend(progress.outbound);
    }

    Err(ConsensusError::InvalidMessage(format!(
        "governance round did not reach threshold {} of committee size {} within {} ms \
         (round_timeout_ms {} x max_faulty+1 {})",
        node.committee().threshold(),
        node.committee().members().len(),
        budget_ms,
        round_timeout_ms,
        last_round.saturating_add(1),
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{ConsensusTransport, SoloGovernorTransport, drive_round};
    use crate::{
        ConsensusCommittee, ConsensusConfig, ConsensusError, ConsensusNode, ConsensusProposal,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use swarm_core::types::AgentId;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn id(key: &SigningKey) -> AgentId {
        AgentId::from_verifying_key(&key.verifying_key())
    }

    fn proposal() -> ConsensusProposal {
        ConsensusProposal {
            proposal_id: "proposal-solo".to_string(),
            payload: json!({ "kind": "response_action" }),
        }
    }

    #[test]
    fn solo_transport_commits_a_one_member_round_and_publishes_only_local_signatures() {
        let local = key(41);
        let committee = ConsensusCommittee::new(vec![id(&local)], 0).unwrap();
        let mut node = ConsensusNode::new_with_signing_key(
            id(&local),
            local.clone(),
            committee,
            ConsensusConfig::default(),
            "governance-bootstrap",
            0,
        )
        .unwrap();
        let transport = SoloGovernorTransport::new();

        let commit = drive_round(&mut node, &transport, proposal(), 0).unwrap();

        assert_eq!(commit.prevote_tally, 1);
        assert_eq!(commit.precommit_tally, 1);
        let published = transport.recent_published();
        assert_eq!(transport.published_total(), published.len() as u64);
        assert!(
            !published.is_empty(),
            "a round that publishes nothing has no transport seam to speak of"
        );
        for envelope in published {
            let verifying_key = envelope.verify().unwrap();
            assert_eq!(
                AgentId::from_verifying_key(&verifying_key),
                id(&local),
                "every envelope must be signed by the one local key"
            );
        }
    }

    #[test]
    fn solo_transport_refuses_a_multi_member_committee() {
        // The whole point of the type. Without this, a four-governor deployment
        // wired to the default transport would run rounds in which no peer ever
        // speaks -- and `drive_round` would report a timeout, not a
        // misconfiguration, so the operator would be told the peers were slow.
        let members = vec![id(&key(1)), id(&key(2)), id(&key(3)), id(&key(4))];
        let committee = ConsensusCommittee::new(members, 1).unwrap();
        let error = SoloGovernorTransport::new()
            .accept_committee(&committee)
            .expect_err("a solo transport must refuse a 4-member committee");
        assert!(
            matches!(error, ConsensusError::InvalidCommittee(ref message)
                if message.contains("cannot serve a committee of 4 members")),
            "unexpected refusal: {error}"
        );
    }

    #[test]
    fn drive_round_refuses_a_transport_that_redelivers_forever() {
        // JetStream redelivery is real and is named in the loss/delay harness's
        // "not exercised" list, so the driver must not hang on it. The node
        // dedups a repeated envelope and produces no commit and no outbound, so
        // without the cap there is nothing to break the loop.
        #[derive(Debug)]
        struct RedeliveringTransport(std::sync::Mutex<Option<crate::ConsensusSignedEnvelope>>);
        impl ConsensusTransport for RedeliveringTransport {
            fn accept_committee(&self, _: &ConsensusCommittee) -> Result<(), ConsensusError> {
                Ok(())
            }
            fn publish(
                &self,
                envelope: &crate::ConsensusSignedEnvelope,
            ) -> Result<(), ConsensusError> {
                let mut slot = self.0.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(envelope.clone());
                }
                Ok(())
            }
            fn drain(&self) -> Result<Vec<crate::ConsensusSignedEnvelope>, ConsensusError> {
                Ok(self.0.lock().unwrap().clone().into_iter().collect())
            }
        }

        let keys = [key(1), key(2), key(3), key(4)];
        let committee =
            ConsensusCommittee::new(keys.iter().map(id).collect::<Vec<_>>(), 1).unwrap();
        // The local node must be the round-0 PROPOSER, otherwise it publishes
        // nothing, the transport has nothing to redeliver, and the test would
        // pass on the round budget instead of on the cap -- which is what the
        // first version of it did.
        let proposer = committee
            .proposer_for("governance-bootstrap", 0)
            .unwrap()
            .clone();
        let local = keys
            .iter()
            .find(|candidate| id(candidate) == proposer)
            .expect("the proposer is a committee member")
            .clone();
        let mut node = ConsensusNode::new_with_signing_key(
            id(&local),
            local,
            committee,
            ConsensusConfig::default(),
            "governance-bootstrap",
            0,
        )
        .unwrap();

        let transport = RedeliveringTransport(std::sync::Mutex::new(None));
        let error = drive_round(&mut node, &transport, proposal(), 0)
            .expect_err("a transport that never stops redelivering must be refused");
        assert!(
            matches!(error, ConsensusError::Transport(ref message)
                if message.contains("refusing to spin")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn drive_round_reports_the_bound_it_gave_up_at_rather_than_committing() {
        // A node that is in the committee but is not the round-0 proposer and
        // hears nothing: the transport delivers no peer votes, so the round can
        // never reach threshold. The driver must fail, and its message must name
        // the deadline it used, because that message becomes a Veto reason.
        #[derive(Debug, Default)]
        struct SilentTransport;
        impl ConsensusTransport for SilentTransport {
            fn accept_committee(&self, _: &ConsensusCommittee) -> Result<(), ConsensusError> {
                Ok(())
            }
            fn publish(&self, _: &crate::ConsensusSignedEnvelope) -> Result<(), ConsensusError> {
                Ok(())
            }
            fn drain(&self) -> Result<Vec<crate::ConsensusSignedEnvelope>, ConsensusError> {
                Ok(Vec::new())
            }
        }

        let members = vec![id(&key(1)), id(&key(2)), id(&key(3)), id(&key(4))];
        let committee = ConsensusCommittee::new(members, 1).unwrap();
        let local = key(1);
        let config = ConsensusConfig {
            round_timeout_ms: 100,
            ..ConsensusConfig::default()
        };
        let mut node = ConsensusNode::new_with_signing_key(
            id(&local),
            local,
            committee,
            config,
            "governance-bootstrap",
            0,
        )
        .unwrap();

        let error = drive_round(&mut node, &SilentTransport, proposal(), 0)
            .expect_err("a silent 4-member round must not commit");
        let message = error.to_string();
        assert!(
            message.contains("did not reach threshold 3 of committee size 4 within 200 ms"),
            "the failure must name the threshold and the bound it used: {message}"
        );
    }
}
