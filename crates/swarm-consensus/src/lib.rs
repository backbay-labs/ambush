//! BFT consensus protocol for critical swarm decisions.
//!
//! Used when the swarm must agree before acting:
//! - Response actions (block, isolate, revoke)
//! - Evolution commits (new strategy goes live)
//! - Trust decisions (admit/revoke agents)
//!
//! Implements Tendermint-style propose-prevote-precommit
//! among a rotating Tom committee. Tolerates f Byzantine faults
//! with 2f+1 agreement out of 3f+1 voters.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use swarm_core::types::AgentId;
use swarm_crypto::{
    DetachedSignature, canonical_json_bytes, sha256, sha256_hex, verify_detached_signature,
};

pub const DEFAULT_CONSENSUS_SUBJECT_PREFIX: &str = "swarm.consensus";
pub const CONSENSUS_RECEIPT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("invalid consensus committee: {0}")]
    InvalidCommittee(String),

    #[error("invalid consensus message: {0}")]
    InvalidMessage(String),

    #[error("failed to encode consensus payload: {0}")]
    Encode(#[from] serde_json::Error),

    #[error("failed to canonicalize consensus payload: {0}")]
    Crypto(#[from] swarm_crypto::CryptoError),

    #[error("local node `{0}` cannot issue signed receipts without a signing key")]
    SigningUnavailable(AgentId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CommitteeSeedPayload<'a> {
    previous_commit_hash: &'a str,
    members: &'a [AgentId],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProposerSelectionPayload<'a> {
    previous_commit_hash: &'a str,
    round: u64,
    agent_id: &'a AgentId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CommitteeDescriptor<'a> {
    members: &'a [AgentId],
    max_faulty: usize,
}

pub fn recommended_max_faulty(committee_size: usize) -> usize {
    if committee_size <= 1 {
        0
    } else {
        (committee_size - 1) / 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusCommittee {
    members: Vec<AgentId>,
    max_faulty: usize,
    threshold: usize,
    committee_id: String,
}

impl ConsensusCommittee {
    pub fn new(members: Vec<AgentId>, max_faulty: usize) -> Result<Self, ConsensusError> {
        if members.is_empty() {
            return Err(ConsensusError::InvalidCommittee(
                "committee must contain at least one member".to_string(),
            ));
        }

        let mut deduped = members;
        deduped.sort();
        deduped.dedup();

        let threshold = max_faulty
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                ConsensusError::InvalidCommittee(
                    "fault tolerance threshold overflowed usize".to_string(),
                )
            })?;

        if deduped.len() < threshold {
            return Err(ConsensusError::InvalidCommittee(format!(
                "committee size {} cannot satisfy 2f+1 threshold {}",
                deduped.len(),
                threshold
            )));
        }

        let committee_id = sha256_hex(&canonical_json_bytes(&CommitteeDescriptor {
            members: &deduped,
            max_faulty,
        })?);

        Ok(Self {
            members: deduped,
            max_faulty,
            threshold,
            committee_id,
        })
    }

    pub fn members(&self) -> &[AgentId] {
        &self.members
    }

    pub fn max_faulty(&self) -> usize {
        self.max_faulty
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn committee_id(&self) -> &str {
        &self.committee_id
    }

    pub fn contains(&self, agent_id: &AgentId) -> bool {
        self.members.binary_search(agent_id).is_ok()
    }

    pub fn proposer_for(
        &self,
        previous_commit_hash: &str,
        round: u64,
    ) -> Result<&AgentId, ConsensusError> {
        let _committee_seed = canonical_json_bytes(&CommitteeSeedPayload {
            previous_commit_hash,
            members: &self.members,
        })?;
        let mut best: Option<(&AgentId, String)> = None;
        for agent_id in &self.members {
            let score = sha256_hex(&canonical_json_bytes(&ProposerSelectionPayload {
                previous_commit_hash,
                round,
                agent_id,
            })?);
            if best.as_ref().is_none_or(|(_, current)| score > *current) {
                best = Some((agent_id, score));
            }
        }

        best.map(|(agent_id, _)| agent_id).ok_or_else(|| {
            ConsensusError::InvalidCommittee(
                "committee must contain at least one member".to_string(),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetStreamSubjectLayout {
    prefix: String,
}

impl Default for JetStreamSubjectLayout {
    fn default() -> Self {
        Self::new(DEFAULT_CONSENSUS_SUBJECT_PREFIX)
    }
}

impl JetStreamSubjectLayout {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn round_subject(&self, committee: &ConsensusCommittee, height: u64, round: u64) -> String {
        format!(
            "{}.{}.height.{}.round.{}",
            self.prefix,
            committee.committee_id(),
            height,
            round
        )
    }

    pub fn height_wildcard(&self, committee: &ConsensusCommittee, height: u64) -> String {
        format!(
            "{}.{}.height.{}.round.*",
            self.prefix,
            committee.committee_id(),
            height
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusStep {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusProposal {
    pub proposal_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignedMessageKind {
    Proposal,
    Prevote,
    Precommit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsensusMessageBody {
    Proposal { proposal: ConsensusProposal },
    Prevote { proposal_id: Option<String> },
    Precommit { proposal_id: Option<String> },
}

impl ConsensusMessageBody {
    fn kind(&self) -> SignedMessageKind {
        match self {
            Self::Proposal { .. } => SignedMessageKind::Proposal,
            Self::Prevote { .. } => SignedMessageKind::Prevote,
            Self::Precommit { .. } => SignedMessageKind::Precommit,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusMessage {
    pub height: u64,
    pub round: u64,
    pub previous_commit_hash: String,
    pub from: AgentId,
    pub sent_at_ms: i64,
    #[serde(flatten)]
    pub body: ConsensusMessageBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusEnvelope {
    pub subject: String,
    pub message: ConsensusMessage,
}

impl ConsensusEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, ConsensusError> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ConsensusError> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusSignedEnvelope {
    pub envelope: ConsensusEnvelope,
    pub signature: DetachedSignature,
}

impl ConsensusSignedEnvelope {
    pub fn sign(
        envelope: ConsensusEnvelope,
        signing_key: &SigningKey,
    ) -> Result<Self, ConsensusError> {
        let payload = canonical_json_bytes(&envelope)?;
        Ok(Self {
            envelope,
            signature: detached_signature(signing_key, &payload),
        })
    }

    pub fn verify(&self) -> Result<VerifyingKey, ConsensusError> {
        let payload = canonical_json_bytes(&self.envelope)?;
        verify_detached_signature(&payload, &self.signature).map_err(ConsensusError::Crypto)?;
        let key_bytes = hex::decode(&self.signature.public_key_hex).map_err(|error| {
            ConsensusError::InvalidMessage(format!("invalid signer public key hex: {error}"))
        })?;
        let verifying_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            ConsensusError::InvalidMessage(format!(
                "expected 32-byte signer public key, got {}",
                key_bytes.len()
            ))
        })?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key).map_err(|error| {
            ConsensusError::InvalidMessage(format!("invalid signer public key: {error}"))
        })?;
        let derived_id = AgentId::from_verifying_key(&verifying_key);
        if derived_id != self.envelope.message.from {
            return Err(ConsensusError::InvalidMessage(format!(
                "signer identity mismatch: message declared `{}` but signature key derives `{}`",
                self.envelope.message.from, derived_id
            )));
        }
        Ok(verifying_key)
    }

    pub fn message_hash(&self) -> Result<String, ConsensusError> {
        Ok(sha256_hex(&canonical_json_bytes(self)?))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusCommit {
    pub height: u64,
    pub round: u64,
    pub committee_id: String,
    pub proposal: ConsensusProposal,
    pub prevote_tally: usize,
    pub precommit_tally: usize,
    pub commit_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceReceiptDecision {
    Approve,
    Veto,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusGovernanceReceiptPayload {
    pub schema_version: u32,
    pub receipt_id: String,
    pub decision: GovernanceReceiptDecision,
    pub committee_id: String,
    pub committee_members: Vec<AgentId>,
    pub threshold: usize,
    pub height: u64,
    pub round: u64,
    pub previous_commit_hash: String,
    pub commit_hash: String,
    pub proposal_id: String,
    pub prevote_tally: usize,
    pub precommit_tally: usize,
    pub issued_by: AgentId,
    pub issued_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusGovernanceReceipt {
    pub payload: ConsensusGovernanceReceiptPayload,
    pub signature: DetachedSignature,
}

impl ConsensusGovernanceReceipt {
    pub fn issue(
        commit: &ConsensusCommit,
        previous_commit_hash: &str,
        committee: &ConsensusCommittee,
        decision: GovernanceReceiptDecision,
        issued_by: AgentId,
        signing_key: &SigningKey,
        issued_at_ms: i64,
    ) -> Result<Self, ConsensusError> {
        let payload = ConsensusGovernanceReceiptPayload {
            schema_version: CONSENSUS_RECEIPT_SCHEMA_VERSION,
            receipt_id: sha256_hex(&canonical_json_bytes(&serde_json::json!({
                "decision": decision,
                "height": commit.height,
                "round": commit.round,
                "commit_hash": commit.commit_hash,
                "issued_by": issued_by,
                "issued_at_ms": issued_at_ms,
            }))?),
            decision,
            committee_id: committee.committee_id().to_string(),
            committee_members: committee.members().to_vec(),
            threshold: committee.threshold(),
            height: commit.height,
            round: commit.round,
            previous_commit_hash: previous_commit_hash.to_string(),
            commit_hash: commit.commit_hash.clone(),
            proposal_id: commit.proposal.proposal_id.clone(),
            prevote_tally: commit.prevote_tally,
            precommit_tally: commit.precommit_tally,
            issued_by,
            issued_at_ms,
        };
        let payload_bytes = canonical_json_bytes(&payload)?;
        Ok(Self {
            payload,
            signature: detached_signature(signing_key, &payload_bytes),
        })
    }

    pub fn verify(&self) -> Result<VerifyingKey, ConsensusError> {
        let payload = canonical_json_bytes(&self.payload)?;
        verify_detached_signature(&payload, &self.signature).map_err(ConsensusError::Crypto)?;
        let key_bytes = hex::decode(&self.signature.public_key_hex).map_err(|error| {
            ConsensusError::InvalidMessage(format!("invalid signer public key hex: {error}"))
        })?;
        let verifying_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            ConsensusError::InvalidMessage(format!(
                "expected 32-byte signer public key, got {}",
                key_bytes.len()
            ))
        })?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key).map_err(|error| {
            ConsensusError::InvalidMessage(format!("invalid signer public key: {error}"))
        })?;
        let derived_id = AgentId::from_verifying_key(&verifying_key);
        if derived_id != self.payload.issued_by {
            return Err(ConsensusError::InvalidMessage(format!(
                "receipt signer mismatch: payload issued_by `{}` but signature key derives `{}`",
                self.payload.issued_by, derived_id
            )));
        }
        Ok(verifying_key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusExclusionReason {
    InvalidSignature,
    Equivocation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusExclusionReceiptPayload {
    pub schema_version: u32,
    pub receipt_id: String,
    pub committee_id: String,
    pub height: u64,
    pub round: u64,
    pub excluded_agent_id: AgentId,
    pub message_kind: SignedMessageKind,
    pub reason: ConsensusExclusionReason,
    pub evidence_hashes: Vec<String>,
    pub issued_by: AgentId,
    pub issued_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusExclusionReceipt {
    pub payload: ConsensusExclusionReceiptPayload,
    pub signature: DetachedSignature,
}

impl ConsensusExclusionReceipt {
    pub fn verify(&self) -> Result<VerifyingKey, ConsensusError> {
        let payload = canonical_json_bytes(&self.payload)?;
        verify_detached_signature(&payload, &self.signature).map_err(ConsensusError::Crypto)?;
        let key_bytes = hex::decode(&self.signature.public_key_hex).map_err(|error| {
            ConsensusError::InvalidMessage(format!("invalid signer public key hex: {error}"))
        })?;
        let verifying_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            ConsensusError::InvalidMessage(format!(
                "expected 32-byte signer public key, got {}",
                key_bytes.len()
            ))
        })?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key).map_err(|error| {
            ConsensusError::InvalidMessage(format!("invalid signer public key: {error}"))
        })?;
        let derived_id = AgentId::from_verifying_key(&verifying_key);
        if derived_id != self.payload.issued_by {
            return Err(ConsensusError::InvalidMessage(format!(
                "exclusion signer mismatch: payload issued_by `{}` but signature key derives `{}`",
                self.payload.issued_by, derived_id
            )));
        }
        Ok(verifying_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusConfig {
    pub round_timeout_ms: i64,
    pub subject_layout: JetStreamSubjectLayout,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            round_timeout_ms: 1_000,
            subject_layout: JetStreamSubjectLayout::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConsensusProgress {
    pub outbound: Vec<ConsensusEnvelope>,
    pub commits: Vec<ConsensusCommit>,
    pub exclusions: Vec<ConsensusExclusionReceipt>,
    pub round_advanced: bool,
}

impl ConsensusProgress {
    fn extend(&mut self, other: Self) {
        self.outbound.extend(other.outbound);
        self.commits.extend(other.commits);
        self.exclusions.extend(other.exclusions);
        self.round_advanced |= other.round_advanced;
    }

    fn push_outbound(&mut self, envelope: ConsensusEnvelope) {
        self.outbound.push(envelope);
    }
}

#[derive(Debug, Clone, Default)]
struct VoteLedger {
    by_agent: BTreeMap<AgentId, Option<String>>,
    by_value: BTreeMap<Option<String>, BTreeSet<AgentId>>,
}

impl VoteLedger {
    fn record_vote(
        &mut self,
        voter: &AgentId,
        proposal_id: Option<&str>,
    ) -> Result<usize, ConsensusError> {
        let choice = proposal_id.map(str::to_string);
        if let Some(existing) = self.by_agent.get(voter) {
            if existing == &choice {
                return Ok(self.count(choice.as_deref()));
            }

            return Err(ConsensusError::InvalidMessage(format!(
                "agent `{voter}` cast conflicting votes in the same round"
            )));
        }

        self.by_agent.insert(voter.clone(), choice.clone());
        self.by_value
            .entry(choice)
            .or_default()
            .insert(voter.clone());
        Ok(self.count(proposal_id))
    }

    fn remove_voter(&mut self, voter: &AgentId) {
        let Some(choice) = self.by_agent.remove(voter) else {
            return;
        };
        if let Some(voters) = self.by_value.get_mut(&choice) {
            voters.remove(voter);
            if voters.is_empty() {
                self.by_value.remove(&choice);
            }
        }
    }

    fn count(&self, proposal_id: Option<&str>) -> usize {
        self.by_value
            .get(&proposal_id.map(str::to_string))
            .map(BTreeSet::len)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SignedMessageKey {
    height: u64,
    round: u64,
    from: AgentId,
    kind: SignedMessageKind,
}

impl SignedMessageKey {
    fn from_message(message: &ConsensusMessage) -> Self {
        Self {
            height: message.height,
            round: message.round,
            from: message.from.clone(),
            kind: message.body.kind(),
        }
    }
}

pub struct ConsensusNode {
    local_agent_id: AgentId,
    local_signing_key: Option<SigningKey>,
    committee: ConsensusCommittee,
    config: ConsensusConfig,
    height: u64,
    round: u64,
    step: ConsensusStep,
    previous_commit_hash: String,
    round_started_at_ms: i64,
    proposals: BTreeMap<u64, ConsensusProposal>,
    prevotes: BTreeMap<u64, VoteLedger>,
    precommits: BTreeMap<u64, VoteLedger>,
    emitted_prevotes: BTreeSet<u64>,
    emitted_precommits: BTreeSet<u64>,
    pending_local_proposal: Option<ConsensusProposal>,
    seen_signed_messages: BTreeMap<SignedMessageKey, ConsensusSignedEnvelope>,
    excluded_members: BTreeMap<(u64, u64), BTreeSet<AgentId>>,
}

impl ConsensusNode {
    pub fn new(
        local_agent_id: AgentId,
        committee: ConsensusCommittee,
        config: ConsensusConfig,
        previous_commit_hash: impl Into<String>,
        started_at_ms: i64,
    ) -> Result<Self, ConsensusError> {
        Self::new_internal(
            local_agent_id,
            None,
            committee,
            config,
            previous_commit_hash,
            started_at_ms,
        )
    }

    pub fn new_with_signing_key(
        local_agent_id: AgentId,
        signing_key: SigningKey,
        committee: ConsensusCommittee,
        config: ConsensusConfig,
        previous_commit_hash: impl Into<String>,
        started_at_ms: i64,
    ) -> Result<Self, ConsensusError> {
        Self::new_internal(
            local_agent_id,
            Some(signing_key),
            committee,
            config,
            previous_commit_hash,
            started_at_ms,
        )
    }

    fn new_internal(
        local_agent_id: AgentId,
        local_signing_key: Option<SigningKey>,
        committee: ConsensusCommittee,
        config: ConsensusConfig,
        previous_commit_hash: impl Into<String>,
        started_at_ms: i64,
    ) -> Result<Self, ConsensusError> {
        if !committee.contains(&local_agent_id) {
            return Err(ConsensusError::InvalidCommittee(format!(
                "local node `{local_agent_id}` is not in the committee"
            )));
        }
        if config.round_timeout_ms <= 0 {
            return Err(ConsensusError::InvalidCommittee(
                "round timeout must be greater than zero".to_string(),
            ));
        }

        Ok(Self {
            local_agent_id,
            local_signing_key,
            committee,
            config,
            height: 1,
            round: 0,
            step: ConsensusStep::Propose,
            previous_commit_hash: previous_commit_hash.into(),
            round_started_at_ms: started_at_ms,
            proposals: BTreeMap::new(),
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            emitted_prevotes: BTreeSet::new(),
            emitted_precommits: BTreeSet::new(),
            pending_local_proposal: None,
            seen_signed_messages: BTreeMap::new(),
            excluded_members: BTreeMap::new(),
        })
    }

    pub fn local_agent_id(&self) -> &AgentId {
        &self.local_agent_id
    }

    pub fn committee(&self) -> &ConsensusCommittee {
        &self.committee
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn step(&self) -> &ConsensusStep {
        &self.step
    }

    pub fn previous_commit_hash(&self) -> &str {
        &self.previous_commit_hash
    }

    pub fn proposer_for_current_round(&self) -> Result<&AgentId, ConsensusError> {
        self.committee
            .proposer_for(&self.previous_commit_hash, self.round)
    }

    pub fn queue_proposal(
        &mut self,
        proposal: ConsensusProposal,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        self.pending_local_proposal = Some(proposal);
        self.emit_proposal_if_leader(now_ms)
    }

    pub fn tick(&mut self, now_ms: i64) -> Result<ConsensusProgress, ConsensusError> {
        if now_ms - self.round_started_at_ms < self.config.round_timeout_ms {
            return Ok(ConsensusProgress::default());
        }
        self.advance_round(self.round + 1, now_ms)
    }

    pub fn handle_envelope(
        &mut self,
        envelope: &ConsensusEnvelope,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        let expected_subject = self.config.subject_layout.round_subject(
            &self.committee,
            envelope.message.height,
            envelope.message.round,
        );
        if envelope.subject != expected_subject {
            return Err(ConsensusError::InvalidMessage(format!(
                "message subject `{}` did not match expected round subject `{expected_subject}`",
                envelope.subject
            )));
        }
        self.observe_message(&envelope.message, now_ms)
    }

    pub fn handle_signed_envelope(
        &mut self,
        envelope: &ConsensusSignedEnvelope,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        let key = SignedMessageKey::from_message(&envelope.envelope.message);
        if self.is_excluded(key.height, key.round, &key.from) {
            return Ok(ConsensusProgress::default());
        }

        if let Some(previous) = self.seen_signed_messages.get(&key) {
            if previous == envelope {
                return Ok(ConsensusProgress::default());
            }

            return self.exclude_sender(
                key.height,
                key.round,
                key.kind,
                &key.from,
                ConsensusExclusionReason::Equivocation,
                vec![previous.message_hash()?, envelope.message_hash()?],
                now_ms,
            );
        }

        if envelope.verify().is_err() {
            return self.exclude_sender(
                key.height,
                key.round,
                key.kind,
                &key.from,
                ConsensusExclusionReason::InvalidSignature,
                vec![envelope.message_hash()?],
                now_ms,
            );
        }

        self.seen_signed_messages.insert(key, envelope.clone());
        self.handle_envelope(&envelope.envelope, now_ms)
    }

    fn observe_message(
        &mut self,
        message: &ConsensusMessage,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        if !self.committee.contains(&message.from) {
            return Err(ConsensusError::InvalidMessage(format!(
                "message sender `{}` is not a committee member",
                message.from
            )));
        }
        if message.height < self.height {
            return Ok(ConsensusProgress::default());
        }
        if message.height > self.height {
            return Err(ConsensusError::InvalidMessage(format!(
                "message height {} is ahead of local height {}",
                message.height, self.height
            )));
        }
        if message.previous_commit_hash != self.previous_commit_hash {
            return Ok(ConsensusProgress::default());
        }
        if message.round < self.round {
            return Ok(ConsensusProgress::default());
        }
        if message.round > self.round {
            let _ = self.advance_round(message.round, now_ms)?;
        }

        match &message.body {
            ConsensusMessageBody::Proposal { proposal } => {
                self.observe_proposal(&message.from, message.round, proposal.clone(), now_ms)
            }
            ConsensusMessageBody::Prevote { proposal_id } => {
                self.observe_prevote(&message.from, message.round, proposal_id.clone(), now_ms)
            }
            ConsensusMessageBody::Precommit { proposal_id } => {
                self.observe_precommit(&message.from, message.round, proposal_id.clone(), now_ms)
            }
        }
    }

    fn emit_proposal_if_leader(
        &mut self,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        let proposer = self.proposer_for_current_round()?;
        if proposer != &self.local_agent_id {
            return Ok(ConsensusProgress::default());
        }
        if self.proposals.contains_key(&self.round) {
            return Ok(ConsensusProgress::default());
        }
        let Some(proposal) = self.pending_local_proposal.clone() else {
            return Ok(ConsensusProgress::default());
        };
        self.observe_local_proposal(self.round, proposal, now_ms)
    }

    fn observe_local_proposal(
        &mut self,
        round: u64,
        proposal: ConsensusProposal,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        self.record_proposal(&self.local_agent_id.clone(), round, &proposal)?;
        let mut progress = ConsensusProgress::default();
        progress.push_outbound(self.build_envelope(
            round,
            ConsensusMessageBody::Proposal {
                proposal: proposal.clone(),
            },
            now_ms,
        ));
        let follow_up = self.emit_prevote(round, Some(proposal.proposal_id.clone()), now_ms)?;
        progress.extend(follow_up);
        Ok(progress)
    }

    fn observe_proposal(
        &mut self,
        from: &AgentId,
        round: u64,
        proposal: ConsensusProposal,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        self.record_proposal(from, round, &proposal)?;
        if self.emitted_prevotes.contains(&round) {
            return Ok(ConsensusProgress::default());
        }
        self.emit_prevote(round, Some(proposal.proposal_id), now_ms)
    }

    fn observe_prevote(
        &mut self,
        from: &AgentId,
        round: u64,
        proposal_id: Option<String>,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        let count = self
            .prevotes
            .entry(round)
            .or_default()
            .record_vote(from, proposal_id.as_deref())?;
        if count >= self.committee.threshold() && !self.emitted_precommits.contains(&round) {
            return self.emit_precommit(round, proposal_id, now_ms);
        }
        Ok(ConsensusProgress::default())
    }

    fn observe_precommit(
        &mut self,
        from: &AgentId,
        round: u64,
        proposal_id: Option<String>,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        let count = self
            .precommits
            .entry(round)
            .or_default()
            .record_vote(from, proposal_id.as_deref())?;
        if count >= self.committee.threshold() {
            return self.commit(round, proposal_id, now_ms);
        }
        Ok(ConsensusProgress::default())
    }

    fn emit_prevote(
        &mut self,
        round: u64,
        proposal_id: Option<String>,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        if !self.emitted_prevotes.insert(round) {
            return Ok(ConsensusProgress::default());
        }
        self.step = ConsensusStep::Prevote;
        let count = self
            .prevotes
            .entry(round)
            .or_default()
            .record_vote(&self.local_agent_id, proposal_id.as_deref())?;
        let mut progress = ConsensusProgress::default();
        progress.push_outbound(self.build_envelope(
            round,
            ConsensusMessageBody::Prevote {
                proposal_id: proposal_id.clone(),
            },
            now_ms,
        ));
        if count >= self.committee.threshold() && !self.emitted_precommits.contains(&round) {
            let follow_up = self.emit_precommit(round, proposal_id, now_ms)?;
            progress.extend(follow_up);
        }
        Ok(progress)
    }

    fn emit_precommit(
        &mut self,
        round: u64,
        proposal_id: Option<String>,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        if !self.emitted_precommits.insert(round) {
            return Ok(ConsensusProgress::default());
        }
        self.step = ConsensusStep::Precommit;
        let count = self
            .precommits
            .entry(round)
            .or_default()
            .record_vote(&self.local_agent_id, proposal_id.as_deref())?;
        let mut progress = ConsensusProgress::default();
        progress.push_outbound(self.build_envelope(
            round,
            ConsensusMessageBody::Precommit {
                proposal_id: proposal_id.clone(),
            },
            now_ms,
        ));
        if count >= self.committee.threshold() {
            let follow_up = self.commit(round, proposal_id, now_ms)?;
            progress.extend(follow_up);
        }
        Ok(progress)
    }

    fn commit(
        &mut self,
        round: u64,
        proposal_id: Option<String>,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        let Some(proposal_id) = proposal_id else {
            return Ok(ConsensusProgress::default());
        };
        let Some(proposal) = self.proposals.get(&round) else {
            return Ok(ConsensusProgress::default());
        };
        if proposal.proposal_id != proposal_id {
            return Ok(ConsensusProgress::default());
        }

        let prevote_tally = self
            .prevotes
            .get(&round)
            .map(|ledger| ledger.count(Some(proposal_id.as_str())))
            .unwrap_or_default();
        let precommit_tally = self
            .precommits
            .get(&round)
            .map(|ledger| ledger.count(Some(proposal_id.as_str())))
            .unwrap_or_default();
        if prevote_tally < self.committee.threshold()
            || precommit_tally < self.committee.threshold()
        {
            return Ok(ConsensusProgress::default());
        }

        let commit_hash = sha256_hex(&canonical_json_bytes(&serde_json::json!({
            "height": self.height,
            "round": round,
            "previous_commit_hash": self.previous_commit_hash,
            "proposal_id": proposal.proposal_id,
            "payload": proposal.payload,
        }))?);

        let commit = ConsensusCommit {
            height: self.height,
            round,
            committee_id: self.committee.committee_id().to_string(),
            proposal: proposal.clone(),
            prevote_tally,
            precommit_tally,
            commit_hash: commit_hash.clone(),
        };

        if self
            .pending_local_proposal
            .as_ref()
            .map(|pending| pending.proposal_id.as_str())
            == Some(commit.proposal.proposal_id.as_str())
        {
            self.pending_local_proposal = None;
        }

        self.height = self.height.saturating_add(1);
        self.round = 0;
        self.step = ConsensusStep::Commit;
        self.previous_commit_hash = commit_hash;
        self.round_started_at_ms = now_ms;
        self.proposals.clear();
        self.prevotes.clear();
        self.precommits.clear();
        self.emitted_prevotes.clear();
        self.emitted_precommits.clear();
        self.step = ConsensusStep::Propose;

        let mut progress = ConsensusProgress::default();
        progress.commits.push(commit);
        Ok(progress)
    }

    fn advance_round(
        &mut self,
        target_round: u64,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        if target_round <= self.round {
            return Ok(ConsensusProgress::default());
        }
        self.round = target_round;
        self.step = ConsensusStep::Propose;
        self.round_started_at_ms = now_ms;

        let mut progress = ConsensusProgress {
            round_advanced: true,
            ..ConsensusProgress::default()
        };
        let follow_up = self.emit_proposal_if_leader(now_ms)?;
        progress.extend(follow_up);
        Ok(progress)
    }

    fn record_proposal(
        &mut self,
        from: &AgentId,
        round: u64,
        proposal: &ConsensusProposal,
    ) -> Result<(), ConsensusError> {
        let expected = self
            .committee
            .proposer_for(&self.previous_commit_hash, round)?;
        if from != expected {
            return Err(ConsensusError::InvalidMessage(format!(
                "proposal for round {round} came from `{from}` but proposer is `{expected}`"
            )));
        }

        if let Some(existing) = self.proposals.get(&round) {
            if existing == proposal {
                return Ok(());
            }
            return Err(ConsensusError::InvalidMessage(format!(
                "round {round} already recorded proposal `{}`",
                existing.proposal_id
            )));
        }

        self.proposals.insert(round, proposal.clone());
        Ok(())
    }

    fn build_envelope(
        &self,
        round: u64,
        body: ConsensusMessageBody,
        now_ms: i64,
    ) -> ConsensusEnvelope {
        ConsensusEnvelope {
            subject: self
                .config
                .subject_layout
                .round_subject(&self.committee, self.height, round),
            message: ConsensusMessage {
                height: self.height,
                round,
                previous_commit_hash: self.previous_commit_hash.clone(),
                from: self.local_agent_id.clone(),
                sent_at_ms: now_ms,
                body,
            },
        }
    }

    fn is_excluded(&self, height: u64, round: u64, agent_id: &AgentId) -> bool {
        self.excluded_members
            .get(&(height, round))
            .is_some_and(|members| members.contains(agent_id))
    }

    #[allow(clippy::too_many_arguments)]
    fn exclude_sender(
        &mut self,
        height: u64,
        round: u64,
        message_kind: SignedMessageKind,
        agent_id: &AgentId,
        reason: ConsensusExclusionReason,
        evidence_hashes: Vec<String>,
        now_ms: i64,
    ) -> Result<ConsensusProgress, ConsensusError> {
        self.excluded_members
            .entry((height, round))
            .or_default()
            .insert(agent_id.clone());
        self.drop_sender_round_contributions(round, agent_id);
        let Some(signing_key) = self.local_signing_key.as_ref() else {
            return Ok(ConsensusProgress::default());
        };
        let receipt = self.issue_exclusion_receipt(
            height,
            round,
            message_kind,
            agent_id.clone(),
            reason,
            evidence_hashes,
            signing_key,
            now_ms,
        )?;
        Ok(ConsensusProgress {
            exclusions: vec![receipt],
            ..ConsensusProgress::default()
        })
    }

    fn drop_sender_round_contributions(&mut self, round: u64, agent_id: &AgentId) {
        if self
            .committee
            .proposer_for(&self.previous_commit_hash, round)
            .is_ok_and(|proposer| proposer == agent_id)
        {
            self.proposals.remove(&round);
        }
        if let Some(ledger) = self.prevotes.get_mut(&round) {
            ledger.remove_voter(agent_id);
        }
        if let Some(ledger) = self.precommits.get_mut(&round) {
            ledger.remove_voter(agent_id);
        }
        self.seen_signed_messages.retain(|key, _| {
            !(key.height == self.height && key.round == round && &key.from == agent_id)
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_exclusion_receipt(
        &self,
        height: u64,
        round: u64,
        message_kind: SignedMessageKind,
        excluded_agent_id: AgentId,
        reason: ConsensusExclusionReason,
        evidence_hashes: Vec<String>,
        signing_key: &SigningKey,
        issued_at_ms: i64,
    ) -> Result<ConsensusExclusionReceipt, ConsensusError> {
        let payload = ConsensusExclusionReceiptPayload {
            schema_version: CONSENSUS_RECEIPT_SCHEMA_VERSION,
            receipt_id: sha256_hex(&canonical_json_bytes(&serde_json::json!({
                "height": height,
                "round": round,
                "excluded_agent_id": excluded_agent_id,
                "reason": reason,
                "evidence_hashes": evidence_hashes,
                "issued_by": self.local_agent_id,
                "issued_at_ms": issued_at_ms,
            }))?),
            committee_id: self.committee.committee_id().to_string(),
            height,
            round,
            excluded_agent_id,
            message_kind,
            reason,
            evidence_hashes,
            issued_by: self.local_agent_id.clone(),
            issued_at_ms,
        };
        let payload_bytes = canonical_json_bytes(&payload)?;
        Ok(ConsensusExclusionReceipt {
            payload,
            signature: detached_signature(signing_key, &payload_bytes),
        })
    }
}

fn detached_signature(signing_key: &SigningKey, payload: &[u8]) -> DetachedSignature {
    let signature = signing_key.sign(payload);
    let verifying_key = signing_key.verifying_key();
    DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: sha256(verifying_key.as_bytes()).to_hex(),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ConsensusCommittee, ConsensusConfig, ConsensusEnvelope, ConsensusNode, ConsensusProgress,
        ConsensusProposal, ConsensusSignedEnvelope, DEFAULT_CONSENSUS_SUBJECT_PREFIX,
        JetStreamSubjectLayout,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use swarm_core::types::AgentId;

    #[derive(Clone)]
    struct CommitteeMember {
        agent_id: AgentId,
        signing_key: SigningKey,
    }

    fn member(seed: u8) -> CommitteeMember {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        CommitteeMember {
            agent_id: AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
        }
    }

    fn committee_members() -> Vec<CommitteeMember> {
        vec![member(1), member(2), member(3)]
    }

    fn committee() -> ConsensusCommittee {
        ConsensusCommittee::new(
            committee_members()
                .into_iter()
                .map(|member| member.agent_id)
                .collect(),
            1,
        )
        .unwrap()
    }

    fn proposal(index: usize) -> ConsensusProposal {
        ConsensusProposal {
            proposal_id: format!("proposal-{index}"),
            payload: json!({
                "sequence": index,
                "kind": "response_action",
            }),
        }
    }

    struct InProcessHarness {
        now_ms: i64,
        members: Vec<CommitteeMember>,
        member_map: BTreeMap<AgentId, SigningKey>,
        nodes: Vec<ConsensusNode>,
        pending: VecDeque<ConsensusSignedEnvelope>,
    }

    impl InProcessHarness {
        fn new(previous_commit_hash: &str) -> Self {
            let members = committee_members();
            let member_map = members
                .iter()
                .map(|member| (member.agent_id.clone(), member.signing_key.clone()))
                .collect::<BTreeMap<_, _>>();
            let committee = ConsensusCommittee::new(
                members
                    .iter()
                    .map(|member| member.agent_id.clone())
                    .collect(),
                1,
            )
            .unwrap();
            let config = ConsensusConfig {
                round_timeout_ms: 25,
                subject_layout: JetStreamSubjectLayout::default(),
            };
            let nodes = members
                .iter()
                .map(|member| {
                    ConsensusNode::new_with_signing_key(
                        member.agent_id.clone(),
                        member.signing_key.clone(),
                        committee.clone(),
                        config.clone(),
                        previous_commit_hash.to_string(),
                        0,
                    )
                    .unwrap()
                })
                .collect();
            Self {
                now_ms: 0,
                members,
                member_map,
                nodes,
                pending: VecDeque::new(),
            }
        }

        fn queue_on_all(&mut self, proposal: ConsensusProposal) {
            let mut outbound = Vec::new();
            for node in &mut self.nodes {
                outbound.push(node.queue_proposal(proposal.clone(), self.now_ms).unwrap());
            }
            for progress in outbound {
                self.collect(progress);
            }
        }

        fn collect(&mut self, progress: ConsensusProgress) {
            for envelope in progress.outbound {
                let signing_key = self
                    .member_map
                    .get(&envelope.message.from)
                    .expect("missing signing key for committee member");
                self.pending
                    .push_back(ConsensusSignedEnvelope::sign(envelope, signing_key).unwrap());
            }
        }

        fn flush(
            &mut self,
        ) -> (
            Vec<super::ConsensusCommit>,
            Vec<super::ConsensusExclusionReceipt>,
        ) {
            let mut commits = Vec::new();
            let mut exclusions = Vec::new();
            while let Some(envelope) = self.pending.pop_front() {
                let mut outbound = Vec::new();
                for node in &mut self.nodes {
                    let progress = node.handle_signed_envelope(&envelope, self.now_ms).unwrap();
                    commits.extend(progress.commits.clone());
                    exclusions.extend(progress.exclusions.clone());
                    outbound.push(progress);
                }
                for progress in outbound {
                    self.collect(progress);
                }
            }
            (commits, exclusions)
        }

        fn elapse_round_timeout(&mut self) {
            self.now_ms += 25;
            let mut outbound = Vec::new();
            for node in &mut self.nodes {
                outbound.push(node.tick(self.now_ms).unwrap());
            }
            for progress in outbound {
                self.collect(progress);
            }
        }
    }

    #[test]
    fn committee_rotation_depends_on_previous_commit_hash_and_agent_ids() {
        let committee = committee();

        let baseline = committee.proposer_for("commit-a", 0).unwrap().clone();
        let same_again = committee.proposer_for("commit-a", 0).unwrap().clone();
        assert_eq!(baseline, same_again);

        let proposer_variants = ["commit-a", "commit-b", "commit-c", "commit-d"]
            .into_iter()
            .map(|previous_commit_hash| {
                committee
                    .proposer_for(previous_commit_hash, 0)
                    .unwrap()
                    .clone()
            })
            .collect::<BTreeSet<_>>();
        assert!(
            proposer_variants.len() > 1,
            "expected previous commit hash to influence proposer selection"
        );

        let round_variants = (0..4)
            .map(|round| committee.proposer_for("commit-a", round).unwrap().clone())
            .collect::<BTreeSet<_>>();
        assert!(
            round_variants.len() > 1,
            "expected round number to rotate proposer selection"
        );

        let layout = JetStreamSubjectLayout::default();
        let subject = layout.round_subject(&committee, 4, 2);
        assert!(subject.starts_with(DEFAULT_CONSENSUS_SUBJECT_PREFIX));
        assert!(subject.contains(committee.committee_id()));
        assert_eq!(
            subject,
            format!(
                "{}.{}.height.4.round.2",
                DEFAULT_CONSENSUS_SUBJECT_PREFIX,
                committee.committee_id()
            )
        );
    }

    #[test]
    fn timeout_advances_to_the_next_round_and_proposer() {
        let mut harness = InProcessHarness::new("bootstrap");
        let first_round_proposer = harness.nodes[0]
            .proposer_for_current_round()
            .unwrap()
            .clone();

        harness.elapse_round_timeout();

        for node in &harness.nodes {
            assert_eq!(node.round(), 1);
        }

        let second_round_proposer = harness.nodes[0]
            .proposer_for_current_round()
            .unwrap()
            .clone();
        assert_ne!(first_round_proposer, second_round_proposer);

        harness.queue_on_all(proposal(1));
        let (commits, exclusions) = harness.flush();
        assert!(exclusions.is_empty());
        assert_eq!(commits.len(), 3);
        assert!(
            commits
                .iter()
                .all(|commit| commit.proposal.proposal_id == "proposal-1")
        );
        assert!(harness.nodes.iter().all(|node| node.height() == 2));
    }

    #[test]
    fn three_node_committee_reaches_consensus_for_ten_sequential_proposals() {
        let mut harness = InProcessHarness::new("bootstrap");
        let mut commit_hashes = Vec::new();

        for index in 0..10 {
            harness.queue_on_all(proposal(index));
            let (commits, exclusions) = harness.flush();
            assert!(exclusions.is_empty());
            assert_eq!(commits.len(), 3);

            let commit_hash = commits[0].commit_hash.clone();
            assert!(
                commits
                    .iter()
                    .all(|commit| commit.commit_hash == commit_hash)
            );
            assert!(
                commits
                    .iter()
                    .all(|commit| commit.proposal.proposal_id == format!("proposal-{index}"))
            );

            commit_hashes.push(commit_hash.clone());
            assert!(
                harness
                    .nodes
                    .iter()
                    .all(|node| node.previous_commit_hash() == commit_hash)
            );
            assert!(
                harness
                    .nodes
                    .iter()
                    .all(|node| node.height() == (index as u64) + 2)
            );
        }

        assert_eq!(commit_hashes.len(), 10);
        assert!(
            commit_hashes
                .windows(2)
                .all(|window| window[0] != window[1])
        );
    }

    #[test]
    fn consensus_envelope_round_trips_through_json() {
        let committee = committee();
        let proposer = committee.proposer_for("bootstrap", 0).unwrap().clone();
        let mut node = ConsensusNode::new(
            proposer,
            committee.clone(),
            ConsensusConfig::default(),
            "bootstrap",
            0,
        )
        .unwrap();
        let envelope = node
            .queue_proposal(proposal(42), 0)
            .unwrap()
            .outbound
            .into_iter()
            .next()
            .unwrap();

        let bytes = envelope.encode().unwrap();
        let decoded = ConsensusEnvelope::decode(&bytes).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(
            decoded.subject,
            JetStreamSubjectLayout::default().round_subject(&committee, 1, 0)
        );
    }

    #[test]
    fn signed_consensus_envelope_round_trips_and_verifies() {
        let members = committee_members();
        let committee = ConsensusCommittee::new(
            members
                .iter()
                .map(|member| member.agent_id.clone())
                .collect(),
            1,
        )
        .unwrap();
        let proposer = committee.proposer_for("bootstrap", 0).unwrap().clone();
        let member = members
            .iter()
            .find(|member| member.agent_id == proposer)
            .unwrap();
        let mut node = ConsensusNode::new_with_signing_key(
            proposer,
            member.signing_key.clone(),
            committee,
            ConsensusConfig::default(),
            "bootstrap",
            0,
        )
        .unwrap();
        let envelope = node
            .queue_proposal(proposal(7), 0)
            .unwrap()
            .outbound
            .into_iter()
            .next()
            .unwrap();
        let signed = ConsensusSignedEnvelope::sign(envelope.clone(), &member.signing_key).unwrap();
        assert_eq!(signed.envelope, envelope);
        assert_eq!(
            signed.verify().unwrap().to_bytes(),
            member.signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn invalid_signature_emits_signed_exclusion_receipt() {
        let members = committee_members();
        let committee = ConsensusCommittee::new(
            members
                .iter()
                .map(|member| member.agent_id.clone())
                .collect(),
            1,
        )
        .unwrap();
        let proposer = committee.proposer_for("bootstrap", 0).unwrap().clone();
        let proposer_member = members
            .iter()
            .find(|member| member.agent_id == proposer)
            .unwrap()
            .clone();
        let validator_member = members
            .iter()
            .find(|member| member.agent_id != proposer_member.agent_id)
            .unwrap()
            .clone();

        let mut proposer_node = ConsensusNode::new_with_signing_key(
            proposer_member.agent_id.clone(),
            proposer_member.signing_key.clone(),
            committee.clone(),
            ConsensusConfig::default(),
            "bootstrap",
            0,
        )
        .unwrap();
        let mut validator_node = ConsensusNode::new_with_signing_key(
            validator_member.agent_id.clone(),
            validator_member.signing_key.clone(),
            committee,
            ConsensusConfig::default(),
            "bootstrap",
            0,
        )
        .unwrap();

        let envelope = proposer_node
            .queue_proposal(proposal(9), 0)
            .unwrap()
            .outbound
            .into_iter()
            .next()
            .unwrap();
        let wrong_signer = member(99);
        let signed = ConsensusSignedEnvelope::sign(envelope, &wrong_signer.signing_key).unwrap();

        let progress = validator_node.handle_signed_envelope(&signed, 0).unwrap();
        assert_eq!(progress.exclusions.len(), 1);
        assert_eq!(
            progress.exclusions[0].payload.excluded_agent_id,
            proposer_member.agent_id
        );
        assert_eq!(
            progress.exclusions[0].payload.reason,
            super::ConsensusExclusionReason::InvalidSignature
        );
    }

    #[test]
    fn byzantine_committee_rejects_equivocation_and_invalid_signatures() {
        let members = committee_members();
        let committee = ConsensusCommittee::new(
            members
                .iter()
                .map(|member| member.agent_id.clone())
                .collect(),
            1,
        )
        .unwrap();
        let proposer = committee.proposer_for("bootstrap", 0).unwrap().clone();
        let proposer_member = members
            .iter()
            .find(|member| member.agent_id == proposer)
            .unwrap()
            .clone();
        let validator_member = members
            .iter()
            .find(|member| member.agent_id != proposer_member.agent_id)
            .unwrap()
            .clone();
        let equivocator = members
            .iter()
            .find(|member| {
                member.agent_id != proposer_member.agent_id
                    && member.agent_id != validator_member.agent_id
            })
            .unwrap()
            .clone();

        let mut validator = ConsensusNode::new_with_signing_key(
            validator_member.agent_id.clone(),
            validator_member.signing_key.clone(),
            committee.clone(),
            ConsensusConfig::default(),
            "bootstrap",
            0,
        )
        .unwrap();
        let height = validator.height();
        let round = validator.round();
        let subject = JetStreamSubjectLayout::default().round_subject(&committee, height, round);
        let invalid_proposal = ConsensusEnvelope {
            subject: subject.clone(),
            message: super::ConsensusMessage {
                height,
                round,
                previous_commit_hash: validator.previous_commit_hash().to_string(),
                from: proposer_member.agent_id.clone(),
                sent_at_ms: 1,
                body: super::ConsensusMessageBody::Proposal {
                    proposal: proposal(99),
                },
            },
        };
        let wrong_signer = member(99);
        let invalid_signed =
            ConsensusSignedEnvelope::sign(invalid_proposal, &wrong_signer.signing_key).unwrap();

        let invalid_progress = validator
            .handle_signed_envelope(&invalid_signed, 2)
            .unwrap();
        assert!(invalid_progress.commits.is_empty());
        assert_eq!(invalid_progress.exclusions.len(), 1);
        assert_eq!(
            invalid_progress.exclusions[0].payload.excluded_agent_id,
            proposer_member.agent_id
        );
        assert_eq!(
            invalid_progress.exclusions[0].payload.reason,
            super::ConsensusExclusionReason::InvalidSignature
        );

        let equivocation_a = ConsensusEnvelope {
            subject: subject.clone(),
            message: super::ConsensusMessage {
                height,
                round,
                previous_commit_hash: validator.previous_commit_hash().to_string(),
                from: equivocator.agent_id.clone(),
                sent_at_ms: 2,
                body: super::ConsensusMessageBody::Precommit {
                    proposal_id: Some("alpha".to_string()),
                },
            },
        };
        let equivocation_b = ConsensusEnvelope {
            subject,
            message: super::ConsensusMessage {
                height,
                round,
                previous_commit_hash: validator.previous_commit_hash().to_string(),
                from: equivocator.agent_id.clone(),
                sent_at_ms: 3,
                body: super::ConsensusMessageBody::Precommit {
                    proposal_id: Some("beta".to_string()),
                },
            },
        };
        let signed_a =
            ConsensusSignedEnvelope::sign(equivocation_a, &equivocator.signing_key).unwrap();
        let signed_b =
            ConsensusSignedEnvelope::sign(equivocation_b, &equivocator.signing_key).unwrap();

        let first = validator.handle_signed_envelope(&signed_a, 3).unwrap();
        assert!(first.commits.is_empty());
        assert!(first.exclusions.is_empty());

        let second = validator.handle_signed_envelope(&signed_b, 4).unwrap();
        assert!(second.commits.is_empty());
        assert_eq!(second.exclusions.len(), 1);
        assert_eq!(
            second.exclusions[0].payload.excluded_agent_id,
            equivocator.agent_id
        );
        assert_eq!(
            second.exclusions[0].payload.reason,
            super::ConsensusExclusionReason::Equivocation
        );
        assert_eq!(validator.height(), height);
    }

    #[test]
    fn equivocating_precommits_emit_signed_exclusion_receipt() {
        let mut harness = InProcessHarness::new("bootstrap");
        harness.queue_on_all(proposal(1));
        let (commits, exclusions) = harness.flush();
        assert!(exclusions.is_empty());
        assert_eq!(commits.len(), 3);

        let committee = ConsensusCommittee::new(
            harness
                .members
                .iter()
                .map(|member| member.agent_id.clone())
                .collect(),
            1,
        )
        .unwrap();
        let signer = harness.members[0].clone();
        let mut validator = ConsensusNode::new_with_signing_key(
            harness.members[1].agent_id.clone(),
            harness.members[1].signing_key.clone(),
            committee.clone(),
            ConsensusConfig::default(),
            harness.nodes[1].previous_commit_hash(),
            0,
        )
        .unwrap();
        let round = validator.round();
        let height = validator.height();
        let envelope_a = ConsensusEnvelope {
            subject: JetStreamSubjectLayout::default().round_subject(&committee, height, round),
            message: super::ConsensusMessage {
                height,
                round,
                previous_commit_hash: validator.previous_commit_hash().to_string(),
                from: signer.agent_id.clone(),
                sent_at_ms: 1,
                body: super::ConsensusMessageBody::Precommit {
                    proposal_id: Some("alpha".to_string()),
                },
            },
        };
        let envelope_b = ConsensusEnvelope {
            subject: JetStreamSubjectLayout::default().round_subject(&committee, height, round),
            message: super::ConsensusMessage {
                height,
                round,
                previous_commit_hash: validator.previous_commit_hash().to_string(),
                from: signer.agent_id.clone(),
                sent_at_ms: 2,
                body: super::ConsensusMessageBody::Precommit {
                    proposal_id: Some("beta".to_string()),
                },
            },
        };
        let signed_a = ConsensusSignedEnvelope::sign(envelope_a, &signer.signing_key).unwrap();
        let signed_b = ConsensusSignedEnvelope::sign(envelope_b, &signer.signing_key).unwrap();

        let first = validator.handle_signed_envelope(&signed_a, 2).unwrap();
        assert!(first.exclusions.is_empty());
        assert!(first.commits.is_empty());

        let second = validator.handle_signed_envelope(&signed_b, 2).unwrap();
        assert_eq!(second.exclusions.len(), 1);
        assert_eq!(
            second.exclusions[0].payload.reason,
            super::ConsensusExclusionReason::Equivocation
        );
        assert_eq!(
            second.exclusions[0].payload.message_kind,
            super::SignedMessageKind::Precommit
        );
    }
}
