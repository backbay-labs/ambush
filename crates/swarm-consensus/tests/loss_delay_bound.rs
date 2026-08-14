#![allow(clippy::unwrap_used, clippy::expect_used)]
//! BFT-05: a seeded message-loss and delay harness, and what it does and does
//! not prove about `round_timeout_ms * (max_faulty + 1)`.
//!
//! # The bound in the requirement is NOT a theorem about this implementation
//!
//! BFT-05 asks for a harness proving "commit completes within
//! `round_timeout_ms * (max_faulty + 1)` in the common case". That bound is the
//! classical Tendermint one, and it holds only when proposer selection is a
//! ROTATION: if round `r`'s proposer is `members[(r + k) % n]`, then among any
//! `f + 1` consecutive rounds at least one proposer is correct.
//!
//! `ConsensusCommittee::proposer_for` (`crates/swarm-consensus/src/lib.rs`) is
//! not a rotation. It is an independent per-round argmax of
//! `sha256(previous_commit_hash, round, agent_id)`, so each round's proposer is
//! an independent draw and the same faulty member can lead `f + 1` rounds in a
//! row. This harness therefore does NOT assert the bound. It:
//!
//! 1. proves a genuinely conditional version of it that IS a protocol property
//!    (see `ROUND_ZERO_PRECONDITION` below), and
//! 2. publishes the MEASURED distribution for everything else, including the
//!    exact number of episodes whose leader schedule violates the bound's
//!    precondition.
//!
//! Replacing `proposer_for` with a VRF rotation is VRF-02 (phase 301). When
//! that lands, the unconditional bound becomes assertable and the measured
//! constants here will change; that is the point of recording them.
//!
//! # Determinism
//!
//! No `std::thread::sleep`, no `SystemTime`, no `Instant`. `ConsensusNode`
//! reads no clock -- every entry point takes `now_ms: i64` -- so the whole
//! harness runs on an integer virtual clock stepped by the delivery schedule.
//! Randomness is a hand-rolled splitmix64 seeded from the episode seed alone,
//! so an episode is reproducible from its seed and nothing else. That is
//! asserted, not assumed, by
//! `episodes_are_reproducible_from_their_seed_alone`.
//!
//! # Fault classes this harness does NOT exercise
//!
//! Stated here because a harness that does not say what it skipped is a claim
//! of coverage it has not earned:
//!
//! - **Byzantine equivocation under loss/delay.** Faulty members here are
//!   CRASH-faulty: their outbound is dropped, they never lie. Equivocation is
//!   covered separately by `byzantine_committee_rejects_equivocation_and_-
//!   invalid_signatures` in `src/lib.rs`, under perfect delivery. The
//!   combination is untested.
//! - **A Byzantine proposer sending different valid proposals to disjoint
//!   subsets.** `ConsensusNode::record_proposal` errors on the second distinct
//!   proposal for a round, so modelling a split proposal means changing the
//!   node, not the harness.
//! - **Invalid signatures under loss/delay.** Covered separately, under perfect
//!   delivery.
//! - **Per-node clock skew.** One virtual clock is shared by every node.
//! - **Network partition and heal.** That is the `PartitionState` lane in
//!   `swarm-agents`, not this one.
//! - **Governor crash and restart mid-round.** `PersistedGovernanceState`
//!   persists no round state; a restart loses the round (fail-closed, but
//!   untested here).
//! - **Cross-height replay.** Only height 1 is exercised; the dedup key is
//!   `{height, round, from, kind}`.
//! - **Real transport faults** -- JetStream redelivery, backpressure,
//!   message-size limits, reordering beyond the delay model. Delivery here is
//!   in-process.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde_json::json;
use swarm_consensus::{
    ConsensusCommittee, ConsensusConfig, ConsensusNode, ConsensusProposal, ConsensusSignedEnvelope,
    recommended_max_faulty,
};
use swarm_core::types::AgentId;

/// Virtual round timeout. Small so an episode is cheap; the bound is stated as
/// a multiple of it, so its absolute value is irrelevant.
const ROUND_TIMEOUT_MS: i64 = 25;

/// Maximum per-hop delivery delay, in virtual ms.
///
/// Held below `ROUND_TIMEOUT_MS / 3` deliberately. A commit needs three hops
/// (proposal -> prevote -> precommit), so `3 * MAX_DELAY_MS <= ROUND_TIMEOUT_MS`
/// is what makes `ROUND_ZERO_PRECONDITION` a provable property rather than a
/// lucky measurement.
const MAX_DELAY_MS: i64 = 5;

/// Probability that a message between two live members is lost, as
/// `LOSS_NUMERATOR / LOSS_DENOMINATOR`.
const LOSS_NUMERATOR: u64 = 1;
const LOSS_DENOMINATOR: u64 = 16;

/// Hard cap on virtual rounds per episode. An episode that reaches it is
/// recorded as a non-commit, never silently skipped.
const MAX_ROUNDS: i64 = 64;

/// Seeds per committee size.
const SEEDS_PER_SIZE: u64 = 64;

/// Committee sizes exercised, one per `f` in 1..=3 under `3f + 1`.
const SIZES: [usize; 3] = [4, 7, 10];

/// splitmix64. Ten lines rather than a new workspace dependency, and its only
/// input is the episode seed.
struct Splitmix64(u64);

impl Splitmix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish in `0..bound`. The modulo bias is negligible at these bounds
    /// and, more importantly, deterministic -- which is the property that
    /// matters for a reproducible corpus.
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

fn member_key(index: usize) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xA0;
    bytes[1] = index as u8;
    bytes[31] = index as u8;
    SigningKey::from_bytes(&bytes)
}

fn proposal() -> ConsensusProposal {
    ConsensusProposal {
        proposal_id: "loss-delay-proposal".to_string(),
        payload: json!({ "kind": "response_action", "action": "block_egress" }),
    }
}

/// One deterministic run: which members are silent, what was lost, what
/// committed and when.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Episode {
    seed: u64,
    size: usize,
    max_faulty: usize,
    /// Indices into the committee's sorted member list.
    silent: Vec<usize>,
    /// `proposer_for(previous_commit_hash, r)` for `r` in `0..=max_faulty`,
    /// as indices, computed before the round runs.
    leader_schedule: Vec<usize>,
    dropped: usize,
    delivered: usize,
    delayed: usize,
    /// Round of the first commit observed at any node, if any.
    commit_round: Option<u64>,
    /// Virtual ms at which that commit was observed.
    commit_at_ms: Option<i64>,
}

impl Episode {
    fn previous_commit_hash(seed: u64) -> String {
        // Varies per episode so the leader schedule varies too -- with a fixed
        // hash every seed of a given size would share one schedule and the
        // measured leader statistics would be a single sample repeated.
        format!("governance-bootstrap-{seed}")
    }

    /// The precondition under which round 0 MUST commit, decidable from the
    /// fault plan without looking at the outcome.
    ///
    /// If the round-0 proposer is live and no message between live members was
    /// lost in round 0, then: every live member receives the proposal within
    /// `MAX_DELAY_MS`, prevotes by `2 * MAX_DELAY_MS`, precommits by
    /// `3 * MAX_DELAY_MS <= ROUND_TIMEOUT_MS`, and the live count is at least
    /// `threshold()` because at most `f` members are silent out of `3f + 1`.
    fn round_zero_precondition_held(&self, round_zero_losses: usize) -> bool {
        !self.silent.contains(&self.leader_schedule[0]) && round_zero_losses == 0
    }

    /// True when every proposer in rounds `0..=f` is silent, which is exactly
    /// the case the requirement's bound assumes away and `proposer_for`'s
    /// independent argmax does not prevent.
    fn bound_precondition_violated_by_leader_schedule(&self) -> bool {
        self.leader_schedule
            .iter()
            .all(|leader| self.silent.contains(leader))
    }

    fn within_bound(&self) -> bool {
        self.commit_at_ms
            .is_some_and(|at_ms| at_ms <= ROUND_TIMEOUT_MS * (self.max_faulty as i64 + 1))
    }
}

/// One episode's inputs. Everything an episode does is a function of these.
#[derive(Debug, Clone)]
struct EpisodePlan {
    seed: u64,
    size: usize,
    /// Numerator of the per-hop loss probability over [`LOSS_DENOMINATOR`].
    /// Zero means a delay-only network, which is what makes the round-0
    /// precondition corpus large enough to be worth asserting over.
    loss_numerator: u64,
    /// Overrides the seeded fault plan; the negative controls use it to silence
    /// more members than the protocol can tolerate.
    forced_silent: Option<Vec<usize>>,
}

impl EpisodePlan {
    fn seeded(seed: u64, size: usize) -> Self {
        Self {
            seed,
            size,
            loss_numerator: LOSS_NUMERATOR,
            forced_silent: None,
        }
    }

    fn without_loss(mut self) -> Self {
        self.loss_numerator = 0;
        self
    }

    fn silencing(mut self, silent: Vec<usize>) -> Self {
        self.forced_silent = Some(silent);
        self
    }
}

/// Run one episode end to end on a virtual clock.
fn run_episode(plan: EpisodePlan) -> Episode {
    let EpisodePlan {
        seed,
        size,
        loss_numerator,
        forced_silent,
    } = plan;
    let mut rng = Splitmix64::new(seed);
    let max_faulty = recommended_max_faulty(size);
    let keys = (0..size).map(member_key).collect::<Vec<_>>();
    let committee = ConsensusCommittee::new(
        keys.iter()
            .map(|key| AgentId::from_verifying_key(&key.verifying_key()))
            .collect(),
        max_faulty,
    )
    .unwrap();
    // `ConsensusCommittee::new` sorts and dedups, so index into the SORTED
    // member list, not into `keys`.
    let members = committee.members().to_vec();
    let key_by_id = keys
        .iter()
        .map(|key| {
            (
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let previous_commit_hash = Episode::previous_commit_hash(seed);

    let silent = match forced_silent {
        Some(forced) => forced,
        None => {
            let count = rng.below(max_faulty as u64 + 1) as usize;
            let mut chosen = Vec::new();
            while chosen.len() < count {
                let candidate = rng.below(size as u64) as usize;
                if !chosen.contains(&candidate) {
                    chosen.push(candidate);
                }
            }
            chosen.sort_unstable();
            chosen
        }
    };

    let leader_schedule = (0..=max_faulty as u64)
        .map(|round| {
            let leader = committee
                .proposer_for(&previous_commit_hash, round)
                .unwrap();
            members.iter().position(|member| member == leader).unwrap()
        })
        .collect::<Vec<_>>();

    let config = ConsensusConfig {
        round_timeout_ms: ROUND_TIMEOUT_MS,
        ..ConsensusConfig::default()
    };
    let mut nodes = members
        .iter()
        .map(|member| {
            ConsensusNode::new_with_signing_key(
                member.clone(),
                key_by_id[member].clone(),
                committee.clone(),
                config.clone(),
                previous_commit_hash.clone(),
                0,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let mut episode = Episode {
        seed,
        size,
        max_faulty,
        silent,
        leader_schedule,
        dropped: 0,
        delivered: 0,
        delayed: 0,
        commit_round: None,
        commit_at_ms: None,
    };

    // (deliver_at_ms, sequence) -> (recipient index, envelope). The sequence
    // number keeps the map total-ordered when two messages land in the same
    // virtual millisecond, so delivery order is a function of the seed.
    let mut queue: BTreeMap<(i64, u64), (usize, ConsensusSignedEnvelope)> = BTreeMap::new();
    let mut sequence = 0u64;
    let mut now_ms = 0i64;
    let mut round_zero_losses = 0usize;

    let schedule = |episode: &mut Episode,
                    rng: &mut Splitmix64,
                    queue: &mut BTreeMap<(i64, u64), (usize, ConsensusSignedEnvelope)>,
                    sequence: &mut u64,
                    round_zero_losses: &mut usize,
                    now_ms: i64,
                    sender: usize,
                    node: &ConsensusNode,
                    outbound: Vec<swarm_consensus::ConsensusEnvelope>| {
        for envelope in outbound {
            let round = envelope.message.round;
            let signed = node.sign_outbound(envelope).unwrap();
            if episode.silent.contains(&sender) {
                // A crash-faulty member: its traffic never reaches anyone. Not
                // counted as network loss -- it is the fault plan, not the link.
                continue;
            }
            for recipient in 0..episode.size {
                if recipient == sender {
                    continue;
                }
                if rng.below(LOSS_DENOMINATOR) < loss_numerator {
                    episode.dropped += 1;
                    if round == 0 && !episode.silent.contains(&recipient) {
                        *round_zero_losses += 1;
                    }
                    continue;
                }
                let delay = rng.below(MAX_DELAY_MS as u64 + 1) as i64;
                if delay > 0 {
                    episode.delayed += 1;
                }
                episode.delivered += 1;
                queue.insert((now_ms + delay, *sequence), (recipient, signed.clone()));
                *sequence += 1;
            }
        }
    };

    for (index, node) in nodes.iter_mut().enumerate() {
        let progress = node.queue_proposal(proposal(), now_ms).unwrap();
        if let Some(commit) = progress.commits.first()
            && episode.commit_round.is_none()
        {
            episode.commit_round = Some(commit.round);
            episode.commit_at_ms = Some(now_ms);
        }
        schedule(
            &mut episode,
            &mut rng,
            &mut queue,
            &mut sequence,
            &mut round_zero_losses,
            now_ms,
            index,
            node,
            progress.outbound,
        );
    }

    let horizon_ms = ROUND_TIMEOUT_MS * MAX_ROUNDS;
    while episode.commit_round.is_none() && now_ms <= horizon_ms {
        let next_delivery = queue.keys().next().map(|(at_ms, _)| *at_ms);
        now_ms = match next_delivery {
            Some(at_ms) if at_ms <= now_ms + 1 => at_ms.max(now_ms),
            _ => now_ms + 1,
        };

        while let Some((&key, _)) = queue.range((now_ms, 0)..=(now_ms, u64::MAX)).next() {
            let (recipient, envelope) = queue.remove(&key).unwrap();
            let progress = nodes[recipient]
                .handle_signed_envelope(&envelope, now_ms)
                .unwrap();
            if let Some(commit) = progress.commits.first()
                && episode.commit_round.is_none()
            {
                episode.commit_round = Some(commit.round);
                episode.commit_at_ms = Some(now_ms);
            }
            schedule(
                &mut episode,
                &mut rng,
                &mut queue,
                &mut sequence,
                &mut round_zero_losses,
                now_ms,
                recipient,
                &nodes[recipient],
                progress.outbound,
            );
        }

        for (index, node) in nodes.iter_mut().enumerate() {
            let progress = node.tick(now_ms).unwrap();
            if let Some(commit) = progress.commits.first()
                && episode.commit_round.is_none()
            {
                episode.commit_round = Some(commit.round);
                episode.commit_at_ms = Some(now_ms);
            }
            schedule(
                &mut episode,
                &mut rng,
                &mut queue,
                &mut sequence,
                &mut round_zero_losses,
                now_ms,
                index,
                node,
                progress.outbound,
            );
        }
    }

    // Stash for the round-0 assertion, which needs the loss count and not just
    // the plan. Encoded in `delayed`'s sibling rather than a new field so the
    // Episode stays a value the reproducibility test can compare wholesale.
    ROUND_ZERO_LOSSES.with(|cell| cell.set(round_zero_losses));
    episode
}

thread_local! {
    static ROUND_ZERO_LOSSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The loss-and-delay corpus: 3 sizes x 64 seeds.
fn corpus() -> Vec<(Episode, usize)> {
    corpus_with(|plan| plan)
}

/// The delay-only corpus: same plans, loss disabled.
fn delay_only_corpus() -> Vec<(Episode, usize)> {
    corpus_with(EpisodePlan::without_loss)
}

fn corpus_with(shape: impl Fn(EpisodePlan) -> EpisodePlan) -> Vec<(Episode, usize)> {
    let mut episodes = Vec::new();
    for size in SIZES {
        for seed in 0..SEEDS_PER_SIZE {
            // Mix the size into the seed so the same seed index means a
            // different fault plan per size.
            let episode_seed = seed.wrapping_mul(0x0100_0000_01B3) ^ ((size as u64) << 32);
            let episode = run_episode(shape(EpisodePlan::seeded(episode_seed, size)));
            let round_zero_losses = ROUND_ZERO_LOSSES.with(std::cell::Cell::get);
            episodes.push((episode, round_zero_losses));
        }
    }
    episodes
}

fn summarize(episodes: &[(Episode, usize)]) -> String {
    let committed = episodes
        .iter()
        .filter(|(episode, _)| episode.commit_round.is_some())
        .count();
    let within_bound = episodes
        .iter()
        .filter(|(episode, _)| episode.within_bound())
        .count();
    let schedule_violations = episodes
        .iter()
        .filter(|(episode, _)| episode.bound_precondition_violated_by_leader_schedule())
        .count();
    let dropped: usize = episodes.iter().map(|(episode, _)| episode.dropped).sum();
    let delayed: usize = episodes.iter().map(|(episode, _)| episode.delayed).sum();
    let delivered: usize = episodes.iter().map(|(episode, _)| episode.delivered).sum();
    let mut commit_rounds: BTreeMap<Option<u64>, usize> = BTreeMap::new();
    for (episode, _) in episodes {
        *commit_rounds.entry(episode.commit_round).or_default() += 1;
    }
    format!(
        "episodes={} committed={committed} within_bound={within_bound} \
         leader_schedule_violations={schedule_violations} dropped={dropped} delayed={delayed} \
         delivered={delivered} commit_rounds={commit_rounds:?}",
        episodes.len(),
    )
}

// ---------------------------------------------------------------------------
// MEASURED CONSTANTS
//
// Every number below was produced by running this harness, not chosen. They are
// exact rather than tolerances on purpose: a tolerance is where a future
// regression hides, and this corpus is fully deterministic, so exactness costs
// nothing. If `proposer_for`, `recommended_max_faulty`, the vote rules or the
// timeout schedule change, these fail and the new distribution has to be
// re-measured and re-argued rather than re-tuned.
// ---------------------------------------------------------------------------

/// Total episodes per corpus: 3 sizes x 64 seeds.
const TOTAL_EPISODES: usize = 192;

/// Verbatim `summarize` output for the loss-and-delay corpus.
const MEASURED_LOSS_AND_DELAY: &str = "episodes=192 committed=192 within_bound=169 \
     leader_schedule_violations=5 dropped=1729 delayed=20695 delivered=24719 \
     commit_rounds={Some(0): 136, Some(1): 25, Some(2): 8, Some(3): 7, Some(4): 3, Some(5): 4, \
     Some(6): 1, Some(8): 1, Some(10): 1, Some(11): 1, Some(12): 1, Some(14): 1, Some(15): 1, \
     Some(19): 1, Some(29): 1}";

/// Verbatim `summarize` output for the delay-only corpus.
///
/// Read this against the loss corpus above: with nothing dropped, 187 of 192
/// episodes land inside the bound and the 5 that do not are EXACTLY the 5 whose
/// leader schedule is fully silent. Delay alone never costs a round; loss and
/// the non-rotating proposer are the only two things that do.
const MEASURED_DELAY_ONLY: &str = "episodes=192 committed=192 within_bound=187 \
     leader_schedule_violations=5 dropped=0 delayed=14169 delivered=16893 \
     commit_rounds={Some(0): 161, Some(1): 22, Some(2): 6, Some(3): 2, Some(4): 1}";

/// Episodes of the loss-and-delay corpus that satisfy the round-0 precondition
/// (live round-0 proposer AND no round-0 loss among live members).
const MEASURED_ROUND_ZERO_QUALIFYING_WITH_LOSS: usize = 13;

/// Same, on the delay-only corpus, where the only way to fail the precondition
/// is a silent round-0 proposer.
const MEASURED_ROUND_ZERO_QUALIFYING_DELAY_ONLY: usize = 161;

/// Episodes whose commit landed outside `round_timeout_ms * (max_faulty + 1)`.
const MEASURED_MISSED_BOUND: usize = 23;

/// Of those, the ones explained by the leader schedule -- every proposer in
/// rounds `0..=f` silent -- rather than by message loss. This is the count that
/// makes "the stated bound does not hold here" a measurement instead of an
/// opinion, and the count VRF-02 should drive to zero.
const MEASURED_MISSED_BY_LEADER_SCHEDULE: usize = 5;

#[test]
fn seeded_loss_and_delay_corpus_matches_its_measured_distribution() {
    let episodes = corpus();
    assert_eq!(episodes.len(), TOTAL_EPISODES);

    let dropped: usize = episodes.iter().map(|(episode, _)| episode.dropped).sum();
    let delayed: usize = episodes.iter().map(|(episode, _)| episode.delayed).sum();
    // Without these two the file would be a perfect-delivery harness with a
    // misleading name.
    assert!(
        dropped > 0 && delayed > 0,
        "the corpus must exercise loss and delay: dropped={dropped} delayed={delayed}"
    );

    assert_eq!(
        summarize(&episodes),
        MEASURED_LOSS_AND_DELAY,
        "measured distribution changed"
    );
}

#[test]
fn delay_alone_never_pushes_a_commit_past_one_round() {
    // Isolating delay from loss. `3 * MAX_DELAY_MS <= ROUND_TIMEOUT_MS`, so with
    // nothing lost, a live round-0 proposer must carry the round to a commit
    // inside the first round timeout no matter how the delays fall. This is a
    // protocol property, not a measurement: a failure here is a consensus bug.
    let episodes = delay_only_corpus();
    assert_eq!(episodes.len(), TOTAL_EPISODES);
    assert_eq!(
        episodes
            .iter()
            .map(|(episode, _)| episode.dropped)
            .sum::<usize>(),
        0,
        "the delay-only corpus must drop nothing"
    );
    assert!(
        episodes
            .iter()
            .map(|(episode, _)| episode.delayed)
            .sum::<usize>()
            > 0,
        "the delay-only corpus must still delay"
    );
    assert_eq!(
        summarize(&episodes),
        MEASURED_DELAY_ONLY,
        "delay-only distribution changed"
    );

    // The load-bearing claim of this corpus: with nothing lost, the ONLY reason
    // an episode misses `round_timeout_ms * (max_faulty + 1)` is that every
    // proposer in rounds 0..=f was silent. Delay never costs a round on its own.
    let missed = episodes
        .iter()
        .filter(|(episode, _)| !episode.within_bound())
        .collect::<Vec<_>>();
    for (episode, _) in &missed {
        assert!(
            episode.bound_precondition_violated_by_leader_schedule(),
            "seed {} size {} missed the bound with nothing lost and a live proposer somewhere \
             in rounds 0..={}; silent={:?} leaders={:?} commit_round={:?}",
            episode.seed,
            episode.size,
            episode.max_faulty,
            episode.silent,
            episode.leader_schedule,
            episode.commit_round,
        );
    }
    assert_eq!(
        missed.len(),
        MEASURED_MISSED_BY_LEADER_SCHEDULE,
        "with loss disabled the shortfall must be exactly the leader-schedule shortfall"
    );
}

#[test]
fn a_live_round_zero_proposer_commits_in_round_zero_when_nothing_is_lost() {
    let mut qualifying = 0usize;
    for (episode, round_zero_losses) in delay_only_corpus() {
        if !episode.round_zero_precondition_held(round_zero_losses) {
            continue;
        }
        qualifying += 1;
        assert_eq!(
            episode.commit_round,
            Some(0),
            "seed {} size {} had a live round-0 proposer and no loss, so it must commit in \
             round 0; silent={:?} leaders={:?} commit_at_ms={:?}",
            episode.seed,
            episode.size,
            episode.silent,
            episode.leader_schedule,
            episode.commit_at_ms,
        );
        assert!(
            episode
                .commit_at_ms
                .is_some_and(|at_ms| at_ms <= ROUND_TIMEOUT_MS),
            "seed {} committed in round 0 but at {:?} ms, past one round timeout",
            episode.seed,
            episode.commit_at_ms,
        );
    }
    // Anti-vacuity. If the precondition never held, the loop asserted nothing.
    assert_eq!(
        qualifying, MEASURED_ROUND_ZERO_QUALIFYING_DELAY_ONLY,
        "the number of episodes satisfying the round-0 precondition changed; a DROP toward zero \
         means this test is going vacuous"
    );
    assert!(
        qualifying * 2 > TOTAL_EPISODES,
        "corpus too thin to be worth asserting over"
    );
}

#[test]
fn the_round_zero_precondition_also_holds_under_loss_but_over_a_much_smaller_corpus() {
    // Same property, same oracle, on the loss corpus. Kept separate and its
    // qualifying count published because it is small: with 1/16 per-hop loss and
    // hundreds of round-0 messages, most episodes lose something in round 0.
    // Reporting 13/192 is the honest version of "the precondition held".
    let mut qualifying = 0usize;
    for (episode, round_zero_losses) in corpus() {
        if !episode.round_zero_precondition_held(round_zero_losses) {
            continue;
        }
        qualifying += 1;
        assert_eq!(
            episode.commit_round,
            Some(0),
            "seed {} size {}: live round-0 proposer, zero round-0 loss, yet commit_round={:?}",
            episode.seed,
            episode.size,
            episode.commit_round,
        );
    }
    assert_eq!(qualifying, MEASURED_ROUND_ZERO_QUALIFYING_WITH_LOSS);
}

#[test]
fn the_stated_bound_is_not_claimed_and_every_shortfall_is_classified() {
    // This test asserts the OPPOSITE of what a green "the bound holds" test
    // would. BFT-05's bound is not a theorem about this implementation, so the
    // phase publishes how far short the corpus falls and why, split into the two
    // causes, both exact.
    let episodes = corpus();
    let missed = episodes
        .iter()
        .filter(|(episode, _)| !episode.within_bound())
        .collect::<Vec<_>>();
    assert_eq!(
        missed.len(),
        MEASURED_MISSED_BOUND,
        "the number of episodes missing round_timeout_ms * (max_faulty + 1) changed"
    );
    assert!(
        !missed.is_empty(),
        "if no episode ever missed the bound this test asserts nothing; either the bound now \
         holds unconditionally -- say so and delete this -- or the loss rate has drifted to zero"
    );

    let by_leader_schedule = missed
        .iter()
        .filter(|(episode, _)| episode.bound_precondition_violated_by_leader_schedule())
        .count();
    assert_eq!(
        by_leader_schedule, MEASURED_MISSED_BY_LEADER_SCHEDULE,
        "the split between leader-schedule shortfalls and loss shortfalls changed"
    );

    for (episode, _) in &missed {
        assert!(
            episode.commit_round.is_some(),
            "every episode still commits eventually; seed {} did not within {} rounds",
            episode.seed,
            MAX_ROUNDS,
        );
    }
}

#[test]
fn a_fully_silent_leader_schedule_provably_cannot_commit_inside_the_bound() {
    // A theorem, not a measurement: if every proposer in rounds 0..=f is silent,
    // no proposal is recorded in those rounds, so `ConsensusNode::commit` cannot
    // fire in them and the commit round is strictly greater than f. This is what
    // `proposer_for`'s independent argmax makes reachable and a rotation would
    // not. The corpus contains such episodes; their count is published in
    // MEASURED_LOSS_AND_DELAY as `leader_schedule_violations`.
    let episodes = corpus();
    let violated = episodes
        .iter()
        .filter(|(episode, _)| episode.bound_precondition_violated_by_leader_schedule())
        .collect::<Vec<_>>();
    assert!(
        !violated.is_empty(),
        "no episode in this corpus has an all-silent leader schedule, so this test proves \
         nothing; if VRF-02 has landed, delete it and assert the unconditional bound instead"
    );
    for (episode, _) in violated {
        // The theorem is "cannot commit INSIDE the bound", so `None` satisfies it.
        // Whether every episode commits eventually is a separate, weaker liveness
        // claim, pinned by `committed=192` inside MEASURED_LOSS_AND_DELAY.
        assert!(
            episode
                .commit_round
                .is_none_or(|round| round > episode.max_faulty as u64),
            "seed {} size {} has every proposer in rounds 0..={} silent (silent={:?} \
             leaders={:?}) yet reports commit_round={:?}",
            episode.seed,
            episode.size,
            episode.max_faulty,
            episode.silent,
            episode.leader_schedule,
            episode.commit_round,
        );
    }
}

#[test]
fn silencing_every_member_yields_no_commit_rather_than_a_synthesized_one() {
    // The oracle's anti-vacuity proof. If the driver ever synthesized a commit,
    // treated "no commit" as "precondition not met", or timed out silently, this
    // is what fails.
    let episode = run_episode(EpisodePlan::seeded(0xDEAD_BEEF, 4).silencing(vec![0, 1, 2, 3]));
    assert_eq!(episode.commit_round, None);
    assert_eq!(episode.commit_at_ms, None);
    assert!(!episode.within_bound());
    assert_eq!(episode.delivered, 0, "every member was silent");
}

#[test]
fn silencing_one_more_than_max_faulty_yields_no_commit() {
    // Strictly stronger than the all-silent control: f+1 of 3f+1 members are
    // silent, so 2f live members remain against a threshold of 2f+1. The round is
    // provably unreachable while the network is otherwise healthy and messages
    // really are flowing -- which is what catches a driver that synthesizes
    // progress for partially-silent plans.
    for size in SIZES {
        let max_faulty = recommended_max_faulty(size);
        let silent = (0..=max_faulty).collect::<Vec<_>>();
        let episode = run_episode(EpisodePlan::seeded(0x5EED_0001, size).silencing(silent));
        assert_eq!(
            episode.commit_round,
            None,
            "size {size} with {} silent members must not commit (threshold {} > live {})",
            max_faulty + 1,
            2 * max_faulty + 1,
            size - (max_faulty + 1),
        );
        assert!(
            episode.delivered > 0,
            "size {size}: the live members must still be exchanging messages, otherwise this \
             control degenerates into the all-silent one"
        );
    }
}

#[test]
fn episodes_are_reproducible_from_their_seed_alone() {
    // Reproducibility is the whole basis for asserting exact constants above.
    for size in SIZES {
        for seed in [1u64, 7, 4242] {
            let first = run_episode(EpisodePlan::seeded(seed, size));
            let second = run_episode(EpisodePlan::seeded(seed, size));
            assert_eq!(
                first, second,
                "episode (seed {seed}, size {size}) is not reproducible from its seed"
            );
        }
    }
}
