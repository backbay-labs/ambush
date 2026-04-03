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

// TODO: Implement
// - ConsensusRound struct
// - Propose / Prevote / Precommit phases
// - VRF-based committee rotation
// - Signed vote collection and tallying
