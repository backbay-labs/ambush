# Phase 156 Verification

status: passed

## Result

Phase 156 verification passed.

## Commands

- `cargo fmt --all`
- `cargo check -p swarm-consensus -p swarm-runtime --tests -j 1 --message-format short`
- `cargo test -p swarm-consensus tests::byzantine_committee_rejects_equivocation_and_invalid_signatures -- --exact`
- `cargo test -p swarm-consensus tests::timeout_advances_to_the_next_round_and_proposer -- --exact`
- `cargo test -p swarm-consensus -- --nocapture`
- `cargo test -p swarm-runtime --test dispatch_integration partitioned_request_response_ -- --nocapture`
- `cargo test -p swarm-runtime --test governance_resilience_integration -- --nocapture`

## Verified Behaviors

- Consensus validators now reject both invalid signatures and equivocation in one deterministic Byzantine regression without producing unauthorized commits.
- Round timeout still advances the committee to the next proposer, so the existing recovery path remains live alongside the new Byzantine safety proof.
- The live dispatcher path now proves three partition outcomes on destructive actions: missing lease denial, valid lease redemption, and expired lease denial before approval-gate or executor execution.
- Partition recovery now persists one reconciliation report that survives restart and preserves the distinction between authorized and unauthorized partition-era actions.
