# Phase 172 Verification

status: passed

## Result

Phase 172 verification passed.

## Commands

- `cargo test -p swarm-core config::tests::evolution_requires_probability_assurance_floor_when_enabled -- --exact`
- `cargo test -p swarm-core config::tests::evolution_requires_non_empty_allowed_solver_statuses_when_enabled -- --exact`
- `cargo test -p swarm-core config::tests::evolution_requires_non_empty_assurance_override_detector_when_enabled -- --exact`
- `cargo test -p swarm-evolution assurance_coverage_floor -- --nocapture`
- `cargo test -p swarm-evolution solver_summary_is_required -- --nocapture`
- `cargo test -p swarm-evolution evolution_queue_creates_pending_review_proposal -- --nocapture`
- `cargo test -p swarm-runtime --lib evolution_status::tests::evolution_status_harness_summarizes_durable_artifacts -- --exact`
- `cargo check -p swarm-core -p swarm-evolution -p swarm-runtime --tests -j 1 --message-format short`

## Verified Behaviors

- Assurance configuration now validates solver-policy and coverage-floor constraints before an enabled evolution lane can start.
- Queue proposal creation now attaches one durable assurance summary and blocks candidates explicitly when a detector misses the configured evasion floor or when solver evidence is required but absent.
- The shared evolution status surface now reports the latest assurance decision and blocked assurance checks from durable proposal artifacts instead of forcing operators to inspect raw queue JSON.
