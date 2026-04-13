# Phase 205 Verification

status: passed

## Result

Phase 205 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-runtime --lib 'control::tests::first_run_' -- --nocapture`
- `cargo test -p swarm-cli cli_parses_first_run_command -- --nocapture`
- `SWARM_VOTER_SIGNING_KEY=first-run-vote-key SWARM_EVIDENCE_SIGNING_KEY=first-run-evidence-key cargo run -p swarm-runtime --bin swarmctl -- first-run --config rulesets/default.yaml --json`

## Verified Behaviors

- `swarmctl first-run` now fails non-zero when the readiness gate is blocked
  and returns one structured `guided_first_run` report instead of silently
  bypassing onboarding preconditions.
- A passing walkthrough reuses the shipped demo replay, approval, and proof
  flow to produce a first detection, a persisted approval set plus receipt
  pack, and a proof bundle with a Merkle root and final incident.
- The CLI path works against the signed repo config, which proves the guided
  onboarding flow is not limited to unit-test fixtures.
