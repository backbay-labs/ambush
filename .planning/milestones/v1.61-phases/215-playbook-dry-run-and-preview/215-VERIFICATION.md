# Phase 215 Verification

status: passed

## Result

Phase 215 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-core response_playbook_ -- --nocapture`
- `cargo test -p swarm-runtime --lib playbook_preview_ -- --nocapture`
- `cargo test -p swarm-cli playbook_preview -- --nocapture`
- `cargo run -p swarm-runtime --bin swarmctl -- playbook-preview --config rulesets/default.yaml --threat-class execution --severity HIGH --confidence 0.97 --mode incident --json`

## Verified Behaviors

- Repo-owned response playbook resolution now prefers the first matching branch
  and falls back deterministically to rule-level actions when no branch
  selector matches.
- The runtime preview report reuses the shared typed rehearsal metadata and
  policy gate, surfacing projected blast radius, rollback expectations, and
  approval verdicts without calling live executors or mutating durable runtime
  state.
- `swarmctl playbook-preview` works against the signed repo config and returns
  one machine-readable `playbook_preview` envelope for operator automation.
