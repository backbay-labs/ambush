# Phase 157 Verification

status: passed

## Result

Phase 157 verification passed.

## Commands

- `cargo fmt --all`
- `cargo check -p swarm-core -p swarm-runtime --tests -j 1 --message-format short`
- `cargo test -p swarm-core config::tests::deception_enabled_requires_non_empty_playbook -- --exact`
- `cargo test -p swarm-core config::tests::deception_monitoring_confidence_must_be_high_fidelity -- --exact`
- `cargo test -p swarm-runtime calico_agent::tests:: -- --nocapture`
- `cargo test -p swarm-runtime --bin swarm_detect tests::serve_mode_registers_calico_when_deception_is_enabled -- --exact`

## Verified Behaviors

- Invalid repo-owned deception config now fails closed when `deception.enabled` is true without a playbook or when a monitoring rule drops below the required high-fidelity confidence floor.
- `CalicoAgent` now emits one baseline `DeployDecoy` request per playbook entry and does not re-emit those bootstrap actions on subsequent ticks.
- Monitored file-path and honeypot-port interactions now produce signed Calico pheromone deposits with confidence `>= 0.95` and the expected `initial_access` or `lateral_movement` threat class.
- Serve mode now registers an admitted Calico agent with a stable `swarm:ed25519:<hex>` identity when deception is enabled.
