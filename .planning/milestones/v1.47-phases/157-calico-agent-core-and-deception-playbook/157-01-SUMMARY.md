# Phase 157 Plan 01 Summary

## Delivered

- Added a repo-owned `deception` config surface in `crates/swarm-core/src/config.rs` with typed `DeceptionPlaybook` entries, placement strategies, monitoring rules, defaults, and fail-closed validation for empty or low-confidence tripwires.
- Added `CalicoAgent` in `crates/swarm-runtime/src/calico_agent.rs` as a real `SwarmAgent` implementation that emits one baseline `DeployDecoy` request per playbook entry and signs high-confidence `InitialAccess` / `LateralMovement` pheromone deposits when monitored file paths, honeypot ports, or canary credentials are touched.
- Wired serve-mode registration in `crates/swarm-runtime/src/bin/swarm_detect.rs` so Calico is admitted through the existing persistent-identity registry and runs behind `deception.enabled`.
- Updated `rulesets/default.yaml` and `docs/CONFIGURATION.md` so the checked-in mission config now documents the repo-owned deception lane and includes a valid baseline playbook example.

## Notes

- Phase 157 intentionally stops at core deception behavior: typed playbook config, baseline deployment requests, and high-confidence trigger deposits.
- Durable decoy lifecycle state, Sphinx graph registration, and Kitten fitness feedback remain Phase 158 work.
