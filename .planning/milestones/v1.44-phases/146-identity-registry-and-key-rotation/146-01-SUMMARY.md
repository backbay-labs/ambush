# Phase 146 Plan 01 Summary

## Delivered

- Extended the repo-owned identity config with `identity.registry_dir` in `crates/swarm-core/src/config.rs`, surfaced the default in `rulesets/default.yaml`, and added fail-closed validation so the registry path cannot be left empty.
- Expanded `crates/swarm-runtime/src/agent_identity.rs` from a raw key store into a durable identity-lifecycle surface with `FileAgentIdentityRegistry`, active and retired identity records, continuity-proof persistence, registry-relative path resolution, and a key-replacement flow that preserves historical verification metadata.
- Wired `crates/swarm-runtime/src/bin/swarm_detect.rs` to open the registry during serve startup, admit persisted identities before agent registration, skip unregistered agents with structured warnings, and pass the admitted identity set into the dispatcher.
- Hardened `crates/swarm-runtime/src/dispatcher.rs` so governance-relevant actions (`RoleShift`, `HealthReport`, `RequestResponse`, `GovernanceVeto`, `ProposeStrategy`) fail closed when emitted by an identity outside the admitted set instead of propagating deeper into runtime routing.
- Added an operator-facing `swarmctl identity rotate` path through the shared CLI surface in `crates/swarm-cli/src/core.inc`, backed by the runtime registry and key store so rotation produces a durable continuity proof, retires the old public key with `active_until_ms`, and atomically promotes the new active key.

## Notes

- Registry enforcement in this phase is intentionally local to serve-mode startup and dispatcher governance actions. Substrate-wide rejection of unregistered deposits remains deferred to the distributed-governance milestone.
- Retired identity history stores public verification material and continuity proofs, not old private seeds.
