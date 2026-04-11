# Phase 145 Plan 01 Summary

## Delivered

- Added repo-owned `identity.agent_key_dir` config in `crates/swarm-core/src/config.rs`, surfaced it through the runtime config loader, documented it in `docs/CONFIGURATION.md`, and set the default path in `rulesets/default.yaml`.
- Added `crates/swarm-runtime/src/agent_identity.rs` with a file-backed Ed25519 load-or-create store plus config-relative path resolution, and hardened the store against create-vs-read races so restart and concurrent bootstrap resolve to the persisted key material instead of a transient in-memory key.
- Wired `swarm_detect --serve` to load persisted identities for Whisker, Tom, Pounce, Kitten, Sphinx, Stalker, and Weaver, using the derived `swarm:ed25519:<hex>` value as the serve-mode agent ID instead of ephemeral role-local names.
- Extended the signed pheromone contract in `crates/swarm-core/src/pheromone.rs` and `crates/swarm-pheromone/src/substrate.rs` so deposits now bind `agent_identity` and `agent_role` into the canonical signature payload.
- Propagated the new deposit fields and identity config surface across runtime helpers and test fixtures, then added focused proof that stable serve-mode identities survive restart and propagate through the request / receipt audit path.

## Notes

- Unit-test constructors for runtime agents remain ephemeral by design; only serve-mode bootstrap uses the persisted identity store in this phase.
- Phase 145 stops at durable identity derivation and signed metadata. Registry admission, continuity proofs, and retired-key retention remain explicit Phase 146 work.
