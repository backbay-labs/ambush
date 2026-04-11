# Phase 146 Verification

status: passed

## Result

Phase 146 verification passed.

## Commands

- `cargo fmt --all`
- `cargo check -p swarm-runtime -p swarm-cli --tests -j 1 --message-format short`
- `cargo test -p swarm-core config::tests::identity_requires_non_empty_registry_dir -- --exact`
- `cargo test -p swarm-runtime --lib agent_identity::tests::rotation_updates_registry_and_produces_verifiable_continuity_proof -- --exact`
- `cargo test -p swarm-runtime --lib dispatcher::tests::dispatcher_rejects_governance_actions_from_unadmitted_identities -- --exact`
- `cargo test -p swarm-runtime --bin swarm_detect tests::serve_mode_registers_sphinx_when_memory_is_enabled -- --exact`
- `cargo test -p swarm-cli core::tests::cli_parses_identity_rotate_command -- --exact`

## Verified Behaviors

- Runtime config now fails closed when `identity.registry_dir` is empty.
- The durable identity registry admits first-seen persisted identities, rejects unexpected replacements for the same role and slot, and persists continuity-proof rotation state with retired-key history.
- Serve-mode Sphinx registration now goes through registry admission before agent registration and still preserves the stable `swarm:ed25519:<hex>` identity path.
- The dispatcher rejects governance actions from unadmitted identities instead of applying role or health changes.
- `swarmctl identity rotate` is reachable through the shared CLI parser with the repo-owned role and slot arguments needed for operator-managed key rotation.
