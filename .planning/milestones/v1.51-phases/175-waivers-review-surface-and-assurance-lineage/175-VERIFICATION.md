# Phase 175 Verification

status: passed

## Result

Phase 175 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-core evolution_requires_positive_assurance_waiver_ttl_when_enabled -- --nocapture`
- `cargo test -p swarm-core evolution_requires_ed25519_assurance_waiver_operator_ids_when_enabled -- --nocapture`
- `cargo test -p swarm-evolution evolution_queue_applies_signed_assurance_waiver_and_allows_accept_for_canary -- --nocapture`
- `cargo test -p swarm-evolution evolution_handoff_preserves_waived_assurance_lineage -- --nocapture`
- `cargo test -p swarm-evolution canary_start_with_assurance_accepts_active_waiver_lineage -- --nocapture`
- `cargo test -p swarm-evolution promotion_accepts_canary_with_active_waived_assurance_lineage -- --nocapture`
- `cargo test -p swarm-evolution canary_start_with_assurance_rejects_blocked_lineage -- --nocapture`
- `cargo test -p swarm-evolution promotion_rejects_canary_without_passed_assurance_lineage -- --nocapture`
- `cargo test -p swarm-evolution evolution_handoff_launch_rejects_missing_assurance_lineage -- --nocapture`
- `cargo test -p swarm-runtime evolution_status_harness_surfaces_active_assurance_waiver_lineage -- --nocapture`
- `cargo check -p swarm-evolution -p swarm-runtime --tests -j 1 --message-format short`

## Verified Behaviors

- Assurance waivers are signer-bound, time-bounded, gap-bounded, and validated against the current assurance digest before rollout progression is allowed.
- Queue acceptance can proceed from blocked assurance only when an active valid waiver clears the remaining assurance blocker.
- Handoff, canary, promotion, and status artifacts all preserve and render waived assurance lineage through the normal shipped review surfaces.
- Fail-closed rollout behavior remains intact when assurance lineage is missing, blocked, expired, or not covered by a valid waiver.

## Notes

- The target `evolution_status_harness_surfaces_active_assurance_waiver_lineage` test passed before a stale cargo runner continued enumerating zero-test package targets. The stale cargo process was terminated after the relevant target result had already completed.
