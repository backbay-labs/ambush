# Phase 139 Plan 01 Summary

## Delivered

- Added repo-owned formal safety-gate config in `crates/swarm-core/src/config.rs`, wired it through `rulesets/default.yaml`, and seeded the first deterministic invariant bundle in `rulesets/safety/office-detector-admission.yaml`.
- Implemented deterministic formal safety verification in `crates/swarm-evolution/src/evolution.rs`, including repo-relative invariant loading, parameter-bound enforcement, corpus-backed threshold checks, and persisted bundle hashes on proved artifacts.
- Reused the existing selection, bridge, handoff, and canary machinery by routing Kitten proposals through the real admission lane in `crates/swarm-runtime/src/ingest.rs` instead of inventing a second review queue.
- Replaced the warning-only `SwarmAction::ProposeStrategy` branch in `crates/swarm-runtime/src/dispatcher.rs` with an asynchronous router seam so Kitten can keep its bounded tick loop while the runtime handles selection, safety review, and canary launch off-thread.
- Extended durable population state in `crates/swarm-evolution/src/mutation.rs` so accepted, blocked, and rejected proposal outcomes are written back to the retained candidate set instead of disappearing after routing.
- Registered the real proposal router in `crates/swarm-runtime/src/bin/swarm_detect.rs` and added focused regression coverage for config validation, formal safety acceptance and rejection, dispatcher routing, and end-to-end canary admission.

## Notes

- The shipped safety lane is deterministic and repo-owned. Optional `custom_z3` invariants are parsed but fail closed unless a proof backend is explicitly wired later.
- Formal safety currently evaluates the candidate against persisted verification and shadow artifacts already produced by the runtime, which keeps admission auditable and avoids a second replay lane.
- Phase 139 stops at proof-backed canary admission. Evolution metrics over SSE and `swarmctl evolution status` remain Phase 140 work.
