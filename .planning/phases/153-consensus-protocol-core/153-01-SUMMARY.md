# Phase 153 Plan 01 Summary

## Delivered

- Replaced the placeholder `swarm-consensus` crate with a real reusable protocol core in `crates/swarm-consensus/src/lib.rs`, including committee membership validation, deterministic proposer rotation, JetStream subject helpers, wire envelopes, and a propose / prevote / precommit round engine.
- Derived proposer rotation from the previous commit hash plus a stable ordering of committee `AgentId` values so every node can compute the same leader locally without a separate VRF dependency.
- Added timeout-driven round advance and proposer rollover so stalled rounds can move forward without external orchestration logic.
- Added an in-process consensus harness that fans messages across three nodes and proves the committee commits ten sequential proposals while producing stable commit hashes for the next proposer seed.
- Kept the phase scoped to protocol core only: signatures, equivocation handling, runtime governance routing, and registry-backed admission are deferred to Phase 154.

## Notes

- The crate exposes a JetStream subject layout and JSON envelope seam, but the runtime still does not publish live governance traffic through it yet; that integration remains explicit next-phase work.
- The current threshold model is intentionally explicit on `max_faulty` and committee size so the runtime phase can choose single-instance `1-of-1` fallback versus multi-instance policy without hiding quorum math inside TomAgent.
