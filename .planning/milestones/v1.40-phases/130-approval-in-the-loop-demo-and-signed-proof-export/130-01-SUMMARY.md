# Phase 130 Summary

## Delivered

- Extended `crates/swarm-runtime/src/ingest.rs` with demo-run approval state, `POST /v1/demo/approvals/{approval_set_id}/resume`, and `GET /v1/demo/proof` so human-gated demo runs can pause, resume, and export one proof package.
- Added a human-approved audited execution path in `crates/swarm-runtime/src/lib.rs` so resumed demo actions execute through the canonical runtime authorization, guard, lease, and adapter flow instead of a demo-only shortcut.
- Wired `crates/swarm-runtime/src/http/core.inc` so the operator approval vote endpoint automatically creates the verdict, exports the signed receipt pack, and calls back into the runtime resume endpoint once quorum is met.
- Hooked serve mode and CLI surfaces into the approval harness in `crates/swarm-runtime/src/bin/swarm_detect.rs`, `crates/swarm-runtime/src/cli/core.inc`, and `crates/swarm-runtime/Cargo.toml`, then tightened the demo tests around repo-owned policy rules and signer-derived voter identities.

## User-Visible Outcome

- A demo replay that hits `RequireHuman` now pauses cleanly and exposes a resumable approval target instead of executing immediately or silently failing.
- One signed operator approval vote can resume the paused action end to end and produce a final receipt-bearing runtime audit outcome.
- `GET /v1/demo/proof` now returns one JSON package containing the signed approval receipt pack, Merkle proofs for the recorded decision artifacts, the final correlated incident when present, and the full demo timeline.

## Notes

- The runtime demo path depends on a non-empty repository policy ruleset so the configurable approval gate can fall back to the static human-gate logic instead of fail-closing on an empty ruleset.
- Signed approval votes require the eligible voter ID to match the signer-derived `swarm:ed25519:...` identity embedded in the vote signature.
