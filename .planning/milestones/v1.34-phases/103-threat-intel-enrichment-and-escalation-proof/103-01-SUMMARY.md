---
phase: 103-threat-intel-enrichment-and-escalation-proof
plan: 01
subsystem: runtime-detection
tags: [runtime, detection, threat-intel, dns]
requirements-completed: [SUBSTRATE-05]
one-liner: "The shared live detection pipeline now enriches findings with active threat-intel matches before pheromone deposits are written."
completed: 2026-04-07
---

# Phase 103 Plan 01 Summary

**The shared live detection pipeline now enriches findings with active threat-intel matches before pheromone deposits are written.**

## Accomplishments

- Added pipeline-level threat-intel enrichment inside `detect_and_deposit`, which keeps `DetectionStrategy` synchronous while still making live detection consult the substrate-backed cache.
- Implemented TTL-aware lookup against the configured substrate for normalized destination-IP and DNS-domain candidates derived from each telemetry event.
- Added DNS parent-domain expansion so operators can seed `evil.com` and still match suspicious subdomains like `abcdefghijklabcdefghijkl.evil.com`.
- Made confidence shaping deterministic by applying the highest active threat-intel confidence boost and capping enriched confidence at `1.0`.
- Annotated finding evidence with matched threat-intel records plus base, boost, and enriched confidence values for later operator inspection.
- Added focused runtime tests proving DNS findings are enriched by threat-intel matches before deposits are written.

## Files Created Or Modified

- `crates/swarm-runtime/src/detection/pipeline.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-runtime --lib`
- `cargo test -p swarm-runtime --test escalation_integration`
- `cargo clippy -p swarm-core -p swarm-pheromone -p swarm-runtime --tests -- -D warnings`

## Notes

- The live enrichment seam now covers both `ConfiguredRuntimeStack::process_event` and `WhiskerAgent`, because both already route through `detect_and_deposit`.
- Process-hash enrichment remains blocked on the current telemetry schema, so this phase intentionally limits matching to fields that exist today without widening the shared event model.
