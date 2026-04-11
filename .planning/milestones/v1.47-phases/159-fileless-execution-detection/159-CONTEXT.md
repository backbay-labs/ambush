# Phase 159: Fileless Execution Detection - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 159 expands the live detector set into fileless execution by adding a first-class memory-access telemetry event and a detector that can turn reflective injection, encoded PowerShell, and syscall-gadget hints into threat-class-aware findings.

</domain>

<decisions>
## Implementation Decisions

- Add a typed `TelemetryPayload::ProcessMemoryAccess` variant in `swarm-core` instead of hiding memory-access evidence inside free-form detector JSON.
- Implement a dedicated `FilelessExecutionDetector` in `swarm-whisker` and wire it through the existing runtime detector-factory/profile path rather than embedding heuristics directly into the runtime pipeline.
- Keep durable behavioral baselines and decay mechanics deferred to Phase 160; Phase 159 should stop at deterministic fileless execution coverage and threat-class mapping.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-core/src/telemetry.rs` owns the shared telemetry schema, and every downstream consumer currently matches `TelemetryPayload` exhaustively, so the new payload must propagate through all shared seams.
- `crates/swarm-whisker/src/detector.rs` is the current strategy home and export surface for runtime-owned detector profiles.
- `crates/swarm-runtime/src/detector_factory.rs` and `crates/swarm-runtime/src/config.rs` already own repo-based detector selection and profile validation, which is the correct seam for shipping `fileless_execution` as a first-class runtime detector.
- `crates/swarm-runtime/src/detection/pipeline.rs` already handles pheromone deposit signing and threat-intel enrichment, so Phase 159 should plug into that existing lane instead of creating a detector-specific deposit path.

</code_context>

<deferred>
## Deferred Ideas

- Per-host behavioral baselines, persistent decay, and anomaly scoring remain Phase 160 work.
- Broader evasion corpus coverage and detector robustness work remain queued in v1.48.

</deferred>
