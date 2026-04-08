# Phase 120: Composite Detector And Config Migration - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace the single-variant `SupportedDetector` dispatch with a `CompositeDetector` that holds multiple `DetectionStrategy` implementations and evaluates each event against all configured strategies. Migrate config from `strategy: string` to `strategies: [list]` with per-strategy profile overrides.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — pure infrastructure phase. Requirements define:
- COMPOSE-01: CompositeDetector holds Vec<Box<dyn DetectionStrategy>>, calls evaluate() on all, returns merged Vec<DetectionFinding>
- COMPOSE-02: DetectionConfig gains strategies: Vec<String> that takes precedence over legacy strategy scalar; per-strategy profile overrides in DetectorProfilesConfig

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DetectionStrategy` trait in `crates/swarm-whisker/src/detector.rs` with `fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding>`
- `SupportedDetector` enum in `crates/swarm-runtime/src/control.rs` dispatching single strategy
- `DetectionConfig` in `crates/swarm-core/src/config.rs` with `strategy: String`
- `DetectorProfilesConfig` in `crates/swarm-core/src/config.rs` for per-strategy profiles
- 7 existing detector implementations (process tree, DNS exfil, lateral movement, credential access, suspicious scripting, persistence, supply chain)

### Established Patterns
- Each detector has a corresponding Profile struct with validate()
- supported_detector() factory constructs detector from config
- detect_and_deposit() in pipeline.rs runs detection and deposits to substrate

### Integration Points
- control.rs: SupportedDetector enum and supported_detector() factory
- pipeline.rs: detect_and_deposit() takes a DetectionStrategy
- config.rs: DetectionConfig parsed from rulesets/default.yaml
- rulesets/default.yaml: current strategy: suspicious_process_tree

</code_context>

<specifics>
## Specific Ideas

Backward compatibility: existing single-strategy configs must continue working without modification.

</specifics>

<deferred>
## Deferred Ideas

None — both requirements are in scope.

</deferred>
