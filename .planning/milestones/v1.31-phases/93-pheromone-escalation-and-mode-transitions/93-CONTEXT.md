# Phase 93: Pheromone Escalation And Mode Transitions

## Vision

The runtime reacts to pheromone concentration by transitioning modes (Normal -> Alert -> Incident) and emitting escalation events. This completes the swarm's stigmergic feedback loop: agents deposit pheromones, the concentration monitor senses thresholds, and the runtime shifts behavior accordingly.

## Decisions

- Escalation events (AlertEscalation, IncidentEscalation) are new types in `swarm-core::types` -- they follow the existing SwarmAction pattern but are emitted by the concentration monitor, not individual agents
- Mode transitions use the existing `SwarmMode` enum from `swarm-core::agent` (Normal, Alert, Incident)
- Concentration monitoring runs as a standalone async task (not a SwarmAgent) -- it queries the substrate on a configurable interval and evaluates all known threat classes
- Thresholds come from the existing `PheromoneConfig` fields: `alert_threshold` (2.0), `incident_threshold` (5.0), `min_sources_for_escalation` (2)
- `exceeds_threshold()` on `PheromoneConcentration` already implements the dual-gate logic (strength AND source diversity)
- Mode state is persisted in a simple `SwarmModeState` struct with current mode, last transition time, and triggering threat class
- Integration tests use `InMemoryPheromoneSubstrate` for speed -- no external dependencies

## Deferred Ideas

- ConcentrationMonitorAgent as a SwarmAgent implementation (could be done later, but a standalone async task is simpler and sufficient for now)
- Mode de-escalation (Incident -> Alert -> Normal) when concentrations drop below thresholds
- Per-threat-class mode tracking (currently one global mode)
- Mode transition cooldown / hysteresis to prevent flapping

## Claude's Discretion

- Exact metric names and label dimensions for mode transition counters
- Whether the concentration monitor iterates all ThreatClass variants or only those with active deposits
- Log format for escalation events (structured tracing spans)
- File organization within the escalation module
