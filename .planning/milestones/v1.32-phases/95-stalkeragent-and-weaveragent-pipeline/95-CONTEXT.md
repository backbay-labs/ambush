# Phase 95: StalkerAgent And WeaverAgent Pipeline

## Vision

The live runtime graduates from a single sensing agent into an actual detect -> investigate -> correlate swarm. `WhiskerAgent` leaves detection pheromones, `StalkerAgent` turns those leads into persisted investigation work and investigation-result pheromones, and `WeaverAgent` consumes that second-stage signal to assemble durable correlated incidents.

## Decisions

- `StalkerAgent` reuses the existing replay bundle store and `InvestigationCoordinator` instead of inventing a second investigation path for agents
- Detection pheromones are keyed back to hunts through `indicator.event_id`, which already matches the hunt id used by the critical path (`HuntId(primary_finding.event_id.clone())`)
- `WeaverAgent` reuses the existing `CorrelationEngine`, investigation store, and incident store rather than building a parallel correlation mechanism
- Live serve-mode registration uses the existing config seams: `WhiskerAgent` always registers, `StalkerAgent` follows `investigation.enabled`, and `WeaverAgent` follows `correlation.enabled`
- Integration coverage will use the real in-memory substrate and memory-backed stores so the full multi-agent pipeline is deterministic and fast

## Deferred Ideas

- Generic config-driven factories for arbitrary future agent roles
- Investigation strategies beyond `SummaryInvestigator`
- Cross-agent backpressure and work stealing
- Richer pheromone schemas for investigation and incident outputs

## Claude's Discretion

- Exact investigation-result pheromone payload shape
- How aggressively StalkerAgent retries hunts that are queued but not yet completed
- Whether WeaverAgent emits a follow-up `PublishFindings` action in addition to persisting correlated incidents
- Runtime test harness structure for bounded dispatcher ticks
