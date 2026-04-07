## v1.31 Requirements: Runtime Agent Dispatcher And Pheromone-Driven Escalation

- [ ] **AGENT-01**: A configurable agent dispatcher runs registered SwarmAgent implementations on a tick interval within swarm-detect
- [ ] **AGENT-02**: WhiskerAgent wraps the existing detection pipeline as the first SwarmAgent trait implementation
- [ ] **AGENT-03**: Pheromone concentration monitoring triggers mode transitions (Normal to Alert to Incident) when thresholds are crossed
- [ ] **AGENT-04**: min_sources_for_escalation is enforced as a live gate on escalation events
- [ ] **AGENT-05**: Integration tests prove multi-source deposit to threshold crossing to escalation event emission

## v1.32 Requirements: Multi-Agent Runtime And Role Shifts

- [ ] **MULTI-01**: `SwarmAgent` implementations expose a mutable `AgentRole` via the existing `role()` method and can emit `SwarmAction::RoleShift` actions; the agent dispatcher propagates role changes to all registered agents through a broadcast event bus
- [ ] **MULTI-02**: An `AgentRegistry` holds a keyed roster of `Box<dyn SwarmAgent>` instances indexed by `AgentId`; agents register at startup from `SwarmConfig` and can be added or removed dynamically via a config-reload signal without restarting the runtime
- [ ] **MULTI-03**: Each agent's `tick()` receives a `SwarmEnvironment` snapshot that includes recent `PheromoneDeposit` entries from the `PheromoneSubstrate`, the current `SwarmMode`, and a read-only view of other agents' most recent findings, refreshed once per dispatcher tick
- [ ] **MULTI-04**: `StalkerAgent` implements `SwarmAgent` by wrapping the async `InvestigationCoordinator` pipeline, consuming `PheromoneDeposit` entries left by `WhiskerAgent`, and depositing investigation-result pheromones back into the substrate via `SwarmAction::DepositPheromone`
- [ ] **MULTI-05**: `WeaverAgent` implements `SwarmAgent` by wrapping the `CorrelationEngine` pipeline, reading `StalkerAgent` investigation pheromones from the substrate, and assembling `CorrelatedIncident` records when correlation thresholds are met
- [ ] **MULTI-06**: Agent lifecycle events (spawn, tick completion, health transitions via `AgentHealth`, and role shifts via `SwarmAction::RoleShift`) are emitted as structured JSON logs with `agent_id` fields and exposed as Prometheus counters (`agent_ticks_total`, `agent_role_shifts_total`, `agent_health_transitions_total`) partitioned by agent role
- [ ] **MULTI-07**: An integration test constructs a multi-agent runtime with `WhiskerAgent`, `StalkerAgent`, and `WeaverAgent` registered in the `AgentRegistry`, injects telemetry that triggers detection, and asserts the full pipeline: `WhiskerAgent` deposits detection pheromones, `StalkerAgent` claims and publishes investigation findings, and `WeaverAgent` assembles a `CorrelatedIncident` within a bounded number of dispatcher ticks
