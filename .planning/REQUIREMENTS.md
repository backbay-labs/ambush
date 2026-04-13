# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.30 Requirements (Completed)

### Structured Observability

- [x] **OBS-01**: All ingest and response operations emit structured JSON logs with request correlation IDs
- [x] **OBS-02**: Prometheus metrics include counters for decision verdicts, guard rejections, adapter outcomes, and detector findings per threat class

### Adapter Resilience

- [x] **OBS-03**: HTTP EDR and webhook adapters implement retry with exponential backoff and circuit breaker (disable after N consecutive failures)
- [x] **OBS-04**: Failed response actions are persisted to a dead-letter journal instead of being silently lost

### Operational Probes And Validation

- [x] **OBS-05**: /readyz and /livez endpoints exist for Kubernetes-style probe separation
- [x] **OBS-06**: All detector profiles validate configuration thresholds on load (reject invalid entropy, confidence, or count values)

## v1.31 Requirements (Completed)

### Runtime Agent Dispatcher And Pheromone-Driven Escalation

- [x] **AGENT-01**: A configurable agent dispatcher runs registered SwarmAgent implementations on a tick interval within swarm-detect
- [x] **AGENT-02**: WhiskerAgent wraps the existing detection pipeline as the first SwarmAgent trait implementation
- [x] **AGENT-03**: Pheromone concentration monitoring triggers mode transitions (Normal to Alert to Incident) when thresholds are crossed
- [x] **AGENT-04**: min_sources_for_escalation is enforced as a live gate on escalation events
- [x] **AGENT-05**: Integration tests prove multi-source deposit to threshold crossing to escalation event emission

## v1.32 Requirements (Completed)

### Multi-Agent Runtime And Role Shifts

- [x] **MULTI-01**: `SwarmAgent` implementations expose a mutable `AgentRole` via the existing `role()` method and can emit `SwarmAction::RoleShift` actions; the agent dispatcher propagates role changes to all registered agents through a broadcast event bus
- [x] **MULTI-02**: An `AgentRegistry` holds a keyed roster of `Box<dyn SwarmAgent>` instances indexed by `AgentId`; agents register at startup from `SwarmConfig` and can be added or removed dynamically via a config-reload signal without restarting the runtime
- [x] **MULTI-03**: Each agent's `tick()` receives a `SwarmEnvironment` snapshot that includes recent `PheromoneDeposit` entries from the `PheromoneSubstrate`, the current `SwarmMode`, and a read-only view of other agents' most recent findings, refreshed once per dispatcher tick
- [x] **MULTI-04**: `StalkerAgent` implements `SwarmAgent` by wrapping the async `InvestigationCoordinator` pipeline, consuming `PheromoneDeposit` entries left by `WhiskerAgent`, and depositing investigation-result pheromones back into the substrate via `SwarmAction::DepositPheromone`
- [x] **MULTI-05**: `WeaverAgent` implements `SwarmAgent` by wrapping the `CorrelationEngine` pipeline, reading `StalkerAgent` investigation pheromones from the substrate, and assembling `CorrelatedIncident` records when correlation thresholds are met
- [x] **MULTI-06**: Agent lifecycle events (spawn, tick completion, health transitions via `AgentHealth`, and role shifts via `SwarmAction::RoleShift`) are emitted as structured JSON logs with `agent_id` fields and exposed as Prometheus counters (`agent_ticks_total`, `agent_role_shifts_total`, `agent_health_transitions_total`) partitioned by agent role
- [x] **MULTI-07**: An integration test constructs a multi-agent runtime with `WhiskerAgent`, `StalkerAgent`, and `WeaverAgent` registered in the `AgentRegistry`, injects telemetry that triggers detection, and asserts the full pipeline: `WhiskerAgent` deposits detection pheromones, `StalkerAgent` claims and publishes investigation findings, and `WeaverAgent` assembles a `CorrelatedIncident` within a bounded number of dispatcher ticks

## v1.33 Requirements (Completed)

### Telemetry Bridge Architecture

- [x] **BRIDGE-01**: A `TelemetryBridge` trait in `swarm-core` defines the shared bridge contract with `fn source_id() -> &str`, `async fn poll(&mut self) -> Result<Vec<TelemetryEvent>>`, `fn validate_schema(&self, event: &TelemetryEvent) -> bool`, and `fn health(&self) -> BridgeHealth` for reporting events processed, error count, lag, and last error context
- [x] **BRIDGE-02**: The existing `TetragonBridge` in `swarm-ingest-tetragon` is refactored to implement the `TelemetryBridge` trait, replacing its current direct `Sender<TelemetryEvent>` channel coupling with the trait's `poll`/`health` interface while preserving its reconnect-backoff and `map_process_exec` mapping logic
- [x] **BRIDGE-03**: A `CloudTrailBridge` implements `TelemetryBridge` and maps AWS CloudTrail JSON records (API calls via `eventName`, authentication events via `userIdentity`, S3 data-access events via `requestParameters.bucketName`) into `TelemetryEvent` with `TelemetryPayload::AuthenticationEvent` or `TelemetryPayload::NetworkConnect` as appropriate
- [x] **BRIDGE-04**: A `GenericJsonBridge` implements `TelemetryBridge` and accepts arbitrary JSON documents, mapping fields to `TelemetryEvent` via a `FieldMappingConfig` (configurable paths for `event_id`, `timestamp`, `host_id`, and `payload` variant selection) loaded from `SwarmConfig` at startup without recompilation
- [x] **BRIDGE-05**: Runtime config in `SwarmConfig.runtime.telemetry_sources` selects active bridges by name; the runtime spawns only the named bridges, and each bridge instance exposes event-count, error-count, and lag-seconds metrics on the existing `/healthz` and `/metrics` endpoints
- [x] **BRIDGE-06**: Integration tests start two bridge instances ingesting events concurrently into a shared channel, and assert that both sources produce `DetectionFinding` records through the `DetectionStrategy` pipeline and result in `PheromoneDeposit` entries in the substrate

## v1.34 Requirements (Completed)

### Queryable Substrate And Threat Intel Cache (v1.34)

- **SUBSTRATE-01**: `SwarmMode` transitions (Normal, Alert, Incident) are persisted as timestamped `EscalationRecord` entries in the `PheromoneSubstrate` and are queryable via a new `async fn query_escalations(&self, since: i64) -> Result<Vec<EscalationRecord>>` method on the `PheromoneSubstrate` trait, surviving process restarts on durable backends
- **SUBSTRATE-02**: `SwarmEnvironment` exposes `fn current_mode() -> SwarmMode` and `fn mode_transition_at() -> Option<i64>` so that `SwarmAgent::tick` implementations can make mode-aware decisions such as increasing sampling rate during `SwarmMode::Alert` or unlocking response actions during `SwarmMode::Incident`
- **SUBSTRATE-03**: Per-`ThreatClass` pheromone parameters (half-life, evaporation threshold, escalation strength threshold) are stored as `ThreatClassConfig` records in the substrate and reloadable at runtime via the operator API without process restart, overriding `PheromoneConfig` defaults when present
- **SUBSTRATE-04**: Operators can seed threat-intel indicators (IP addresses, domain names, file hashes) into the substrate via the operator API as `ThreatIntelEntry` records carrying a `confidence: f64` score and a configurable `expires_at: i64` TTL, queryable by indicator type and value
- **SUBSTRATE-05**: `DetectionStrategy::evaluate` implementations can query the threat-intel cache during detection; when a `TelemetryEvent` field (destination IP, DNS query name, or process hash) matches a `ThreatIntelEntry`, the detector boosts the `DetectionFinding.confidence` by the entry's confidence score, capped at 1.0
- **SUBSTRATE-06**: An integration test seeds a `ThreatIntelEntry` for a known-malicious domain, sends a `TelemetryEvent` with a `DnsQuery` matching that domain through the `DnsExfiltrationDetector`, and asserts that the resulting `DetectionFinding.confidence` exceeds the `PheromoneConfig.alert_threshold` and triggers a `SwarmMode::Alert` escalation in the substrate

### Production Hardening And Kubernetes Lifecycle (v1.35)

- **K8S-01**: A PreStop lifecycle handler stops accepting new requests on `/v1/ingest/events`, waits for all in-flight `ConfiguredRuntimeStack::process_event` calls and pending `ResponseExecutor::execute` futures to complete (bounded by a configurable `drain_timeout_ms` in `RuntimeSettings`), then initiates a clean Tokio runtime shutdown so Kubernetes rolling updates never drop active detection or response work
- **K8S-02**: A `/startupz` endpoint validates the loaded `SwarmConfig` schema version, confirms the `PheromoneSubstrate` returns `SubstrateHealth { ready: true }`, verifies at least one `TelemetrySourceConfig` is configured, and returns HTTP 503 until all checks pass, gating Kubernetes startup probes independently from the `/readyz` healthy-operation check
- **K8S-03**: A `SwarmSecretProvider` trait with `fn resolve(&self, reference: &str) -> Result<String>` resolves `auth_token` values in `HttpEdrConfig` and `WebhookConfig` when prefixed with `@secret:` from mounted files at a configurable `secret_dir` path or from environment variables, and a file-watch thread reloads secrets on change without process restart
- **K8S-04**: `SwarmConfig` gains a required `schema_version: u32` field; `parse_config` rejects configs with `schema_version` greater than the compiled maximum, logs a structured migration-step summary when applying backward-compatible transforms for older versions, and returns `RuntimeConfigError::Validation` for unrecognized versions
- **K8S-05**: The `/metrics` endpoint exposes `swarm_heap_bytes` and `swarm_heap_pressure_ratio` gauges via `CriticalPathMetrics`; the `/readyz` handler returns HTTP 503 when `swarm_heap_pressure_ratio` exceeds a configurable `max_heap_pressure` threshold in `RuntimeSettings`, allowing Kubernetes to shed load before OOM
- **K8S-06**: A disaster recovery runbook documents procedures for NATS JetStream connection loss, dead-letter journal disk full, `CircuitBreakerState` stuck open, and `PolicyVerdict::Deny` blocking all response actions, with detection signals, operator remediation steps, and verification commands

## Future Requirements

### SIEM/SOAR Forward And Alert Routing (v1.36)

- **SIEM-01**: A `SiemForwardAdapter` implements `ResponseExecutor` and serializes `DetectionFinding` payloads into a canonical `swarm_finding` JSON schema, forwarding them to Splunk HEC, ELK bulk ingest, or Chronicle ingestion API as selected by a `SiemForwardConfig` variant, inheriting `ResilientExecutor` retry and `CircuitBreakerState` circuit-breaker behavior from `swarm-response`
- **SIEM-02**: A `FindingEnrichmentService` decorates each `DetectionFinding` before SIEM forwarding by attaching `parent_process_ancestry`, `host_metadata`, and `time_to_detect_ms` as additional fields in the `DetectionFinding.evidence` payload
- **SIEM-03**: A `NotificationRouter` in `swarm-response` is configured via a `notification_channels` map in `SwarmConfig` where each named channel specifies a `target_url`, optional `auth_token` (supporting `@secret:` references), `rate_limit`, and `quiet_hours`
- **SIEM-04**: A `RoutingRule` DSL in `SwarmConfig.notification_routing` matches `DetectionFinding` records by `severity` threshold, `threat_class` variant, and UTC time-of-day range, routing matched findings to one or more named notification channels
- **SIEM-05**: A deduplication layer merges `DetectionFinding` records sharing the same `strategy_id` and `ThreatClass` within a configurable `dedup_window_ms` into a single aggregated notification with merged count, time range, and highest severity
- **SIEM-06**: Each notification channel enforces a configurable rate limit tracked in memory; findings suppressed by the rate limit are written to a per-channel dead-letter queue backed by `DeadLetterJournal`, and the operator API exposes a `/v1/notifications/dead-letter/{channel}` endpoint to list and replay suppressed alerts

### Persistence And Supply Chain Detection (v1.37)

- **PERSIST-01**: A `PersistenceDetector` implements `DetectionStrategy` and identifies suspicious scheduled task creation, cron entry modification, systemd timer installation, and registry run key writes from `TelemetryEvent` payloads using two new `TelemetryPayload` variants: `RegistryPersistence` and `FilePersistence`
- **PERSIST-02**: A `SupplyChainDetector` implements `DetectionStrategy` and identifies unsigned binaries executing from trusted paths, DLL side-loading patterns, and signed-binary abuse (certutil with `-urlcache`, rundll32 with remote or `javascript:` arguments) from `ProcessStart` and `FilePersistence` telemetry events
- **PERSIST-03**: The `ThreatClass` enum includes a new `SupplyChain` variant; both detectors tag every `DetectionFinding` with a `mitre_technique_id` field in the `evidence` JSON object
- **PERSIST-04**: Both detectors are configurable via `PersistenceProfile` and `SupplyChainProfile` with `validate()` returning `ProfileValidationError` consistent with existing detector profiles
- **PERSIST-05**: Integration tests construct synthetic telemetry events, evaluate them through both detectors, assert correct `ThreatClass` and `mitre_technique_id`, and convert findings to `PheromoneDeposit` entries via `findings_to_deposits`

### Runtime Hardening And Audit Debt (v1.37.1)

#### Agent Safety

- [x] **HARDEN-01**: `WhiskerAgent` and `StalkerAgent` sign every `PheromoneDeposit` using their agent signing key before submitting to the substrate; deposits with empty `signature` or `agent_key` fields are rejected by `PheromoneSubstrate::deposit()` with a structured error
- [x] **HARDEN-02**: The `AgentDispatcher` wraps every `SwarmAgent::tick()` call in `tokio::time::timeout()` with a configurable `agent_tick_timeout_ms` in `RuntimeSettings` (default 500ms); agents that exceed the timeout are marked `AgentHealth::Degraded` and their tick is skipped for that cycle
- [x] **HARDEN-03**: The `AgentDispatcher::apply_actions()` handler logs a structured warning for any `SwarmAction` variant that is not explicitly processed (currently `ClaimInvestigation` and `PublishFindings` are silently dropped), and documents in code comments which actions are agent-direct vs dispatcher-routed

#### Substrate Durability

- [x] **HARDEN-04**: A `gc_expired_threat_intel()` method on `PheromoneSubstrate` removes `ThreatIntelEntry` records whose `expires_at` has passed; the method runs on the same GC interval as `gc_evaporated()` across all three backends (in-memory, local-journal, JetStream) and logs the number of entries purged
- [x] **HARDEN-05**: The `LocalJournalPheromoneSubstrate` rewrites the threat-intel journal file during GC to remove expired entries, preventing unbounded disk growth consistent with the existing deposit journal rewrite pattern

#### Bridge Resilience

- [x] **HARDEN-06**: `TetragonBridge::poll()` wraps `stream.next().await` in `tokio::time::timeout()` with a configurable `event_timeout_secs` (default 30s); a timeout records a health error, increments `swarm_bridge_error_count`, and triggers reconnect-backoff instead of hanging indefinitely
- [x] **HARDEN-07**: `TetragonBridge` schema validation accepts `ProcessStartEvent` with an empty `parent_process` field (init-spawned processes have no parent) instead of rejecting it, using `"<none>"` as a sentinel value when the parent is absent

#### Operational Gaps

- **HARDEN-08**: The `SwarmSecretProvider` file-watch thread monitors the configured `secret_dir` for changes independently of the main config file watch; when a secret file changes, only the affected `@secret:` references are re-resolved and injected into active response adapter configs without requiring a full config reload
- **HARDEN-09**: Dead-letter journals (response and notification) implement size-based rotation when the journal file exceeds a configurable `max_dead_letter_bytes` in `RuntimeSettings`; the rotated file is renamed with a timestamp suffix and the active journal is truncated

#### Test Coverage

- **HARDEN-10**: `swarm-pheromone` gains a focused test suite covering deposit, query, evaporation GC, escalation record persistence, threat-intel CRUD with TTL expiry, and `ThreatClassConfig` store/query across the `InMemoryPheromoneSubstrate`; at least 15 tests that exercise the substrate trait contract independently of the runtime

### Multi-Detector Composition And Network Detection (v1.38)

#### Composition

- **COMPOSE-01**: A `CompositeDetector` implements `DetectionStrategy` by holding a `Vec<Box<dyn DetectionStrategy>>` and calling `evaluate()` on every contained strategy for each `TelemetryEvent`, returning merged findings, replacing the single-variant `SupportedDetector` dispatch
- **COMPOSE-02**: `DetectionConfig` gains an optional `strategies: Vec<String>` field that takes precedence over the existing `strategy: String` scalar, with per-strategy profile overrides in `DetectorProfilesConfig`
- **COMPOSE-03**: Deposits from different strategies on the same event use distinct `PheromoneDeposit.agent_id` values incorporating the `strategy_id`, so `PheromoneConcentration.distinct_sources` reflects independent strategy signals toward `min_sources_for_escalation`
- **COMPOSE-04**: `CorrelationEngine::assemble_incident_at()` applies higher correlation weight to `IncidentMemberDecision` pairs with different `strategy_id` values than same-strategy pairs
- **COMPOSE-05**: `CanaryConfig` and `PromotionConfig` gain an optional `strategy_id` field to scope canary/promotion observation to a single strategy within the `CompositeDetector`

#### Network Detection

- **NETWORK-01**: A `NetworkConnectDetector` implements `DetectionStrategy`, matches `TelemetryPayload::NetworkConnect` events, and detects C2 beaconing patterns (periodic connections with low inter-arrival jitter to the same destination from the same process)
- **NETWORK-02**: The runtime-owned detection pipeline queries `PheromoneSubstrate::query_threat_intel_entry()` with `ThreatIntelIndicatorType::IpAddress` for `TelemetryPayload::NetworkConnect` destination IPs, annotates matching findings with threat-intel evidence, and boosts `DetectionFinding.confidence` without changing the synchronous detector contract
- **NETWORK-03**: A `NetworkConnectProfile` defines `suspicious_ports: Vec<u16>` and `process_port_allowlist: HashMap<String, Vec<u16>>` for anomalous port and process-to-port mismatch detection
- **NETWORK-04**: `NetworkConnectDetector` sets findings to `ThreatClass::CommandAndControl`; integration tests prove NetworkConnect telemetry through detection to signed pheromone deposit
- **NETWORK-05**: A cross-strategy integration test configures `CompositeDetector` with 3+ strategies, feeds a multi-stage attack sequence, and asserts `PheromoneConcentration.distinct_sources >= 3` triggers escalation via `min_sources_for_escalation`

### PounceAgent And Policy Gate Hardening (v1.39)

#### Autonomous Response

- **POUNCE-01**: `PounceAgent` implements `SwarmAgent` with `AgentRole::Pouncer`, reads `SwarmEnvironment.mode` and `pheromones`, and emits `SwarmAction::RequestResponse` with `ResponseAction` variants when mode is `Alert` or `Incident`
- **POUNCE-02**: `PounceAgent::tick()` checks `SwarmEnvironment.peer_findings` to skip emitting responses whose target scope matches an existing `AgentFinding` in the same tick cycle
- **POUNCE-03**: A `ResponsePlaybookConfig` maps `(ThreatClass, Severity, confidence_range)` tuples to ordered `ResponseAction` sequences with per-step `escalation_timeout_secs`
- **POUNCE-04**: `AgentDispatcher::apply_actions()` routes `SwarmAction::RequestResponse` through `SwarmRuntime::authorize_and_execute()` so PounceAgent actions flow through the policy gate and guard pipeline
- **POUNCE-05**: PounceAgent supports a dry-run mode that routes through the identical code path as live mode, passing `ExecutionMode::DryRun` to the executor, producing receipts with `status: Simulated`

#### Policy Hardening

- **POLICY-01**: `SwarmRuntime::authorize_and_execute()` validates `CapabilityLease.expires_at_ms > ApprovalContext.now_ms` before executing; expired leases return `ApprovalError::Denied("capability lease expired")`
- **POLICY-02**: `StaticApprovalGate` tracks recent actions per scope and denies requests exceeding a configurable `max_actions_per_scope_per_minute` rate limit
- **POLICY-03**: A `ConfigurableApprovalGate` loads YAML rules with action allow/deny by threat class, severity thresholds, time-of-day restrictions, and per-agent rate limits
- **POLICY-04**: Every policy verdict carries the matched rule name and verdict reason in structured logs and `ResponseReceipt` audit records

#### Mode De-escalation

- **DEESC-01**: `SwarmModeState` gains `transition_down()` that de-escalates mode when the new mode is lower than current, updating `last_transition_at` and clearing `triggering_threat_class`
- **DEESC-02**: `ConcentrationMonitor::evaluate_all()` calls `transition_down()` when all threat-class concentrations stay below alert threshold for a configurable `deescalation_cooldown_secs`

#### Agent Governance

- **TOM-01**: `TomAgent` implements `SwarmAgent` with `AgentRole::Tom`, monitors agent health summaries, and emits `RoleShift` for degraded agents and `HealthReport { status: Failed }` for agents degraded beyond a configurable tick threshold
- **TOM-02**: `TomAgent` provides pre-execution synchronous veto authority over destructive PounceAgent actions via a shared `GovernancePolicy`; vetoed actions produce auditable veto receipts with the rejected action and reason

### Killer Demo And Providence Integration (Active v1.40)

#### Demo Infrastructure

- [x] **DEMO-01**: `POST /v1/demo/replay` (gated behind `demo_mode` config) accepts a scenario YAML path and injects events into the running telemetry channel with configurable inter-event delay, driving the full agent swarm
- [x] **DEMO-02**: `GET /v1/events/stream` emits Server-Sent Events for agent actions (pheromone deposits, investigation claims, correlation publishes, escalation transitions, policy decisions, response executions) with event-type filtering
- [x] **DEMO-03**: The review workbench includes a real-time dashboard showing `SwarmMode`, per-agent health, per-`ThreatClass` pheromone concentrations, and a scrolling escalation timeline
- [x] **DEMO-04**: Demo flow pauses at `RequireHuman` policy verdicts; operator approves via approval-set vote endpoint; response executes with signed receipt proving the approval chain
- [x] **DEMO-05**: `GET /v1/demo/proof` exports a JSON document with all signed receipts, Merkle proofs, the final `CorrelatedIncident`, and full decision timeline

#### Providence Integration

- [x] **PROV-01**: A `providence_webhook` notification channel delivers `SwarmFindingEnvelope` payloads to a Providence API endpoint, mapping threat_class and severity to Providence incident fields
- [x] **PROV-02**: Providence webhook payloads include stable URL references back to Swarm operator API for finding drilldown, replay bundle access, and audit trail inspection
- [x] **PROV-03**: Providence webhook payloads include current `SwarmMode`, active agent count, and bridge health summary for runtime status display

### Deployment And Hardening (v1.41)

#### Platform API

- **API-01**: A `/v2/api/` route group on the detect HTTP server (port 9090) serves cursor-paginated, filterable endpoints for findings, incidents, and runtime status with a `{ data: [...], cursor: Option<String> }` envelope (default page_size=50, max 200), separate from the `/v1/operator/` surface
- **API-02**: `GET /v2/api/assets/{host_id}/posture` returns per-`ThreatClass` pheromone concentration summaries, active investigations, escalation level, and recent findings for a host; prerequisite: `PheromoneSubstrate` gains a host-filtered query method or filter parameter on existing `query_deposits()`
- **API-03**: `GET /v2/api/stream/findings` reuses the existing `RuntimeEventBroadcaster` with a `finding` event type filter (consistent with the `/v1/events/stream?types=` pattern) to emit Server-Sent Events of `SwarmFindingEnvelope` payloads as they are produced
- **API-04**: Platform API keys protect only `/v2/api/*` routes; health probes and `/v1/ingest/events` remain unauthenticated. Each key entry in `SwarmConfig.platform_api.keys` includes `name`, `key_hash` (SHA-256), and `scopes: ["read"]`; middleware extracts the key, resolves scope, and attaches identity to the request context

#### Deployment

- **HELM-01a**: A base Helm chart deploys `swarm_detect --serve` as the main workload with ConfigMap-mounted `SwarmConfig`, Kubernetes Secrets for `@secret:` references, and sensible resource requests/limits derived from the existing `Dockerfile` multi-stage build
- **HELM-01b**: The Helm chart parameterizes runtime mode, detection strategies, pheromone backend (in-memory vs JetStream), response adapter, SIEM target, and notification channels via `values.yaml`, with a NATS subchart dependency when the JetStream backend is selected
- **HELM-02**: The Helm chart wires existing probe endpoints: startup `/startupz` (initialDelaySeconds=5, periodSeconds=5, failureThreshold=12), readiness `/readyz` (periodSeconds=10, failureThreshold=3), liveness `/livez` (periodSeconds=15, failureThreshold=3), PreStop `/prestop`, with a `PodDisruptionBudget` of minAvailable=1
- **CLI-01**: `swarmctl validate --config <path>` performs full config validation including schema version, detector profile thresholds, and `@secret:` reference resolution; opt-in `--check-endpoints` attempts TCP connect (5s timeout) to configured webhook/SIEM URLs; exits non-zero on failure with structured JSON output when `--json` is passed
- **CLI-02**: `swarmctl init --mode detect_only|live_response` generates a complete `rulesets/custom.yaml` with documented defaults and inline comments for the selected mode; no interactive prompts

#### Runtime Hardening

- **HARD-01**: The 8 `Default::default()` implementations in `swarm-whisker` detectors (`detector.rs`, `dns_exfiltration.rs`, `lateral_movement.rs`, `credential_access.rs`, `suspicious_scripting.rs`, `persistence.rs`, `supply_chain.rs`, `network_connect.rs`) that panic on profile validation failure are replaced with `const`-validated defaults or fallible constructors returning `Result`; the 2 `.expect()` calls in `swarm-runtime/src/ingest.rs` (demo proof export path) are replaced with `Result` propagation
- **HARD-02**: The evolution subsystem (~23K LoC: `drafting.rs`, `mutation.rs`, `evolution.rs`, `selection.rs`, `portfolio.rs`, `governance_prep.rs`, `canary.rs`, `promotion.rs`, `strategy.rs`, `evidence.rs`) is extracted to a `swarm-evolution` crate; the CLI (~3.5K LoC: `cli/core.inc`, `bin/swarmctl.rs`) is extracted to a `swarm-cli` crate; `swarm-runtime` retains agents, HTTP, ingest, and dispatcher since they share too much state to cleanly separate
- **HARD-03a**: Bearer token validation is added to the detect server's `/v2/api/*` routes consistent with the operator surface `require_bearer_auth` middleware pattern; per-request authenticated identity is logged as a structured `tracing` span field
- **HARD-03b**: Optional TLS on both HTTP servers via `SwarmConfig.tls.cert_path` and `tls.key_path` using `tokio-rustls`; when `tls.client_ca_cert` is additionally configured, the server requires and validates client certificates with identity extracted from the certificate Subject CN
- **HARD-04**: `#[instrument]` attributes are added to the critical path: `IngestState::process_event()`, `ConfiguredRuntimeStack::process_event()`, `CompositeDetector::evaluate()`, `ConfigurableApprovalGate::check()`, and `DispatchingExecutor::execute()`; the existing `correlation_id` is used as the `trace_id` span field; OTLP export is behind an `--otlp-endpoint` CLI flag, defaulting to stdout JSON via the existing `init_tracing()` setup

### Evolution Engine Core (v1.42)

#### Kitten Agent

- **KITTEN-01**: `KittenAgent` implements `SwarmAgent` with `AgentRole::Kitten` and runs a genetic algorithm mutation loop over detector profile configurations (`SuspiciousProcessTreeProfile`, `DnsExfiltrationProfile`, `NetworkConnectProfile`, `PersistenceProfile`, `SupplyChainProfile`, `CredentialAccessProfile`), producing candidate strategies with mutated thresholds and rule combinations; mutation operators include Gaussian perturbation for floats, swap for categoricals, and toggle for rule activation; the agent uses a multi-tick state machine (`AwaitingDrift → Mutating → Evaluating → Verifying → Proposing`) to avoid exceeding the 500ms tick timeout
- **KITTEN-02**: Candidate strategies are evaluated against the repo-owned replay corpus (`scenarios/`); fitness scoring uses a configurable multi-objective function (defaults: 0.40 detection rate, 0.30 false-positive cost against `benign-baseline.yaml`, 0.15 speed relative to a 1000us budget per event, 0.15 ATT&CK `ThreatClass` coverage fraction) with Pareto tournament selection for non-dominated candidates; fitness weights are specified in `SwarmConfig.evolution.fitness_weights`
- **KITTEN-03**: `KittenAgent` activates evolution based on detected concept drift: a `ConceptDriftDetector` maintains a sliding window of detection metrics and triggers when detection rate declines or false-positive rate rises beyond configurable thresholds (`SwarmConfig.evolution.drift_threshold_pct`, `observation_window_secs`); includes a minimum observation count before drift is declared and a cooldown period after evolution produces a candidate
- **KITTEN-04**: Evolved candidates are submitted to the existing canary pipeline via the existing `SwarmAction::ProposeStrategy` variant (with `strategy_id`, `strategy`, and `fitness` fields); the `AgentDispatcher::apply_actions()` handler routes `ProposeStrategy` through the safety gate (SAFETY-01) and then to the existing `EvolutionProposalReviewState::AcceptedForCanary` handoff; canary failure returns the candidate to the population with a failure record
- **KITTEN-05**: The Kitten's population of candidate strategy genomes is serialized to the durable substrate on each generation and restored on restart, preventing loss of evolutionary progress; a configurable `max_proposals_per_hour` throttle prevents flooding the canary pipeline

#### Formal Safety Gate

- **SAFETY-01**: A `FormalSafetyGate` trait with `fn verify(&self, candidate: &StrategyGenome) -> Result<VerificationReport>` validates evolved strategies before canary admission using a two-tier approach: Tier 1 is a deterministic property checker that runs the candidate against known-bad and benign corpora and verifies coverage floors, FP ceilings, and latency budgets (matching the 5 invariant types in `EvolutionProofInvariant`); Tier 2 is optional Z3 SMT verification behind a `z3` feature flag for operators who want formal universal-quantification proofs
- **SAFETY-02**: Safety invariants are defined as repo-owned YAML files in `rulesets/safety/` with `schema_version: u32`; each invariant specifies `type` (coverage_floor, fp_ceiling, latency_budget, parameter_bounds, custom_z3), target corpus path, and threshold; operators can add domain-specific invariants without modifying Rust code
- **SAFETY-03**: The safety gate runs asynchronously via a background task (not blocking the Kitten's tick loop); the Kitten checks for verification results on subsequent ticks; verification results are persisted as signed `EvolutionProofReport` artifacts in the existing spine audit trail with strategy genome hash, invariant file hash, and counterexamples on failure

#### Evolution Observability

- **EVOLVE-OBS-01**: Evolution metrics are emitted as `RuntimeEvent` types on the existing SSE broadcaster: generation count, population diversity (mean pairwise distance), best/mean fitness per objective, verification pass/fail rate, and canary admission rate
- **EVOLVE-OBS-02**: `swarmctl evolution status` displays current generation, population size, drift detector state, latest fitness scores, and pending/completed verification results

### Swarm Memory And Adversarial Pressure (v1.43)

#### Sphinx Memory Agent

- **SPHINX-01**: `SphinxAgent` implements `SwarmAgent` with `AgentRole::Sphinx` and maintains a persistent knowledge graph of threat patterns, ATT&CK technique observations, and cross-engagement correlations; storage uses a `FileKnowledgeGraphStore` following the pattern of `FileStrategyMemoryStore`, not the pheromone substrate (which is designed for time-decaying signals, not persistent knowledge)
- **SPHINX-02**: The knowledge graph uses typed nodes (`ThreatPattern`, `ATTACKTechnique`, `Entity`, `Engagement`) and typed edges (`Temporal` with configurable window, `Causal` from process parent-child and network flow origin, `Entity` linking by shared host/user/process, `Semantic` linking by shared ATT&CK kill chain stage); start with this concrete graph model and iterate toward the full MAGMA multi-dimensional traversal in later milestones
- **SPHINX-03**: Other agents query Sphinx indirectly through pheromone substrate deposits: agents deposit `QueryPheromone` entries with a query type and parameters; `SphinxAgent` reads these deposits on its tick and responds with `AnswerPheromone` deposits containing results; this preserves the indirect stigmergic communication model rather than adding direct inter-agent request/response messaging
- **SPHINX-04**: Strategy fitness evaluation in `KittenAgent` incorporates Sphinx knowledge via Q-value-based retrieval: `Q(strategy, context) = sum(relevance * outcome_reward * recency_decay)` using the existing `RECENCY_HALF_LIFE_HOURS` from `strategy.rs`; falls back to pure replay fitness when Sphinx is unavailable or has insufficient data for the context
- **SPHINX-05**: The knowledge graph implements TTL-based garbage collection for stale entries (configurable `knowledge_retention_days`, default 90) to prevent unbounded growth, following the existing `gc_expired_threat_intel()` pattern

#### Adversarial Co-Evolution

- **HELLCAT-01**: A `RedSwarmAdapter` trait (`async fn generate_adversarial_sequence(&self, context: &ThreatContext) -> Vec<TelemetryEvent>`) generates adversarial telemetry sequences; the default implementation reads and parameterizes scenario files from `scenario-suites/` (extending the existing `hellcat-office-v1.yaml` pattern) without requiring the full Hellcat Python system; a `MockRedSwarm` implementation exists for testing with static scenarios
- **HELLCAT-02**: `KittenAgent` fitness evaluation includes adversarial pressure from `RedSwarmAdapter`-generated sequences; blue detection fitness is measured against the latest adversarial corpus snapshot (frozen per-generation for reproducibility); the adversarial corpus is regenerated between generations; fitness artifacts record the adversarial corpus version used
- **HELLCAT-03**: Red-blue evolution episodes are logged as `EvolutionEpisode` records persisted in a `FileEvolutionEpisodeStore` (following the existing store pattern) containing: episode_id, generation, adversarial corpus version, blue strategy genome hash, per-`ThreatClass` detection and evasion coverage, and fitness vectors for both sides

### Agent Identity And Infrastructure Signals (v1.44)

#### Agent Identity Lifecycle

- **IDENTITY-01**: Agent keys are generated at first startup and persisted to a configurable `agent_key_dir` path; keys survive restarts and are loaded on startup with identity derived from the Ed25519 public key (`swarm:ed25519:<hex>`)
- **IDENTITY-02**: An `AgentIdentityRegistry` maintains the set of known agent identities; agents register on startup and are admitted to the registry after identity verification; unknown agent identities are logged and rejected from governance participation
- **IDENTITY-03**: Agent key rotation generates a new keypair, creates a continuity proof (old key signs a handoff message containing the new public key), and updates the registry; the old key is retained for verification of historical signed artifacts

#### Infrastructure Signal Detection

- **INFRA-01**: A `swarm-ingest-sentinel` crate implements the `TelemetryBridge` trait for Sentinel-derived infrastructure telemetry; it maps the three payload types from sentinel-convergence doc 05 (`InfrastructureHealth` with CPU/memory/thermal metrics, `ThermalAnomaly` with temperature spike data, `ResourceExhaustion` with trending resource usage) into new `TelemetryPayload` variants consumable by the detection pipeline
- **INFRA-02**: An `InfrastructureAnomalyDetector` implements `DetectionStrategy` and detects infrastructure-signal threats: cryptominer activity via sustained CPU/thermal anomalies, resource exhaustion from fork bombs or disk wipers, and memory pressure spikes correlating with fileless malware; the shipped detector maps those patterns into existing escalation classes (`ThreatClass::Execution`, `ThreatClass::Impact`, `ThreatClass::DefenseEvasion`)
- **INFRA-03**: Infrastructure anomaly findings flow through the existing pheromone deposit, escalation, and notification pipelines; cross-signal correlation between infrastructure anomalies and behavioral detections (e.g., CPU spike + suspicious process tree) boosts escalation confidence via `distinct_sources` diversity
- **INFRA-04**: `SwarmConfig.runtime.telemetry_sources` accepts `"sentinel"` as a named bridge; the bridge exposes event-count, error-count, and lag-seconds metrics on `/healthz` and `/metrics` consistent with the existing Tetragon and JSON bridge patterns

### Providence Native (v1.45)

_Depends on: v1.42 (KittenAgent for PROVFB-02). PROVFB-02 is gated on KittenAgent availability and falls back to persisting feedback as pending entries when KittenAgent is not deployed._

#### Contract And Auth

- [x] **PROVAUTH-01**: A shared `SwarmProvidenceWebhookContract` schema defines the inbound and outbound payload formats; Swarm's outbound `swarm_providence_webhook` envelope maps to Providence's `CreateIncidentBody` (title, severity, status, source, description) with the rich context (finding, aggregate, runtime, links) in the description field; the contract includes `schema_version` for forward compatibility
- [x] **PROVAUTH-02**: Service-to-service authentication: Swarm stores a Providence API bearer token via `@secret:providence_api_token`; Providence verifies inbound Swarm webhooks via HMAC-SHA256 signature in a `X-Swarm-Signature` header using a shared secret

#### Incident Lifecycle

- [x] **PROVBI-01**: A `ProvidenceIncidentAdapter` manages outbound lifecycle: Swarm escalation to Alert or Incident creates a Providence incident via `POST /incidents` with the mapped payload; severity changes issue `PUT /incidents/:id`; mode return to Normal resolves with `status: 'resolved'`; the adapter stores Providence incident IDs in the substrate linked to the triggering `EscalationRecord` via a generic `ExternalReference { system: String, id: String, url: Option<String> }` on `IncidentRecord`
- [x] **PROVBI-02**: Failed Providence API calls are retried with exponential backoff and dead-lettered after 3 attempts, consistent with existing `NotificationRouter` resilience patterns; idempotent create-by-key (using `strategy_id:threat_class:finding_id` as the incident key) prevents duplicate incidents on retry
- [x] **PROVBI-03**: `/healthz` and `/readyz` include Providence integration health when the adapter is configured: reachable, authenticated, and accepting writes

#### Analyst Feedback Loop

- [x] **PROVFB-01**: Swarm exposes `POST /v1/providence/feedback` accepting `{ action: "confirm" | "dismiss" | "investigate", incident_id: string, finding_id?: string, analyst_id: string, reason?: string }` with HMAC-SHA256 signature verification; `confirm` boosts deposit confidence for matching findings, `dismiss` suppresses matching deposits and tags as false-positive, `investigate` enqueues a StalkerAgent investigation
- [x] **PROVFB-02**: False-positive dismissals from PROVFB-01 are forwarded to `KittenAgent` as negative fitness signals via `SwarmAction::FeedbackSignal`, penalizing strategy configurations that produce findings matching dismissed patterns; when KittenAgent is not deployed, feedback is persisted as pending entries for later consumption
- [x] **PROVFB-03**: Feedback actions are persisted as signed audit entries in the spine audit trail linking the Providence analyst identity (stored as opaque string), action type, affected finding/incident IDs, the full feedback payload, and the resulting substrate operation outcome

#### Dashboard Integration

- [x] **PROVDASH-01**: A dedicated `/v1/demo/widget` endpoint serves a minimal embeddable dashboard (no full chrome) with `Content-Security-Policy: frame-ancestors` and `X-Frame-Options` headers configured via `operator.allowed_embed_origins` in `SwarmConfig` (default: same-origin only); the widget HTML is self-contained and does not require Swarm auth to render
- [x] **PROVDASH-02**: The embedded widget displays real-time agent activity, pheromone concentrations, and escalation timeline scoped to a specific context via URL parameters (e.g., `?strategy_id=...&threat_class=...` or `?hunt_id=...`); it connects to `/v1/events/stream` with the appropriate type filter
- [x] **PROVDASH-03**: Swarm generates short-lived read-only context tokens (configurable TTL, default 15 minutes) scoped to a specific `hunt_id` or incident context; tokens are Ed25519-signed using the operator signing key with expiry, scope, and anti-replay nonce; they are included in Providence webhook drilldown links as URL query parameters and validated as an alternative to bearer auth for read-only access

### Distributed Governance (v1.46)

_Note: PROJECT.md constraints previously stated "no BFT, gossip, or distributed red-swarm work." This milestone marks the architectural evolution from single-node to distributed operation. The constraint is updated with a key decision entry: single-node operations are proven through v1.43, evolution and memory are established, agent identity is durable (v1.44), and the project is ready for multi-instance governance._

#### Consensus Protocol

- **CONSENSUS-01**: `swarm-consensus` implements a Tendermint-style propose-prevote-precommit BFT protocol tolerating f Byzantine agents in a 2f+1 committee, with round-based progress and view-change on proposer timeout; inter-instance communication uses NATS JetStream subjects (reusing the existing pheromone substrate connection)
- **CONSENSUS-02**: Committee rotation uses a deterministic seed derived from the previous round's commit hash combined with agent identity hashes, providing verifiable fair proposer selection without requiring a separate VRF cryptographic dependency
- **CONSENSUS-03**: Consensus protocol messages are signed with persistent Ed25519 agent keys (IDENTITY-01) and verified before processing; Byzantine message detection (equivocation via conflicting signed messages, invalid signatures) triggers automatic agent exclusion from the current round with a signed exclusion receipt

#### Multi-Instance Governance

- **GOVERN-01**: `TomAgent` consensus extends from single-instance synchronous veto to multi-instance BFT agreement; response actions requiring governance approval are proposed to the consensus committee and executed only after 2f+1 prevote-precommit confirmation; single-instance mode continues to work via degenerate 1-of-1 consensus
- **GOVERN-02**: Multi-instance pheromone deposits are validated against the `AgentIdentityRegistry` (from IDENTITY-02); deposits from agents not in the registry are rejected by the substrate with a structured error; the registry is synchronized across instances via consensus
- **GOVERN-03**: Governance decisions (approve, veto, timeout) are persisted as signed consensus receipts in the spine audit trail with round number, committee composition, and vote tally

#### Partition Authority

- **PARTITION-01**: A partition detector identifies network splits using heartbeat timeout and quorum loss signals; partition state transitions (healthy → degraded → partitioned → healing) are logged as structured events and emitted on the runtime event broadcaster
- **PARTITION-02**: Contingency leases pre-authorize bounded action sets during healthy periods for redemption during partition; leases specify action type, blast radius cap (max affected hosts), and maximum duration; leases are issued by consensus and signed by the issuing committee
- **PARTITION-03**: During partition, detection and reporting continue (fail-open for observability) while destructive response actions are denied unless covered by a valid contingency lease (fail-closed for safety); expired contingency leases are never redeemed
- **PARTITION-04**: Partition reconciliation on healing merges divergent decisions from sub-swarms; authorized actions (covered by valid leases) are preserved; unauthorized actions (no lease or expired lease) are flagged for operator review with a reconciliation report

#### Resilience Testing

- **CHAOS-01**: A chaos testing harness injects Byzantine agent behavior (equivocation, delayed responses, invalid signatures) into the consensus protocol and verifies safety properties hold (no unauthorized response execution, no equivocation acceptance)
- **CHAOS-02**: Network partition simulation tests verify that detection continues, unauthorized responses are blocked, and contingency leases are correctly redeemed and expired
- **CHAOS-03**: Cascading failure scenarios (agent crash → health degradation → mode transition → recovery) are tested end-to-end with deterministic replay against multi-instance configurations

### Calico And Detection Breadth (v1.47)

#### Calico Deception Agent

- **CALICO-01**: `CalicoAgent` implements `SwarmAgent` with `AgentRole::Calico` and manages deception infrastructure: deploying honeypot services that match legitimate host profiles and canary tokens on monitored file paths; the agent maintains a `DeceptionPlaybook` loaded from repo-owned YAML defining decoy types, placement strategies, and monitoring rules
- **CALICO-02**: Canary token interactions (file access, network connection to honeypot port, credential use) generate high-fidelity `DetectionFinding` entries with `ThreatClass::InitialAccess` or `ThreatClass::LateralMovement` and confidence ≥ 0.95; any interaction with a decoy is inherently suspicious
- **CALICO-03**: Decoy lifecycle (deploy → monitor → rotate → cleanup) is managed by CalicoAgent's tick loop; deployed decoys are registered in SphinxAgent's knowledge graph for cross-agent correlation; decoy metadata (type, placement, creation time) is persisted for forensic attribution
- **CALICO-04**: Deception interactions feed into `KittenAgent` evolution as high-weight positive signals; an attacker engaging a decoy validates the detection strategy that placed it, boosting that strategy's fitness in subsequent generations

#### Fileless Execution And Behavioral Baselines

- **FILELESS-01**: A `FilelessExecutionDetector` implements `DetectionStrategy` and identifies indicators of reflective DLL injection, encoded PowerShell execution with multi-stage deobfuscation hints, and raw syscall gadget patterns from a new `TelemetryPayload::ProcessMemoryAccess` variant and existing `ProcessStart` events
- **FILELESS-02**: A `BehavioralAnomalyDetector` implements `DetectionStrategy` and maintains per-host process ancestry baselines; it flags deviations such as unusual parent-child pairs, first-seen binaries, or atypical tool usage for a user role as medium-confidence findings
- **FILELESS-03**: `TelemetryPayload` includes a `ProcessMemoryAccess` variant carrying `source_process`, `target_process`, `allocation_type`, `protection_flags`, `region_size`, and optional `call_stack_hint` for memory-based detection
- **FILELESS-04**: `BehavioralAnomalyDetector` baselines persist across runtime restarts via the durable `PheromoneSubstrate` and decay with a configurable `baseline_half_life_secs`
- **FILELESS-05**: `ThreatClass::DefenseEvasion` is used for fileless execution findings; `ThreatClass::PrivilegeEscalation` is used when the detector observes memory manipulation targeting a higher-privilege process
- **FILELESS-06**: Both detectors ship with configurable profiles; integration tests cover evasion scenarios through detection to pheromone deposit

### Adversarial Robustness (v1.48)

#### Evasion Bench

- **EVASION-01**: An evasion test corpus provides at least 10 curated payloads per `ThreatClass` representing real-world evasion techniques
- **EVASION-02**: A coverage metrics module computes per-detector evasion catch rates via `/metrics` and `/api/v1/evasion/coverage`
- **EVASION-03**: KittenAgent's existing mutation loop (from KITTEN-01) proposes threshold adjustments in response to evasion corpus gaps and validates through the canary pipeline; no separate mutation module
- **EVASION-04**: An evasion catalog documents intentionally uncovered ATT&CK techniques per detector with rationale
- **EVASION-05**: Integration tests execute the full evasion corpus → gap identification → KittenAgent mutation → canary validation cycle

#### Z3 Formal Verification

- **Z3-01**: The optional Z3 SMT verification tier (behind the `z3` feature flag referenced in SAFETY-01) is implemented using the `z3` Rust crate; `FormalSafetyGate` Tier 2 compiles strategy invariants from `rulesets/safety/*.yaml` into Z3 assertions and proves universal properties (e.g., `∀ indicator ∈ known_bad_set, detector(indicator) = ALERT`) that the deterministic Tier 1 checker cannot verify by enumeration alone
- **Z3-02**: Z3 verification results include machine-readable counterexamples on failure; the solver timeout is configurable (default 30s per invariant) with fail-closed semantics (timeout = rejection); verification artifacts are signed and persisted in the spine audit trail alongside Tier 1 results

### Canonical Runtime Contract And Governance Modes (v1.49)

#### Canonical Runtime Contract

- **CONTRACT-01**: Canonical documents distinguish active runtime contracts from historical reference material through one source-of-truth matrix covering docs, config examples, and operator surfaces
- **CONTRACT-02**: The active contract describes the shipped Rust runtime across critical lane, async lane, governance, evolution, and operator capabilities using one consistent capability matrix
- **CONTRACT-03**: Agent archetype, configuration, and operator-facing docs describe the current Rust runtime surfaces and no longer depend on historical Python or deferred-governance assumptions

#### Governance Modes

- **GOVMODE-01**: One canonical governance-mode spec defines local guarded response, human-gated approval, receipt-backed quorum, maintenance-only behavior, and when each mode applies
- **GOVMODE-02**: Identity admission, rotation, human-gate severity, consensus receipts, and approval lineage are documented as one active contract with matching config and status-surface semantics
- **GOVMODE-03**: Degraded governance, contingency leases, partition handling, reconciliation, and trust recovery are specified as fail-closed runtime contracts with explicit operator visibility

#### Evolution Contract

- **EVOCONTRACT-01**: Queue, canary, promotion, proof, and review artifacts are restated as one canonical bounded evolution contract aligned with the current runtime status and approval surfaces

### Async Enrichment And Correlation Depth (v1.50)

#### Multi-Graph Correlation

- **ASYNC-01**: Weaver correlation expands beyond the current graph foundation into temporal, causal, entity, and semantic traversal with repo-owned scoring and edge semantics
- **ASYNC-02**: Correlated incidents include explainable cross-hunt evidence chains, confidence scores, and graph-backed attribution suitable for operator review

#### Investigation Scheduling

- **SCHED-01**: The async investigation lane prioritizes work by criticality, freshness, learned value, and bounded queue budget instead of FIFO-only scheduling
- **SCHED-02**: Ambiguous investigations can run a speculate-plus-vote confidence workflow that records competing interpretations and final confidence lineage before escalation

#### Behavioral Depth

- **BEHAV-01**: Behavioral baselines extend beyond per-host scope into identity and peer-group scope using repo-owned thresholds and operator-visible evidence
- **BEHAV-02**: Host, identity, and peer-group baselines persist, decay, and recover independently with scope-specific durability and reload semantics

#### Async Product Surface

- **ASYNC-03**: Operator surfaces expose async queue depth, backlog pressure, confidence-vote state, and correlation outcomes as first-class runtime status instead of implicit logs only
- **ASYNC-04**: Integration proof covers the bounded detect → investigate → correlate → operator-review flow across the async lane without widening the hot path

### Assurance-Gated Evolution And Counterexample Loop (v1.51)

#### Assurance Policy

- **ASSURE-01**: Evasion coverage floors become explicit gate inputs for strategy queue, canary, and promotion decisions on a per-strategy or per-detector basis
- **ASSURE-02**: Solver proof outcomes, timeout state, and counterexample presence become explicit gate inputs alongside replay and canary evidence
- **ASSURE-03**: Queue, canary, and promotion paths fail closed when assurance policy is unsatisfied unless a signed bounded operator waiver exists

#### Counterexample Loop

- **COUNTER-01**: Solver counterexamples and evasion misses are harvested into replayable regression cases with durable lineage back to the triggering candidate and proof artifacts
- **COUNTER-02**: Harvested replay and counterexample cases feed mutation ranking, proposal fitness, and operator review summaries

#### Waivers And Lineage

- **ASSURE-04**: Signed operator waivers are time-bounded, reasoned, and auditable, and they attach directly to the assurance decision they override
- **ASSURE-05**: Evolution status, proof exports, and review surfaces expose assurance lineage, waived gaps, and gating reasons without inventing a parallel status channel

### Providence Reconciliation And Response Rehearsal (v1.52)

#### Providence Reconciliation

- **PROVREC-01**: Authenticated Providence callbacks reconcile create, update, and resolve state against durable correlated incidents instead of leaving Swarm outbound-only
- **PROVREC-02**: Workflow drift or lifecycle mismatch between Providence and Swarm is persisted and surfaced for operator review with explicit reconciliation status
- **PROVREC-03**: Analyst dispositions and notes persist as signed audit evidence and feed bounded memory or evolution inputs through Sphinx and Kitten

#### Response Rehearsal

- **REHEARSE-01**: Response rehearsal reuses the existing policy, approval, and adapter path in non-destructive mode so live actions can be practiced without side effects
- **REHEARSE-02**: Rehearsal computes bounded blast-radius and rollback evidence before live action approval using the same scoped-action model as the runtime
- **REHEARSE-03**: Rehearsal artifacts persist as signed proof packages linked to incidents, actions, and review sessions
- **REHEARSE-04**: Providence and local review surfaces can display rehearsal and reconciliation context without bypassing the bounded action lane

### Production Packaging, Recovery, And Operator Access (v1.53)

#### Production Packaging And Recovery

- **PROD-01**: Repo-owned deployment profiles provide secure-by-default packaging for the runtime and its stateful dependencies, including clear state-root boundaries
- **PROD-02**: Backup, restore, upgrade, and rollback drills cover pheromone state, replay bundles, incident stores, agent keys, and repo-owned config roots
- **PROD-03**: A supported topology and durability matrix is defined and verified for local-journal and JetStream-backed deployments
- **PROD-04**: SLOs, capacity envelopes, and alert thresholds are published from measured end-to-end load tests rather than hot-path microbenchmarks alone

#### Operator Access

- **ACCESS-01**: Operator access supports multiple identities with scoped permissions over read, rehearse, approve, and maintenance actions
- **ACCESS-02**: Operator actions and approvals are individually attributable and auditable end to end
- **ACCESS-03**: A reference architecture and adoption pack document supported deployment, identity, secret, and integration patterns for operators

### Panic Eradication And Error Contracts (v1.54)

#### Error Propagation

- **PANIC-01**: All `unwrap()` and `expect()` calls in non-test runtime code are replaced with explicit error propagation or documented `// SAFETY:` justifications
- **PANIC-02**: Each crate boundary defines a typed error enum with `From` conversions; cross-crate error propagation never uses string-only errors for programmatic decisions
- **PANIC-03**: The ingest, service, and agent tick paths propagate errors through `Result` returns instead of panicking on unexpected input shapes
- **PANIC-04**: A CI lint or test enforces that new `unwrap()`/`expect()` calls in non-test code require explicit justification comments

### JetStream Integration Tests And Load Baselines (v1.55)

#### JetStream Testing

- **JTEST-01**: A containerized NATS JetStream test harness can bootstrap a real backend in CI and local development, export stable connection details, and run at least one repo-owned JetStream-backed verification path without manual infrastructure setup
- **JTEST-02**: Substrate tests covering deposit, query, escalation, threat-class config, threat-intel, and GC run against both in-memory and JetStream backends with identical assertions
- **JTEST-03**: `criterion` benchmarks measure hot-path latency (ingest → detect → deposit → escalate) at p50, p95, and p99 under sustained synthetic load

#### Load Testing

- **JTEST-04**: A sustained-throughput load test establishes the maximum events-per-second the runtime can process before readiness shedding activates, with documented hardware profile

### Binary Attestation And Configuration Integrity (v1.56)

#### Startup Attestation

- [x] **ATTEST-01**: The runtime verifies its own binary hash and repo-owned ruleset signatures at startup; live-response mode is refused if attestation fails
- [x] **ATTEST-02**: Configuration files loaded at startup are verified against Ed25519 signatures from the config-signing key; unsigned or tampered configs fail closed with structured error

#### Runtime Self-Monitoring

- [x] **ATTEST-03**: The runtime detects debugger attachment (TracerPid on Linux) and unexpected library loads at configurable intervals; detection emits structured alerts and optionally fails closed for live-response mode

#### Supply Chain

- [x] **ATTEST-04**: `deny.toml` denies advisory violations and wildcard licenses; `cargo-audit` runs as a hard CI gate; SBOM artifacts are generated per release

### Autonomous Parameter Evolution With Measured Fitness (v1.57)

#### Algorithmic Mutation

- [x] **AUTOEVO-01**: KittenAgent generates parameter variant candidates algorithmically (bounded random perturbation, crossover of top-performing genomes) without requiring operator-authored experiment specs
- [x] **AUTOEVO-02**: Generated candidates are evaluated against the repo-owned evasion corpus with measured catch rate, false-positive rate, and latency as fitness dimensions

#### Measured Evolution

- [x] **AUTOEVO-03**: The evolution loop runs for N configurable generations and reports generation-over-generation measured fitness deltas with reproducible benchmark context
- [x] **AUTOEVO-04**: At least one detector strategy shows measurable autonomous improvement (target: 5%+ evasion catch-rate gain over 10 generations) validated against the tracked evasion corpus

### Multi-Event Sequence Detection (v1.58)

#### Temporal Matching

- **SEQDET-01**: A `SequenceDetector` matches ordered temporal sequences of events within a configurable sliding window, where each step is a predicate over `TelemetryEvent` fields
- **SEQDET-02**: Sequence rules are defined in repo-owned YAML with ATT&CK technique chain metadata (e.g., T1003→T1021→T1053)

#### Kill Chain Coverage

- **SEQDET-03**: At least three ATT&CK technique chains are detected that no single-event detector can catch, validated by new scenario suite entries with chain-only ground truth
- **SEQDET-04**: Sequence detection integrates with the existing pheromone deposit and escalation pipeline; partial chain matches deposit lower-confidence intermediate pheromones

### Guided First-Run And Alert Quality Scoring (v1.59)

#### Onboarding

- **ONBOARD-01**: `swarmctl init` includes a readiness diagnostic that validates telemetry source connectivity, detector activation, and substrate health before declaring operational
- **ONBOARD-02**: A guided first-run mode injects synthetic telemetry and walks the operator through seeing their first detection, approval, and proof export within 15 minutes of install

#### Alert Quality

- **ONBOARD-03**: Per-detector and per-host false-positive rates are tracked from analyst feedback and surfaced through `swarmctl` and the operator API
- **ONBOARD-04**: The system generates concrete tuning recommendations (e.g., "add host X to exclusion list", "raise threshold for detector Y") based on measured FP patterns

### Agent Lifecycle Isolation And Graceful Degradation (v1.60)

#### Agent Isolation

- **ISOLATE-01**: Each agent type runs within its own panic boundary (`catch_unwind` or equivalent) so that a panic in one agent does not crash the runtime process
- **ISOLATE-02**: Agent health monitoring detects persistent failures and restarts individual agents without affecting the rest of the swarm

#### Degradation Modes

- **ISOLATE-03**: The runtime defines explicit degradation levels (full, detect-only, read-only, emergency-drain) with documented behavior per level and automated transitions based on health signals
- **ISOLATE-04**: Degradation mode transitions are tested end-to-end: NATS unreachable → detect-only, disk full → read-only, heap pressure → emergency-drain

### Response Action Library And Playbook Builder (v1.61)

#### Action Expansion

- **RESPONSE-01**: The response adapter library expands to at least 15 concrete action types including network isolation, DNS sinkhole, user session termination, EDR-initiated scan, and firewall rule injection
- **RESPONSE-02**: Each response action defines a typed blast-radius model (affected hosts, services, users) and a rollback procedure

#### Playbook Composition

- **RESPONSE-03**: Operators define multi-step response playbooks in YAML with conditional branching (if severity >= high AND threat_class == LateralMovement, then: step1, step2...)
- **RESPONSE-04**: Playbooks support dry-run preview that shows projected blast radius and approval requirements before any live execution

### Statistical Anomaly Scoring And Behavioral Breadth (v1.62)

#### Statistical Scoring

- **ANOMALY-01**: `BehavioralAnomalyDetector` replaces its fixed confidence formula with learned per-entity distributions using online algorithms (Welford's or equivalent)
- **ANOMALY-02**: Anomaly scores are derived from statistical deviation measures (z-score, percentile rank, or information-theoretic surprise) instead of fixed threshold arithmetic

#### Behavioral Breadth

- **ANOMALY-03**: Behavioral baselines extend to network, DNS, authentication, file access, and memory event types with per-type learned distributions
- **ANOMALY-04**: False-positive rate on behavioral findings decreases by at least 30% while maintaining catch rate, measured by replaying labeled telemetry with ground-truth normal/anomalous labels

### Evolution Crate Decomposition And Schema Migration (v1.63)

#### Crate Decomposition

- **DECOMP-01**: `crates/swarm-evolution/src/evolution.rs` is decomposed into focused sub-modules with explicit `pub(crate)` API boundaries and no extracted file exceeding 2000 lines
- **DECOMP-02**: `crates/swarm-evolution/src/mutation.rs` is decomposed into focused sub-modules with documented module responsibilities and no extracted file exceeding 2000 lines

#### Schema Migration

- **DECOMP-03**: Pheromone deposit wire format includes an explicit schema version; the substrate accepts deposits from the current and previous version with automatic migration
- **DECOMP-04**: API response envelopes include schema versions; breaking changes are gated behind version negotiation rather than silent field addition

### Cross-Crate Path Hack Elimination (v1.64)

#### Crate Boundary Cleanup

- **PATHFIX-01**: All `#[path = "../../swarm-evolution/..."]` directives in `swarm-runtime/src/lib.rs` are replaced with proper crate-level dependency edges or re-exports
- **PATHFIX-02**: The former path-hacked evolution modules have one real crate-owned source location instead of being compiled into `swarm-runtime` from `swarm-evolution/src`
- **PATHFIX-03**: Runtime and compatibility imports resolve through normal crate/module paths after the path hacks are removed, restoring IDE go-to-definition and rename-symbol safety
- **PATHFIX-04**: The affected crates build, their library tests pass, and library/bin clippy is clean after path hack removal with no regression in public API surface

### Config Crate Extraction And service.rs Decomposition (v1.65)

#### Config Extraction

- **CFGEXT-01**: `swarm-core/src/config.rs` is extracted into a dedicated `swarm-config` crate or decomposed into focused sub-modules with no file exceeding 2000 lines
- **CFGEXT-02**: Config struct changes no longer trigger recompilation of the entire workspace; only dependent crates rebuild

#### Service Decomposition

- **SVCMOD-01**: `swarm-runtime/src/service.rs` is decomposed into focused sub-modules for lifecycle management, agent orchestration, and request handling with no file exceeding 2000 lines
- **SVCMOD-02**: The `RuntimeService` god object is refactored to reduce `Arc` cloning overhead on the request path

### Learned-State Integrity Signing (v1.66)

#### State Signing

- **STATESIG-01**: Behavioral baseline snapshots are signed with the agent's Ed25519 key before persistence and verified on restore; tampered snapshots fail closed with structured error
- **STATESIG-02**: Sphinx knowledge-graph state files are signed before persistence and verified on restore
- **STATESIG-03**: Evolution population and episode artifacts are signed before persistence and verified on restore
- **STATESIG-04**: All signed state artifacts include a monotonic sequence number to prevent replay of older state

### Secret Zeroization And API Token Lifecycle (v1.67)

#### Memory Hygiene

- **ZERO-01**: Plaintext secrets resolved from `@secret:` paths are zeroized from heap memory after use via the `zeroize` crate
- **ZERO-02**: Release builds use `panic = "abort"` to prevent stack-unwinding information disclosure

#### Token Lifecycle

- **TOKEN-01**: Operator API bearer tokens support configurable expiry and rotation without restart
- **TOKEN-02**: HTTP API surfaces enforce per-source request rate limiting with configurable burst and sustained thresholds

### Multi-Detector Evolution Genomes (v1.68)

#### Genome Breadth

- **GENOME-01**: The evolution mutation/fitness pipeline supports `BehavioralAnomalyDetector`, `FilelessExecutionDetector`, and `DnsExfiltrationDetector` alongside `SuspiciousProcessTreeDetector`
- **GENOME-02**: Each supported detector type has a typed genome representation with perturbation and crossover operators
- **GENOME-03**: The evolution benchmark measures generation-over-generation fitness for all supported detector types
- **GENOME-04**: At least one non-process-tree detector shows measurable autonomous fitness improvement above the current baseline

### Command-Line Deobfuscation Pipeline (v1.69)

#### Normalization

- **DEOBF-01**: A pre-evaluation normalization pass handles caret insertion, environment variable expansion, and Unicode homoglyph substitution before detectors evaluate command-line arguments
- **DEOBF-02**: Base64 and common encoded argument patterns are decoded to plaintext before detector evaluation
- **DEOBF-03**: The evasion corpus catch-rate for `defense_evasion` and `execution` scenarios improves by at least 15% from normalization alone
- **DEOBF-04**: Normalization introduces zero false-positive regression on the benign baseline corpus

### Telemetry Source Breadth (v1.70)

#### Bridge Adapters

- **TELBR-01**: A `WindowsEventLogBridge` implements `TelemetryBridge` for Windows Event Log sources mapped to the shared telemetry schema
- **TELBR-02**: A `SysmonBridge` implements `TelemetryBridge` for Sysmon event sources with process, network, and file telemetry mapping
- **TELBR-03**: An `AuditdBridge` implements `TelemetryBridge` for Linux auditd sources with syscall and authentication telemetry mapping
- **TELBR-04**: All new bridges expose health, event-count, and lag metrics consistent with existing bridge patterns

### CI Hardening And Versioned Releases (v1.71)

#### CI Pipeline

- **CIHARD-01**: CI runs fmt, clippy, build, and test as parallel jobs with proper dependency edges and artifact sharing
- **CIHARD-02**: JetStream integration tests run in CI against a containerized NATS instance
- **CIHARD-03**: The Criterion hot-path benchmark runs in CI and fails the build if p99 latency regresses beyond a configurable threshold

#### Release Pipeline

- **RELEASE-01**: Tagged releases build and publish multi-arch container images with SBOM and signature attestation
- **RELEASE-02**: A CHANGELOG is generated from conventional commit history on each release

### OpenAPI Spec And SOAR Bidirectional Sync (v1.72)

#### API Spec

- **APISPEC-01**: A machine-readable OpenAPI 3.1 spec is published for the `/v2/api/` platform surface
- **APISPEC-02**: A generated Python client is shipped from the OpenAPI spec and tested against the live platform API

#### SOAR Sync

- **SOARSYNC-01**: Inbound analyst verdicts from Splunk SOAR, Sentinel SOAR, or Chronicle SOAR flow into Swarm's false-positive tracking and evolution fitness
- **SOARSYNC-02**: SOAR verdict sync preserves durable audit lineage linking the external analyst identity, source system, and affected finding/incident IDs

### Stigmergic Feedback Loops And Baseline Resistance (v1.73)

#### Pheromone Recruitment

- **STIGM-01**: High-concentration pheromone deposits cause agents to lower detection thresholds for matching threat classes (positive-feedback recruitment)
- **STIGM-02**: Escalation resolution causes agents to restore baseline detection thresholds (inhibitory signaling)
- **STIGM-03**: Time from first-stage detection to SwarmMode::Alert on kill-chain replay scenarios decreases by at least 20% with recruitment enabled

#### Baseline Resistance

- **BASERES-01**: Behavioral baseline snapshots are signed with HMAC using the agent's Ed25519 key (building on STATESIG-01)
- **BASERES-02**: The minimum number of observations needed to shift baselines by 1, 2, and 3 sigma is empirically quantified and published
- **BASERES-03**: Baseline snapshots older than a configurable staleness threshold trigger graduated confidence reduction instead of being silently trusted

## Out of Scope

| Feature | Reason |
|---------|--------|
| OpenTelemetry distributed tracing | OTLP export is optional behind feature flag in v1.41 HARD-04; full OTEL ecosystem integration is future |
| Grafana dashboard or alerting rules | Metrics export is the deliverable; visualization is downstream |
| APM integration (Sentry, Datadog) | Structured logs feed into any APM; vendor-specific integration is future |
| Adapter-specific retry policies per action type | Uniform retry policy first; per-action tuning is future |
| Full Providence workflow ownership beyond bounded incident reconciliation | v1.52 plans authenticated callbacks and state reconciliation, but deeper Providence-owned workflow orchestration remains future |
| Full Hellcat Python integration | v1.43 uses a Rust-native adversarial scenario generator; deep Hellcat integration via PyO3 or subprocess is a future milestone |

### Structural Integrity (v1.74)

#### Test Correctness

- [ ] **TESTFIX-01**: The 2 failing `swarm-pheromone` local journal recovery tests (`local_journal_recovers_deposits_after_reopen` and `local_journal_recovers_escalations_after_reopen` in `substrate.rs`) pass with correct deposit and escalation counts after journal reopen
- [ ] **TESTFIX-02**: The 7 ignored `swarm-pheromone` tests are either re-enabled with passing assertions or documented with explicit skip reasons

#### Dead Code Removal

- [ ] **DEADCODE-01**: The `swarm-evolution` crate (8-line facade re-exporting `swarm-runtime` modules) is deleted from the workspace, all references removed from `Cargo.toml` workspace members, and any downstream imports redirected to `swarm-runtime` directly

#### File Decomposition

- [ ] **DECOMP-01**: `swarm-runtime/src/kitten_agent.rs` (4,479 lines) is decomposed into a focused module tree (`kitten_agent/mod.rs` plus submodules) with each submodule under 1,500 lines, preserving the existing public API
- [ ] **DECOMP-02**: `swarm-runtime/src/drafting.rs` (3,763 lines) is decomposed into a focused module tree with each submodule under 1,500 lines, preserving the existing public API
- [ ] **DECOMP-03**: `swarm-runtime/src/ingest/tests.rs` (5,751 lines) is decomposed into focused test submodules grouped by tested subsystem, with the 7 `unsafe` env-var mutation blocks replaced by config injection or test-scoped configuration patterns

#### Crate Extraction

- [ ] **EXTRACT-01**: Agent implementations (`kitten_agent`, `sphinx_agent`, `tom_agent`, `calico_agent`, `pounce_agent`, `stalker_agent`, `weaver_agent`, `whisker_agent`) are extracted into a dedicated `swarm-agents` crate with `swarm-runtime` depending on `swarm-agents` instead of owning agent source directly
- [ ] **EXTRACT-02**: `swarm-agents` compiles independently with `cargo build -p swarm-agents` and carries its own focused unit test suite, while `swarm-runtime` integration tests continue to exercise the full agent pipeline
- [ ] **EXTRACT-03**: The workspace builds cleanly (`cargo build --workspace`), all existing tests pass (`cargo test --workspace`), and clippy remains warning-free (`cargo clippy --workspace -- -D warnings`) after extraction

### Operator Packaging (v1.75)

#### Default Configuration

- [ ] **DEFAULTS-01**: A curated `rulesets/default.yaml` ships with sensible detection profiles for a `detect_only` deployment covering all 12 shipped detector strategies, with documented inline comments explaining each threshold and its rationale
- [ ] **DEFAULTS-02**: `swarmctl init` generates a working config from `rulesets/default.yaml` that passes `swarmctl validate` without modification and boots the runtime to a ready state on the first run

#### Deployment Documentation

- [ ] **DEPLOY-01**: A repo-owned getting-started guide (`docs/QUICKSTART.md`) walks an operator from zero to first detection in under 15 minutes using Docker Compose, including telemetry injection, detection observation, and finding inspection via `swarmctl`
- [ ] **DEPLOY-02**: Deployment documentation covers Docker single-container, Docker Compose with NATS, Helm chart, and bare-metal binary paths with prerequisites, config, and verification steps
- [ ] **DEPLOY-03**: A `swarmctl quickstart` command orchestrates first-run: validates config, starts the runtime, injects a built-in synthetic attack scenario, waits for detection, and reports the finding with an elapsed-time measurement

#### Adversary Emulation Validation

- [ ] **EMULATION-01**: The repo includes a mapped Atomic Red Team scenario corpus (minimum 20 techniques across execution, persistence, credential access, lateral movement, and defense evasion tactics) adapted as replay scenarios
- [ ] **EMULATION-02**: `cargo test` includes an adversary emulation integration test suite that replays the Atomic Red Team corpus through the full detection pipeline and asserts coverage with a documented technique-to-detector mapping
- [ ] **EMULATION-03**: A coverage report summarizes per-MITRE-technique detection status (detected, partial, not covered) and overall technique coverage percentage, with the target of 60%+ coverage across the mapped corpus

#### Operator Experience

- [ ] **OPEXP-01**: `swarmctl status` outputs a concise operator-readable summary including runtime mode, active detectors, bridge health, recent findings count, and escalation state in a single screen of output
- [ ] **OPEXP-02**: Error messages from config validation, runtime startup failures, and bridge connection issues include actionable remediation guidance (not just error codes)

### External Signal Ingestion (v1.76)

#### Threat Intelligence Feeds

- [ ] **THREATINTEL-01**: A `swarm-ingest-taxii` crate implements a STIX/TAXII 2.1 collection consumer that polls configured feed URLs on a bounded interval and maps STIX indicator objects (IPv4, domain, file hash, URL) into `ThreatIntelEntry` records in the existing pheromone substrate with confidence scores, TTL from STIX `valid_until`, and source attribution
- [ ] **THREATINTEL-02**: The threat-intel substrate consumer deduplicates indicators by type+value, updates confidence and TTL on re-observation, and exposes feed health (last poll time, indicators ingested, errors) on the existing `/healthz` surface
- [ ] **THREATINTEL-03**: Detection findings that match threat-intel indicators carry enriched evidence including the IOC value, feed source, STIX indicator ID, and confidence boost applied, visible in `swarmctl` finding inspection and signed finding envelopes

#### Cloud Audit Log Detection

- [ ] **CLOUDDET-01**: A `CloudTrailDetector` implements `DetectionStrategy` and detects IAM abuse patterns (CreateAccessKey from unusual principal, ConsoleLogin without MFA from new geography, AssumeRole to privilege-escalation-capable roles), resource hijacking (RunInstances with crypto-mining AMI patterns, large instance types from unusual principals), and credential compromise (GetSecretValue/GetParameter from unusual callers) from `TelemetryPayload::CloudTrailEvent` events
- [ ] **CLOUDDET-02**: A `KubernetesAuditDetector` implements `DetectionStrategy` and detects privilege escalation (create/update ClusterRoleBinding, exec into privileged pods, hostPath volume mounts), RBAC abuse (impersonation, wildcard permissions), and container escape indicators (privileged container creation, hostPID/hostNetwork) from `TelemetryPayload::KubernetesAuditEvent` events
- [ ] **CLOUDDET-03**: Both cloud detectors map findings to existing `ThreatClass` variants and MITRE ATT&CK cloud technique IDs, produce signed pheromone deposits through the standard pipeline, and carry cloud-specific evidence (AWS account ID, K8s namespace, principal ARN) in finding payloads

#### Telemetry Bridge Extensions

- [ ] **CLOUDBR-01**: `swarm-ingest-json` extends with a `cloudtrail` bridge variant that parses AWS CloudTrail JSON records (from S3, SQS, or local file) into `TelemetryPayload::CloudTrailEvent` with field mapping for `eventName`, `userIdentity`, `sourceIPAddress`, `requestParameters`, and `responseElements`
- [ ] **CLOUDBR-02**: `swarm-ingest-json` extends with a `kubernetes_audit` bridge variant that parses Kubernetes audit log JSON (webhook backend format) into `TelemetryPayload::KubernetesAuditEvent` with field mapping for `verb`, `user`, `objectRef`, `responseStatus`, and `annotations`
- [ ] **CLOUDBR-03**: Both cloud bridges register in `SwarmConfig.runtime.telemetry_sources`, expose health metrics on the existing bridge surface, and are validated by integration tests proving end-to-end detection through the cloud detector pipeline

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OBS-01 | Phase 90 | Satisfied |
| OBS-02 | Phase 90 | Satisfied |
| OBS-03 | Phase 91 | Satisfied |
| OBS-04 | Phase 91 | Satisfied |
| OBS-05 | Phase 91 | Satisfied |
| OBS-06 | Phase 91 | Satisfied |
| AGENT-01 | Phase 92 | Satisfied |
| AGENT-02 | Phase 92 | Satisfied |
| AGENT-03 | Phase 93 | Satisfied |
| AGENT-04 | Phase 93 | Satisfied |
| AGENT-05 | Phase 93 | Satisfied |
| MULTI-01 | Phase 94 | Satisfied |
| MULTI-02 | Phase 94 | Satisfied |
| MULTI-03 | Phase 94 | Satisfied |
| MULTI-04 | Phase 95 | Satisfied |
| MULTI-05 | Phase 95 | Satisfied |
| MULTI-06 | Phase 94 | Satisfied |
| MULTI-07 | Phase 95 | Satisfied |
| BRIDGE-01 | Phase 96 | Satisfied |
| BRIDGE-02 | Phase 96 | Satisfied |
| BRIDGE-03 | Phase 97 | Satisfied |
| BRIDGE-04 | Phase 97 | Satisfied |
| BRIDGE-05 | Phase 98 | Satisfied |
| BRIDGE-06 | Phase 99 | Satisfied |
| SUBSTRATE-01 | Phase 100 | Satisfied |
| SUBSTRATE-02 | Phase 100 | Satisfied |
| SUBSTRATE-03 | Phase 101 | Satisfied |
| SUBSTRATE-04 | Phase 102 | Satisfied |
| SUBSTRATE-05 | Phase 103 | Satisfied |
| SUBSTRATE-06 | Phase 103 | Satisfied |
| K8S-01 | Phase 104 | Satisfied |
| K8S-02 | Phase 104 | Satisfied |
| K8S-03 | Phase 105 | Satisfied |
| K8S-04 | Phase 105 | Satisfied |
| K8S-05 | Phase 106 | Satisfied |
| K8S-06 | Phase 107 | Satisfied |
| SIEM-01 | Phase 108 | Satisfied |
| SIEM-02 | Phase 109 | Satisfied |
| SIEM-03 | Phase 110 | Satisfied |
| SIEM-04 | Phase 110 | Satisfied |
| SIEM-05 | Phase 111 | Satisfied |
| SIEM-06 | Phase 111 | Satisfied |
| PERSIST-01 | Phase 113 | Satisfied |
| PERSIST-02 | Phase 114 | Satisfied |
| PERSIST-03 | Phases 112, 114 | Satisfied |
| PERSIST-04 | Phases 112, 113, 114 | Satisfied |
| PERSIST-05 | Phase 115 | Satisfied |
| HARDEN-01 | Phase 116, Plan 01 | Satisfied |
| HARDEN-02 | Phase 116, Plan 02 | Satisfied |
| HARDEN-03 | Phase 116, Plan 02 | Satisfied |
| HARDEN-04 | 117-01 | Complete |
| HARDEN-05 | 117-01 | Complete |
| HARDEN-06 | 117-02 | Complete |
| HARDEN-07 | 117-02 | Complete |
| HARDEN-08 | Phase 118, Plan 01 | Complete |
| HARDEN-09 | Phase 118, Plan 02 | Complete |
| HARDEN-10 | Phase 119, Plan 01 | Complete |
| COMPOSE-01 | Phase 120 | Complete |
| COMPOSE-02 | Phase 120 | Complete |
| COMPOSE-03 | Phase 122 | Satisfied |
| COMPOSE-04 | Phase 122 | Satisfied |
| COMPOSE-05 | Phase 122 | Satisfied |
| NETWORK-01 | Phase 121 | Satisfied |
| NETWORK-02 | Phase 121 | Satisfied |
| NETWORK-03 | Phase 121 | Satisfied |
| NETWORK-04 | Phase 123 | Satisfied |
| NETWORK-05 | Phase 123 | Satisfied |
| POUNCE-01 | Phase 124 | Complete |
| POUNCE-02 | Phase 124 | Complete |
| POUNCE-03 | Phase 124 | Complete |
| POUNCE-04 | Phase 124 | Complete |
| POUNCE-05 | Phase 124 | Complete |
| POLICY-01 | Phase 124 | Complete |
| POLICY-02 | Phase 125 | Complete |
| POLICY-03 | Phase 125 | Complete |
| POLICY-04 | Phase 125 | Complete |
| DEESC-01 | Phase 124 | Complete |
| DEESC-02 | Phase 124 | Complete |
| TOM-01 | Phase 126 | Complete |
| TOM-02 | Phase 126 | Complete |
| DEMO-01 | Phase 128 | Complete |
| DEMO-02 | Phase 128 | Complete |
| DEMO-03 | Phase 129 | Complete |
| DEMO-04 | Phase 130 | Complete |
| DEMO-05 | Phase 130 | Complete |
| PROV-01 | Phase 131 | Complete |
| PROV-02 | Phase 131 | Complete |
| PROV-03 | Phase 131 | Complete |
| API-01 | Phase 132 | Complete |
| API-02 | Phase 133 | Complete |
| API-03 | Phase 133 | Complete |
| API-04 | Phase 132 | Complete |
| HELM-01a | Phase 134 | Complete |
| HELM-01b | Phase 134 | Complete |
| HELM-02 | Phase 134 | Complete |
| CLI-01 | Phase 134 | Complete |
| CLI-02 | Phase 134 | Complete |
| HARD-01 | Phase 135 | Complete |
| HARD-02 | Phase 136 | Complete |
| HARD-03a | Phase 135 | Complete |
| HARD-03b | Phase 135 | Complete |
| HARD-04 | Phase 136 | Complete |
| KITTEN-01 | Phase 137 | Complete |
| KITTEN-02 | Phase 138 | Complete |
| KITTEN-03 | Phase 137 | Complete |
| KITTEN-04 | Phase 139 | Complete |
| KITTEN-05 | Phase 138 | Complete |
| SAFETY-01 | Phase 139 | Complete |
| SAFETY-02 | Phase 139 | Complete |
| SAFETY-03 | Phase 139 | Complete |
| EVOLVE-OBS-01 | Phase 140 | Complete |
| EVOLVE-OBS-02 | Phase 140 | Complete |
| SPHINX-01 | Phase 141 | Complete |
| SPHINX-02 | Phase 141 | Complete |
| SPHINX-03 | Phase 142 | Complete |
| SPHINX-04 | Phase 142 | Complete |
| SPHINX-05 | Phase 143 | Complete |
| HELLCAT-01 | Phase 143 | Complete |
| HELLCAT-02 | Phase 144 | Complete |
| HELLCAT-03 | Phase 144 | Complete |
| IDENTITY-01 | Phase 145 | Complete |
| IDENTITY-02 | Phase 146 | Complete |
| IDENTITY-03 | Phase 146 | Complete |
| INFRA-01 | Phase 147 | Complete |
| INFRA-02 | Phase 148 | Complete |
| INFRA-03 | Phase 148 | Complete |
| INFRA-04 | Phase 147 | Complete |
| PROVAUTH-01 | Phase 149 | Complete |
| PROVAUTH-02 | Phase 149 | Complete |
| PROVBI-01 | Phase 150 | Complete |
| PROVBI-02 | Phase 150 | Complete |
| PROVBI-03 | Phase 150 | Complete |
| PROVFB-01 | Phase 151 | Complete |
| PROVFB-02 | Phase 151 | Complete |
| PROVFB-03 | Phase 151 | Complete |
| PROVDASH-01 | Phase 152 | Complete |
| PROVDASH-02 | Phase 152 | Complete |
| PROVDASH-03 | Phase 152 | Complete |
| CONSENSUS-01 | Phase 153 | Complete |
| CONSENSUS-02 | Phase 153 | Complete |
| CONSENSUS-03 | Phase 154 | Complete |
| GOVERN-01 | Phase 154 | Complete |
| GOVERN-02 | Phase 154 | Complete |
| GOVERN-03 | Phase 154 | Complete |
| PARTITION-01 | Phase 155 | Complete |
| PARTITION-02 | Phase 155 | Complete |
| PARTITION-03 | Phase 155 | Complete |
| PARTITION-04 | Phase 155 | Complete |
| CHAOS-01 | Phase 156 | Complete |
| CHAOS-02 | Phase 156 | Complete |
| CHAOS-03 | Phase 156 | Complete |
| CALICO-01 | Phase 157 | Complete |
| CALICO-02 | Phase 157 | Complete |
| CALICO-03 | Phase 158 | Complete |
| CALICO-04 | Phase 158 | Complete |
| FILELESS-01 | Phase 159 | Complete |
| FILELESS-02 | Phase 160 | Complete |
| FILELESS-03 | Phase 159 | Complete |
| FILELESS-04 | Phase 160 | Complete |
| FILELESS-05 | Phase 159 | Complete |
| FILELESS-06 | Phase 160 | Complete |
| EVASION-01 | Phase 161 | Complete |
| EVASION-02 | Phase 161 | Complete |
| EVASION-03 | Phase 162 | Complete |
| EVASION-04 | Phase 161 | Complete |
| EVASION-05 | Phase 162 | Complete |
| Z3-01 | Phase 163 | Complete |
| Z3-02 | Phase 163 | Complete |
| CONTRACT-01 | Phase 164 | Complete |
| CONTRACT-02 | Phase 164 | Complete |
| CONTRACT-03 | Phase 165 | Complete |
| GOVMODE-01 | Phase 165 | Complete |
| GOVMODE-02 | Phase 165 | Complete |
| GOVMODE-03 | Phase 166 | Complete |
| EVOCONTRACT-01 | Phase 167 | Complete |
| ASYNC-01 | Phase 168 | Complete |
| ASYNC-02 | Phase 168 | Complete |
| SCHED-01 | Phase 169 | Complete |
| SCHED-02 | Phase 169 | Complete |
| BEHAV-01 | Phase 170 | Complete |
| BEHAV-02 | Phase 170 | Complete |
| ASYNC-03 | Phase 171 | Complete |
| ASYNC-04 | Phase 171 | Complete |
| ASSURE-01 | Phase 172 | Completed |
| ASSURE-02 | Phase 172 | Completed |
| ASSURE-03 | Phase 174 | Completed |
| COUNTER-01 | Phase 173 | Completed |
| COUNTER-02 | Phase 173 | Completed |
| ASSURE-04 | Phase 175 | Completed |
| ASSURE-05 | Phase 175 | Completed |
| PROVREC-01 | Phase 176 | Completed |
| PROVREC-02 | Phase 176 | Completed |
| PROVREC-03 | Phase 177 | Completed |
| REHEARSE-01 | Phase 178 | Completed |
| REHEARSE-02 | Phase 178 | Completed |
| REHEARSE-03 | Phase 179 | Completed |
| REHEARSE-04 | Phase 179 | Completed |
| PROD-01 | Phase 180 | Completed |
| PROD-02 | Phase 181 | Completed |
| PROD-03 | Phase 181 | Completed |
| PROD-04 | Phase 182 | Completed |
| ACCESS-01 | Phase 183 | Completed |
| ACCESS-02 | Phase 183 | Completed |
| ACCESS-03 | Phase 183 | Completed |
| PANIC-01 | Phase 184 | Completed |
| PANIC-02 | Phase 184 | Completed |
| PANIC-03 | Phases 185-186 | Completed |
| PANIC-04 | Phase 187 | Completed |
| JTEST-01 | Phase 188 | Completed |
| JTEST-02 | Phase 189 | Completed |
| JTEST-03 | Phase 190 | Completed |
| JTEST-04 | Phase 191 | Completed |
| ATTEST-01 | Phase 192 | Completed |
| ATTEST-02 | Phase 193 | Completed |
| ATTEST-03 | Phase 194 | Completed |
| ATTEST-04 | Phase 195 | Completed |
| AUTOEVO-01 | Phase 196 | Completed |
| AUTOEVO-02 | Phase 197 | Completed |
| AUTOEVO-03 | Phase 198 | Completed |
| AUTOEVO-04 | Phase 199 | Completed |
| SEQDET-01 | Phase 200 | Completed |
| SEQDET-02 | Phase 201 | Completed |
| SEQDET-03 | Phase 202 | Completed |
| SEQDET-04 | Phase 203 | Completed |
| ONBOARD-01 | Phase 204 | Completed |
| ONBOARD-02 | Phase 205 | Completed |
| ONBOARD-03 | Phase 206 | Completed |
| ONBOARD-04 | Phase 207 | Completed |
| ISOLATE-01 | Phase 208 | Completed |
| ISOLATE-02 | Phase 209 | Completed |
| ISOLATE-03 | Phase 210 | Completed |
| ISOLATE-04 | Phase 211 | Completed |
| RESPONSE-01 | Phase 212 | Completed |
| RESPONSE-02 | Phase 213 | Completed |
| RESPONSE-03 | Phase 214 | Completed |
| RESPONSE-04 | Phase 215 | Completed |
| ANOMALY-01 | Phase 216 | Completed |
| ANOMALY-02 | Phase 217 | Completed |
| ANOMALY-03 | Phase 218 | Completed |
| ANOMALY-04 | Phase 219 | Completed |
| DECOMP-01 | Phase 220 | Completed |
| DECOMP-02 | Phase 221 | Completed |
| DECOMP-03 | Phase 222 | Completed |
| DECOMP-04 | Phase 223 | Completed |
| PATHFIX-01 | Phase 224 | Complete |
| PATHFIX-02 | Phase 225 | Complete |
| PATHFIX-03 | Phase 226 | Complete |
| PATHFIX-04 | Phase 227 | Complete |
| CFGEXT-01 | Phase 228 | Complete |
| CFGEXT-02 | Phase 229 | Complete |
| SVCMOD-01 | Phase 230 | Complete |
| SVCMOD-02 | Phase 231 | Complete |
| STATESIG-01 | Phase 232 | Complete |
| STATESIG-02 | Phase 233 | Complete |
| STATESIG-03 | Phase 234 | Complete |
| STATESIG-04 | Phase 235 | Complete |
| ZERO-01 | Phase 236 | Complete |
| ZERO-02 | Phase 237 | Complete |
| TOKEN-01 | Phase 238 | Complete |
| TOKEN-02 | Phase 239 | Complete |
| GENOME-01 | Phase 240 | Complete |
| GENOME-02 | Phase 241 | Complete |
| GENOME-03 | Phase 242 | Complete |
| GENOME-04 | Phase 243 | Complete |
| DEOBF-01 | Phase 244 | Complete |
| DEOBF-02 | Phase 245 | Complete |
| DEOBF-03 | Phase 246 | Complete |
| DEOBF-04 | Phase 247 | Complete |
| TELBR-01 | Phase 248 | Complete |
| TELBR-02 | Phase 249 | Complete |
| TELBR-03 | Phase 250 | Complete |
| TELBR-04 | Phase 251 | Complete |
| CIHARD-01 | Phase 252 | Complete |
| CIHARD-02 | Phase 253 | Complete |
| CIHARD-03 | Phase 254 | Complete |
| RELEASE-01 | Phase 255 | Complete |
| RELEASE-02 | Phase 255 | Complete |
| APISPEC-01 | Phase 256 | Complete |
| APISPEC-02 | Phase 257 | Complete |
| SOARSYNC-01 | Phase 258 | Complete |
| SOARSYNC-02 | Phase 259 | Complete |
| STIGM-01 | Phase 260 | Complete |
| STIGM-02 | Phase 261 | Complete |
| STIGM-03 | Phase 262 | Complete |
| BASERES-01 | Phase 260 | Complete |
| BASERES-02 | Phase 262 | Complete |
| BASERES-03 | Phase 263 | Complete |
| TESTFIX-01 | Phase 264 | Pending |
| TESTFIX-02 | Phase 264 | Pending |
| DEADCODE-01 | Phase 264 | Pending |
| DECOMP-01 | Phase 265 | Pending |
| DECOMP-02 | Phase 266 | Pending |
| DECOMP-03 | Phase 266 | Pending |
| EXTRACT-01 | Phase 267 | Pending |
| EXTRACT-02 | Phase 267 | Pending |
| EXTRACT-03 | Phase 267 | Pending |
| DEFAULTS-01 | Phase 268 | Pending |
| DEFAULTS-02 | Phase 268 | Pending |
| OPEXP-01 | Phase 268 | Pending |
| OPEXP-02 | Phase 268 | Pending |
| DEPLOY-01 | Phase 269 | Pending |
| DEPLOY-02 | Phase 269 | Pending |
| EMULATION-01 | Phase 270 | Pending |
| EMULATION-02 | Phase 270 | Pending |
| EMULATION-03 | Phase 270 | Pending |
| DEPLOY-03 | Phase 271 | Pending |
| THREATINTEL-01 | Phase 272 | Pending |
| THREATINTEL-02 | Phase 272 | Pending |
| THREATINTEL-03 | Phase 272 | Pending |
| CLOUDBR-01 | Phase 273 | Pending |
| CLOUDBR-02 | Phase 273 | Pending |
| CLOUDBR-03 | Phase 273 | Pending |
| CLOUDDET-01 | Phase 274 | Pending |
| CLOUDDET-02 | Phase 275 | Pending |
| CLOUDDET-03 | Phase 275 | Pending |

**Coverage:**
- v1.30-v1.37.1: 56 requirements satisfied across 10 milestones
- v1.38 complete: 10 satisfied (COMPOSE-01-05 -> Phases 120,122; NETWORK-01-05 -> Phases 121,123)
- v1.39 complete: 13 satisfied (POUNCE-01-05 -> Phase 124; POLICY-01 -> Phase 124; POLICY-02-04 -> Phase 125; DEESC-01-02 -> Phase 124; TOM-01-02 -> Phase 126)
- v1.40 complete: 8 satisfied (DEMO-01-02 -> Phase 128; DEMO-03 -> Phase 129; DEMO-04-05 -> Phase 130; PROV-01-03 -> Phase 131)
- v1.41 complete: 14 satisfied across phases 132-136
- v1.42 complete: 10 satisfied across phases 137-140
- v1.43 complete: 8 satisfied across phases 141-144
- v1.44 complete: 7 satisfied (IDENTITY-01-03, INFRA-01-04)
- v1.45 complete: 11 satisfied across phases 149-152
- v1.46 complete: 13 satisfied across phases 153-156
- v1.47 complete: 10 satisfied across phases 157-160
- v1.48 complete: 7 satisfied across phases 161-163
- v1.49 complete: 7 satisfied across phases 164-167
- v1.50 complete: 8 satisfied across phases 168-171
- v1.51 complete: 7 requirements satisfied across phases 172-175
- v1.52 complete: 7 requirements satisfied across phases 176-179
- v1.53 complete: 7 requirements satisfied across phases 180-183
- v1.54 complete: 4 requirements satisfied across phases 184-187
- v1.55 complete: 4 requirements satisfied across phases 188-191
- v1.56 complete: 4 requirements satisfied across phases 192-195
- v1.57 complete: 4 requirements satisfied across phases 196-199
- v1.58 complete: 4 requirements satisfied across phases 200-203
- v1.59 complete: 4 requirements satisfied across phases 204-207
- v1.60 complete: 4 requirements satisfied across phases 208-211
- v1.61 complete: 4 requirements satisfied across phases 212-215
- v1.62 complete: 4 requirements satisfied across phases 216-219
- v1.63 complete: 4 requirements satisfied across phases 220-223
- v1.64 complete: 4 requirements satisfied across phases 224-227
- v1.65 complete: 4 requirements satisfied across phases 228-231
- v1.66 complete: 4 requirements satisfied across phases 232-235
- v1.67 complete: 4 requirements satisfied across phases 236-239
- v1.68 complete: 4 requirements satisfied across phases 240-243
- v1.69 complete: 4 requirements satisfied across phases 244-247
- v1.70 complete: 4 requirements satisfied across phases 248-251
- v1.71 complete: 5 requirements satisfied across phases 252-255
- v1.72 complete: 4 requirements satisfied across phases 256-259
- v1.73 complete: 6 satisfied across phases 260-263
- v1.74 active: 10 requirements across phases 264-267 (TESTFIX-01-02 -> Phase 264; DEADCODE-01 -> Phase 264; DECOMP-01 -> Phase 265; DECOMP-02-03 -> Phase 266; EXTRACT-01-03 -> Phase 267)
- v1.75 queued: 10 requirements across phases 268-271 (DEFAULTS-01-02, OPEXP-01-02 -> Phase 268; DEPLOY-01-02 -> Phase 269; EMULATION-01-03 -> Phase 270; DEPLOY-03 -> Phase 271)
- v1.76 queued: 9 requirements across phases 272-275 (THREATINTEL-01-03 -> Phase 272; CLOUDBR-01-03 -> Phase 273; CLOUDDET-01 -> Phase 274; CLOUDDET-02-03 -> Phase 275)

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-13 — Defined v1.75 Operator Packaging requirements and mapped 10 requirements to phases 268-271*
