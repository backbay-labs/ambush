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

- [x] **DEFAULTS-01**: A curated `detect_only` bootstrap path exists for first-run operator use, and the full shipped detector profile matrix is documented in the active config reference while the signed bootstrap bundle stays byte-stable
- [x] **DEFAULTS-02**: `swarmctl init` generates a working config from the signed detect-only bootstrap bundle that passes `swarmctl validate` without modification and boots the runtime to a ready state on the first run

#### Deployment Documentation

- [x] **DEPLOY-01**: A repo-owned getting-started guide (`docs/QUICKSTART.md`) walks an operator from zero to first detection using Docker Compose, including built-in telemetry injection, detection observation, and finding inspection via `swarmctl`
- [x] **DEPLOY-02**: Deployment documentation covers Docker single-container, Docker Compose with NATS, Helm chart, and bare-metal binary paths with prerequisites, config, and verification steps
- [x] **DEPLOY-03**: A `swarmctl quickstart` command orchestrates first-run: validates config, starts the runtime, injects a built-in synthetic attack scenario, waits for detection, and reports the finding with an elapsed-time measurement

#### Adversary Emulation Validation

- [x] **EMULATION-01**: The repo includes a mapped adversary-emulation scenario corpus covering more than 20 techniques across execution, persistence, credential access, lateral movement, and defense evasion tactics
- [x] **EMULATION-02**: `cargo test` includes an adversary emulation integration suite that replays the mapped corpus through the full detection pipeline and asserts coverage with a documented technique-to-detector mapping
- [x] **EMULATION-03**: A coverage report summarizes per-MITRE-technique detection status (detected, partial, not covered) and overall technique coverage percentage, and the mapped corpus clears the 60%+ coverage target

#### Operator Experience

- [x] **OPEXP-01**: `swarmctl status` outputs a concise operator-readable summary including runtime mode, active detectors, bridge health, recent findings count, and escalation state in a single screen of output
- [x] **OPEXP-02**: Error messages from config validation, runtime startup failures, and bridge connection issues include actionable remediation guidance (not just error codes)

### External Signal Ingestion (v1.76)

#### Threat Intelligence Feeds

- [x] **THREATINTEL-01**: A `swarm-ingest-taxii` crate implements a STIX/TAXII 2.1 collection consumer that polls configured feed URLs on a bounded interval and maps STIX indicator objects (IPv4, domain, file hash, URL) into `ThreatIntelEntry` records in the existing pheromone substrate with confidence scores, TTL from STIX `valid_until`, and source attribution
- [x] **THREATINTEL-02**: The threat-intel substrate consumer deduplicates indicators by type+value, updates confidence and TTL on re-observation, and exposes feed health (last poll time, indicators ingested, errors) on the existing `/healthz` surface
- [x] **THREATINTEL-03**: Detection findings that match threat-intel indicators carry enriched evidence including the IOC value, feed source, STIX indicator ID, and confidence boost applied, visible in `swarmctl` finding inspection and signed finding envelopes

#### Cloud Audit Log Detection

- [x] **CLOUDDET-01**: A `CloudTrailDetector` implements `DetectionStrategy` and detects IAM abuse patterns (CreateAccessKey from unusual principal, ConsoleLogin without MFA from new geography, AssumeRole to privilege-escalation-capable roles), resource hijacking (RunInstances with crypto-mining AMI patterns, large instance types from unusual principals), and credential compromise (GetSecretValue/GetParameter from unusual callers) from `TelemetryPayload::CloudTrailEvent` events
- [x] **CLOUDDET-02**: A `KubernetesAuditDetector` implements `DetectionStrategy` and detects privilege escalation (create/update ClusterRoleBinding, exec into privileged pods, hostPath volume mounts), RBAC abuse (impersonation, wildcard permissions), and container escape indicators (privileged container creation, hostPID/hostNetwork) from `TelemetryPayload::KubernetesAuditEvent` events
- [x] **CLOUDDET-03**: Both cloud detectors map findings to existing `ThreatClass` variants and MITRE ATT&CK cloud technique IDs, produce signed pheromone deposits through the standard pipeline, and carry cloud-specific evidence (AWS account ID, K8s namespace, principal ARN) in finding payloads

#### Telemetry Bridge Extensions

- [x] **CLOUDBR-01**: `swarm-ingest-json` extends with a `cloudtrail` bridge variant that parses AWS CloudTrail JSON records (from S3, SQS, or local file) into `TelemetryPayload::CloudTrailEvent` with field mapping for `eventName`, `userIdentity`, `sourceIPAddress`, `requestParameters`, and `responseElements`
- [x] **CLOUDBR-02**: `swarm-ingest-json` extends with a `kubernetes_audit` bridge variant that parses Kubernetes audit log JSON (webhook backend format) into `TelemetryPayload::KubernetesAuditEvent` with field mapping for `verb`, `user`, `objectRef`, `responseStatus`, and `annotations`
- [x] **CLOUDBR-03**: Both cloud bridges register in `SwarmConfig.runtime.telemetry_sources`, expose health metrics on the existing bridge surface, and are validated by integration tests proving end-to-end detection through the cloud detector pipeline

### Integration Proof (v1.77)

#### EDR Response Adapter

- [x] **EDRINT-01**: A `CrowdStrikeRtrAdapter` implements the existing `ResponseExecutor` trait and translates `ResponseAction` variants (isolate host, kill process, quarantine file) into CrowdStrike Real Time Response API calls with OAuth2 service-to-service authentication, session management, and response status tracking
- [x] **EDRINT-02**: The CrowdStrike adapter inherits the existing `ResilientExecutor` retry, `CircuitBreakerState` circuit-breaker, and dead-letter journaling behaviors without duplicating resilience logic
- [x] **EDRINT-03**: An integration test suite validates the CrowdStrike adapter against a repo-owned mock RTR API server covering session creation, command execution, result retrieval, and error/timeout handling without requiring live CrowdStrike credentials

#### SIEM Delivery Adapter

- [x] **SIEMINT-01**: A `SplunkHecAdapter` implements the existing `ResponseExecutor` trait and delivers `DetectionFinding` payloads to Splunk HTTP Event Collector with configurable index, source, sourcetype, CIM-compliant field mapping (src, dest, severity, action, signature), and HEC token authentication via `@secret:` resolution
- [x] **SIEMINT-02**: The Splunk adapter batches findings within a configurable flush interval and max batch size, inherits `ResilientExecutor` retry and circuit-breaker behavior, and exposes delivery metrics (events sent, bytes delivered, errors, latency) on the existing `/metrics` surface
- [x] **SIEMINT-03**: An integration test suite validates the Splunk adapter against a repo-owned mock HEC endpoint covering batch delivery, CIM field mapping, authentication, and error/backpressure handling

#### End-to-End Deployment Proof

- [x] **E2EPROOF-01**: A repo-owned Docker Compose stack provisions the runtime with CrowdStrike RTR adapter (mocked), Splunk HEC adapter (mocked), and one telemetry source bridge, proving the full detect -> respond -> deliver loop with observable finding delivery and response receipt generation
- [x] **E2EPROOF-02**: The deployment proof includes a scripted scenario that injects attack telemetry, observes detection, triggers a policy-gated response action through the CrowdStrike adapter, and verifies finding delivery to the Splunk adapter with correct CIM field mapping
- [x] **E2EPROOF-03**: The deployment proof documents the telemetry-to-finding-to-response-to-SIEM flow in a repo-owned integration architecture diagram and validates that all adapter metrics, health endpoints, and audit receipts are populated correctly

### Runtime Decomposition And TCB Boundary (v1.78)

#### Verification Gate Repair

- [x] **GATEFIX-01**: The clippy gate is verified green on the v1.74-v1.77 branch tip in a cold-cache run and the result recorded; the ~41 violations reported against `main` are absent on the branch because `crates/swarm-core/src/lib.rs:1`, `crates/swarm-runtime/src/lib.rs`, and `crates/swarm-runtime/src/bin/swarm_detect.rs` each carry a crate-wide `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]`.
- [x] **GATEFIX-02**: The crate-wide test-code `allow` introduced by the branch is replaced with reviewed per-call-site `#[allow(clippy::unwrap_used)]` attributes, matching the convention Chio's workspace manifest states explicitly ("exceptions get a reviewed allow at the call site, never a crate-wide opt-out"); a blanket crate-level opt-out silently permits every future unwrap in test code, including in the crates that gate destructive response.
- [x] **GATEFIX-03**: `tools/check-runtime-panic-contract.sh` is extended beyond `crates/swarm-runtime/src` to cover every workspace crate's production code, closing the gap where it reports success while clippy fails elsewhere; the script documents in-file exactly which surfaces it does and does not scan.
- [x] **GATEFIX-04**: `tools/check-supply-chain.sh` stops suppressing its own findings: the `-A duplicate` flag is removed from `cargo deny check bans`, and `deny.toml`'s `[bans] multiple-versions`, `[sources] unknown-registry`, and `[sources] unknown-git` are raised from `warn` to `deny`, with a dated `[[bans.skip]]` entry for every duplicate currently surfaced by `cargo tree -d --workspace --all-features`.

#### core.inc Elimination

- [x] **INCFIX-01**: The four `#[path = "core.inc"]` include files totalling 22,762 lines (`crates/swarm-cli/src/core.inc` 5,315, `crates/swarm-runtime/src/http/core.inc` 8,139, `crates/swarm-runtime/src/replay/core.inc` 5,406, `crates/swarm-runtime/src/workbench/core.inc` 3,902) are replaced by ordinary `.rs` modules, so `cargo fmt`, clippy, rust-analyzer, and LOC tooling all see the code they currently skip.
- [ ] **INCFIX-02** (DEFERRED to phase 282 on 2026-08-11 -- the CLI surface is `swarm-cli/src/core.inc`, which two crates include; see phase 281 criterion 1): The CLI surface is decomposed into one module per command domain following Chio's `crates/products/chio-cli/src/cli/chio/dispatch/` convention (20 files averaging ~540 LOC), with no resulting file exceeding 800 lines; the ~49 `Evolution*` command variants become their own `dispatch/evolution/` submodule tree rather than one flat enum arm list.
  - STATE 2026-08-13, MEASURED at cc5b169 (task #14): **not started, and it needs its own phase rather than a slot inside a SPLIT.** `find crates -name '*.inc'` returns 1: `crates/swarm-cli/src/core.inc`, **5,413 lines**. Still included by two crates (`crates/swarm-cli/src/lib.rs:79` and `crates/swarm-runtime-http/src/cli/mod.rs:1` via `../../../`). It names **19 distinct `crate::` modules** (`grep -ohE 'crate::[a-z_]+' crates/swarm-cli/src/core.inc | sort -u | wc -l`), which `swarm-cli` satisfies with 19 facade `pub mod` re-exports and `swarm-runtime-http` satisfies with 18 `pub(crate) use` aliases plus its own `pub mod operator_http`. **The same 5,413 lines compile twice against two different resolutions of the same 19 names**, which is why this is a decomposition refactor and not code motion: any split has to preserve the dual resolution, and any change to which modules it names changes two manifests.
  - CONSTRAINT ADDED 2026-08-13 from phase 320's finding, and verified: `grep -n "swarm-agents\|swarm-response\|swarm-policy" crates/swarm-cli/Cargo.toml` exits 1, while `swarm-runtime-http/Cargo.toml` carries all three (lines 24, 29, 30). The shared file compiles under the INTERSECTION of the two manifests, which is `swarm-cli`'s, so `core.inc` — and anything descended from it — can never name a `swarm-agents`, `swarm-response` or `swarm-policy` type directly. Add as a criterion: **the decomposition must not add any of those three dependencies to `swarm-cli`.**
  - SECOND-ORDER EFFECT on SPLIT-06: those 5,413 lines are counted by no `*.rs` glob and are compiled into both crates, so swarm-cli measures 177 and is 5,590, and swarm-runtime-http measures 10,450 and is 15,863. SPLIT-06's "no workspace crate exceeds 20,000 LOC, measured and recorded" is currently checked by an instrument blind to two crates' real size. Landing INCFIX-02 makes that clause honest; leaving it open means the clause has to say what it measures.
  - Phase 281's route note still stands and is still the cheapest: split into `swarm-cli/src/cli/` modules and repoint the cross-crate include at `#[path = "../../../swarm-cli/src/cli/mod.rs"]`, which removes the `.inc` without deciding ownership, since nested `mod` declarations resolve relative to the included file and INCFIX-03 forbids `#[path = "*.inc"]`, not `#[path]`. Exit criterion is mechanical and already gated: `find crates -name '*.inc'` returns 0, no resulting file exceeds 800 lines, and `tools/check-no-include-files.sh` (wired at `ci.yml:panic-contract`, confirmed by `bash tools/check-gates-wired.sh`) keeps it that way.
- [x] **INCFIX-03**: A CI check fails the build if any new `#[path = "*.inc"]` directive or any non-`.rs` Rust source file is introduced under `crates/`, so the pattern cannot silently return.

#### Crate Extraction From swarm-runtime

- [ ] **SPLIT-01**: `swarm-runtime-http` is extracted from `crates/swarm-runtime/src/http/`, `serve.rs`, and `operator_http.rs`, taking the `axum`, `hyper`, `hyper-util`, `tokio-rustls`, `rustls-pemfile`, and `x509-parser` dependencies out of `swarm-runtime`'s manifest. `service/` (10 files, ~5,498 LOC, zero transport references) stays in the remainder: `replay` imports `crate::service::{EventExecutionContext, RuntimeService, ...}` in non-test code, so moving `service/` into the HTTP crate would drag transport dependencies into replay.
- [ ] **SPLIT-02**: `swarm-runtime-replay` is extracted from `crates/swarm-runtime/src/replay/`, and `swarm-runtime-workbench` from `crates/swarm-runtime/src/workbench/` plus `review_workbench.rs`. `OperatorSurfacePaths` (defined in `http/core.inc`) is relocated to a shared location first: `http` imports `crate::review_workbench` types and `workbench` imports `crate::operator_http::OperatorSurfacePaths`, both in non-test code, so extracting the two as-is produces a Cargo circular dependency and a build failure.
  - STATE 2026-08-13, MEASURED at cc5b169 (task #14): **half delivered.** `swarm-runtime-workbench` exists at 4,064 LOC; `swarm-runtime-replay` does not (`ls crates/ | grep replay` prints nothing). `OperatorSurfacePaths` did relocate — `grep -rn "pub struct OperatorSurfacePaths" crates --include='*.rs'` prints exactly `crates/swarm-core/src/config/operator.rs:318`. Remaining work: **8,142 LOC** (`find crates/swarm-runtime/src/replay -name '*.rs' | xargs wc -l | tail -1`), of which 3,285 is `#[cfg(test)]`.
  - BLOCKER RESTATED 2026-08-13, superseding ADR 0003's framing: the blocker is NOT `replay/harness.rs` constructing `SwarmRuntime`. Once `swarm-runtime` stops naming `crate::replay`, `swarm-runtime-replay -> swarm-runtime` is a legal forward edge and `harness.rs:853-862` compiles unchanged. What blocks it is the root NAMING replay, at three sites after SPLIT-03 and SPLIT-04 land: `lib.rs:240,243,246` (three `#[from]` variants of `StrategyProposalRouteError`, which is the SAME enum that pins the evolution lane), `detector_factory.rs:8` (`DetectorCandidateManifest`), and `evasion_coverage.rs:7-10` (six items including `ReplayHarnessError`). Neither survivor can follow replay out: `detection/pipeline.rs:1` names `detector_factory` and `detection` is named by `dispatcher` and `service`; `startup_attestation.rs:11` names `evasion_coverage::resolve_repo_root`. Proposed as its own requirement SEAM-03 in `.planning/PHASE-282-REMAINDER.md` §3. ADR 0003's executor inversion remains worth doing, LATER and SEPARATELY, to make the replay crate a leaf rather than to unblock it (§3c).
- [ ] **SPLIT-03**: `swarm-agents` is extracted, containing the eight role implementations, satisfying the intent of v1.74's undelivered `EXTRACT-01..03`. This requires a trait boundary in `swarm_core::agent` first: the coupling is bidirectional, with `dispatcher.rs` importing `crate::tom_agent` and `lib.rs` importing `crate::sphinx_agent`/`crate::stalker_agent` while the agent files import back into config, correlation, investigation, replay, and the evolution cluster. No extraction order resolves this; the composition root must stop naming concrete agent types.
  - STATE 2026-08-13, MEASURED at cc5b169 (task #14): **5 of 8 roles delivered.** `ls crates/swarm-agents/src/*_agent.rs | wc -l` prints 5 (`pounce`, `stalker`, `tom`, `weaver`, `whisker`); `ls crates/swarm-runtime/src/*_agent.rs | wc -l` prints 3 (`calico`, `kitten`, `sphinx`) and has to reach 0. Remaining work: **8,932 LOC** (`wc -l crates/swarm-runtime/src/*_agent.rs`), of which 3,377 is `#[cfg(test)]`. The `swarm_core::agent` trait boundary is delivered and holds across two crate lines (`grep -rn SealedAgentTickError crates --include='*.rs' | grep ':impl '` prints two impls, one per crate).
  - BLOCKER RESTATED 2026-08-13, correcting ADR 0007's stated unblock: ADR 0007 pins the three on `EvolutionDetectorGenome::strategy`, `pub(crate)` at `crates/swarm-runtime/src/mutation/types.rs:137`, and says SPLIT-04 moving `mutation/` to `swarm-evolution` clears it. **It does not.** `kitten` lands in `swarm-agents`, not `swarm-evolution`, and `pub(crate)` inside `swarm-evolution` is exactly as invisible from `swarm-agents` as it is today; `tools/check-visibility-baseline.sh` covers `crates/*/src` at any depth in every crate, so the widening would still be the fourth against a baseline of three. **SPLIT-03 and SPLIT-04 are mutually blocking**: move `mutation` while `kitten` stays and the root names `swarm_evolution::mutation` (Cargo cycle); move `kitten` while `mutation` stays and it is `error[E0624]`. Three options, costed in `.planning/PHASE-282-REMAINDER.md` §3a; the recommended one is to delete the single call at `kitten_agent.rs:828` and derive the string from the `#[serde(tag = "strategy")]` attribute the type already carries — one call site, and the only option that leaves the visibility baseline at three. `.strategy()` now has 12 call sites, not ADR 0007's 13.
- [ ] **SPLIT-04**: The evolution code the v1.74-v1.77 branch collapsed into `swarm-runtime` is re-extracted into `swarm-evolution` as a real crate with its own source, replacing the 8-line facade, so the workspace has one honest crate boundary rather than a facade plus a monolith.
  - STATE 2026-08-13, MEASURED at cc5b169 (task #14): **4 modules of 11 delivered.** `swarm-evolution` holds real source at 7,067 LOC (`evidence` 2,389, `governance_prep` 1,728, `portfolio` 1,966, `operator_maintenance` 944, `lib.rs` 40); the 8-line facade is gone. Seven named modules remain in the root at **31,860 LOC** — 87% of the brief's 36,700, not 70% — of which 11,149 is `#[cfg(test)]`. Command: `find crates/swarm-runtime/src -name 'canary.rs' -o -name 'drafting.rs' -o -name 'promotion.rs' -o -name 'selection.rs' -o -name 'strategy.rs' -o -name 'evolution.rs' -o -name 'mutation.rs' -o -path '*/src/evolution/*' -o -path '*/src/mutation/*' | xargs wc -l | tail -1`.
  - BLOCKER RESTATED 2026-08-13, adding a pin the ADRs recorded only as corroborating: ADR 0005 names `StrategyProposalRouteError` (`lib.rs:214`, seven `#[from]` variants over lane types plus three over replay's) as the pin, and it is one. **It is not the only one, and it is no longer the largest.** `runtime_events.rs:4` and `service/mod.rs:46` name `crate::evolution_status::EvolutionStatusReport` in production code, and `evolution_status.rs` names `canary`, `evolution`, `mutation` and `selection` in production code (lines 1, 3, 9, 14, 276, 760, 1020, 1061, 1137, 1172, 1190; its `#[cfg(test)]` opens at 1327). ADR 0005's own progress measure now reads `evolution_status:19 kitten_agent:12 lib:7 sphinx_agent:1`, so **landing the `StrategyProposalRouteError` inversion alone moves zero lines.** Two requirements are needed, SEAM-01 and SEAM-02, both specified with success criteria in `.planning/PHASE-282-REMAINDER.md` §3b. SEAM-02 is the cheaper of the two: one report type at three sites, and the natural fix is to sink it into `swarm-core` the way `OperatorSurfacePaths` went, not to seal a trait.
- [ ] **SPLIT-05**: `swarm-ingest-runtime` is extracted from `ingest/` plus `bridge_runtime.rs` (~13,959 LOC), which no other phase claims; its non-test imports of `crate::http::rate_limit::HttpRateLimiter` and `crate::tom_agent::GovernancePolicy` are resolved so the remainder does not retain forward dependencies on the HTTP and agent crates purely to keep ingest compiling.
- [ ] **SPLIT-06**: After all extractions `crates/swarm-runtime` is a composition root under 25,000 LOC and no workspace crate exceeds 20,000 LOC, measured and recorded. Baseline for the target: `swarm-runtime/src` is 115,156 LOC on the branch counting `.inc` files (97,709 excluding them); the five originally-planned extractions remove roughly 66,000, leaving about 48,800 before `service/` and ingest placement are decided.
  - SUPERSEDED 2026-08-13, MEASURED at cc5b169 (task #14). Both numeric clauses fail, and one of them fails against the other clause of the same requirement. Re-derivation with every command in `.planning/PHASE-282-REMAINDER.md` §4.
    - **Under 25,000 is unreachable.** `swarm-runtime/src` is 80,615 now. Every extraction SPLIT-01..05 names, landed in full, removes 48,934 (replay 8,142 + three agents 8,932 + seven evolution modules 31,860) and leaves **31,681**. The residue is `service/` 5,663 (which SPLIT-01's own text requires to STAY), `config.rs` 2,692, `dispatcher.rs` 2,616, `approval.rs` 2,450, `evolution_status.rs` 2,251, `lib.rs` 2,211, `detection/` 2,165, and sixteen smaller root modules (23 in all). There is no arrangement of SPLIT-01..05 that reaches 25,000.
    - **Under 20,000 is breached by satisfying SPLIT-04.** `swarm-evolution` 7,067 + the seven 31,860 = **38,927**.
    - **COUPLING-DRIVEN REPLACEMENT.** The seven condense into a three-node DAG: A `{canary, evolution, promotion, strategy}` **15,304**; B `{drafting, mutation}` **14,627**, depends on A; C `{selection}` **1,929**, depends on A and B. A and B are genuine SCCs (`canary -> evolution -> strategy -> promotion -> canary`; `drafting -> mutation -> drafting`) and cannot be subdivided without a design change. The DAG holds for test code as well as production code, so no dev-dependency edge is needed in either direction. Three crates (existing swarm-evolution 7,067 / A 15,304 / B+C 16,556) all sit under 20,000; two crates (swarm-evolution+A = 22,371) do not.
    - **THE MEASURE IS BLIND TO 5,413 LINES.** `crates/swarm-cli/src/core.inc` is `#[path]`-included by `swarm-cli/src/lib.rs:79` and `swarm-runtime-http/src/cli/mod.rs:1` and counted by no `*.rs` glob. Real compiled sizes: swarm-cli 5,590, swarm-runtime-http 15,863. Neither breaches today, but "measured and recorded" cannot mean measured by an instrument that cannot see two crates. Amend the clause to `*.rs` under `src/` PLUS `#[path]`-included non-`.rs` source, or make INCFIX-02 a precondition.
    - **THE PLAN NOTE'S CLAIMS, CHECKED.** `mutation/` 10,631 and `evolution/` 6,862 are right at 0a09358 and are directory-only, excluding the module roots `mutation.rs` (74) and `evolution.rs` (78) where the `#[path]` declarations and the outward imports live; at cc5b169 the movable units are 10,814 and 7,707. "Each stands alone" is FALSE — see the SCCs above. `service/` is 5,663 (5,643 at the merge), but "can follow replay out once replay stops importing it" is backwards: outside `service/` and `replay/` only `lib.rs:848` names it, while `service/` itself names ten root modules including phase 320's `containment.rs`.

#### TCB Boundary And Layering Enforcement

- [x] **TCBOUND-01**: `docs/adr/ADR-0001-trusted-computing-base.md` names `swarm-policy` + `swarm-crypto` + `swarm-spine` as the trusted base (deterministic gate, signing, receipt chain) and states, in Chio `ADR-0009` negative-space style, exactly what those crates must never depend on and why adding transport or CLI dependencies to them widens the attack surface.
  PATH CORRECTED 2026-08-13. Delivered as `docs/decisions/0009-trusted-computing-base-boundary.md`. `docs/adr/` does not exist in this repository and never has; ADRs live in `docs/decisions/` and are numbered 0001-0008, so the requirement's path would have started a second ADR tree whose first file collided in number with `docs/decisions/0001-rust-first-runtime.md`. Existing location, next free number.
- [x] **TCBOUND-02**: Each trust-sensitive crate (`swarm-policy`, `swarm-pheromone`, `swarm-response`, `swarm-guard`, `swarm-crypto`, `swarm-spine`) gains an "Owns / does not own" section in its crate-level doc comment, so the boundary survives contributor turnover.
  MEASURED 2026-08-13: all six named crates exist as workspace members (`crates/swarm-{policy,pheromone,response,guard,crypto,spine}`), and all six now carry `## Owns` / `## Does not own` in their `src/lib.rs` crate-level doc comment. The section is ENFORCED, not just written: `tools/check-workspace-layering.sh` RULE 5 fails the build when either heading is absent, proven by fixture case 9. Two candidates were considered and deliberately excluded, with reasons in ADR 0009: `swarm-consensus` (trust-sensitive and manifest-clean, but phase 321 is actively rewriting it) and `swarm-core` (inside the TCB closure and enforced as such, but it is the shared type vocabulary every crate depends on).
- [x] **TCBOUND-03**: `scripts/check-workspace-layering.sh`, modeled on Chio's, fails the build if any TCB crate gains a path dependency on a product crate (`swarm-cli`, `swarm-runtime`, `swarm-runtime-http`) or a direct `clap`/`axum`/`reqwest`/`hyper` dependency; it is wired into `.github/workflows/ci.yml` as a required step.
  PATH CORRECTED 2026-08-13. Delivered as `tools/check-workspace-layering.sh`. There is no `scripts/` directory; every gate lives in `tools/`, and `tools/check-gates-wired.sh` enumerates `tools/check-*.sh` to prove each is invoked by a workflow — a gate landed at the requirement's path would have been invisible to the gate that exists to catch unrun gates. Wired as an unconditional step of the `panic-contract` job; `check-gates-wired.sh` fails the build if that stops being true, OBSERVED by disabling the step: `::error::tools/check-workspace-layering.sh is invoked by no workflow step`.
  PRODUCT-CRATE LIST WIDENED, not replaced. The requirement's three names predate phase 282's split into seven crates, so a gate typed against them would let the same inversion in through `swarm-agents` or `swarm-ingest-runtime`. The set is DERIVED from `cargo metadata` — workspace crates that reach the TCB but are outside its closure, 14 today — and the gate raises a vacuity failure if any of the requirement's three names stops being in it.
  DECLARED vs RESOLVED, decided deliberately and stated per rule (ADR 0009 carries the table). Rules 1 and 2 read DECLARED edges in all three kinds (normal/dev/build); rule 3 reads the RESOLVED normal graph against a baseline. One measured deviation the shipped tree already carries: `cargo tree -p swarm-spine -i reqwest -e normal` prints `reqwest <- swarm-response <- swarm-spine`, so the TCB reaches `reqwest` and `hyper` transitively today. Those two edges are baselined by name; a third fails the build, and a baseline entry that stops holding also fails the build.
- [x] **TCBOUND-04**: The layering script additionally fails if `swarm-policy` or `swarm-response` gains a dependency on the memory or correlation modules, converting v1.82's advisory-lane boundary from a runtime integration test into a build-time guarantee; a deliberately-broken fixture proves the check fires rather than passing vacuously.
  MEASURED 2026-08-13. The memory and correlation modules were located rather than assumed: `crates/swarm-runtime/src/sphinx_agent.rs` (`KnowledgeGraph*`, gated by `memory.enabled`) and `crates/swarm-runtime/src/correlation.rs` (`CorrelationEngine`, gated by `correlation.enabled`), both hosted by `swarm-runtime`. The rule is stated over the HOSTING CRATE, which is strictly stronger than a module rule while the modules stay there — with `swarm-runtime` out of the manifest, `use swarm_runtime::correlation::CorrelationEngine` is a compile error — and the two-line registry that aims it raises `LAYERING-VACUITY[guard]` if a registered module path stops existing, so the lane cannot move out from under the rule silently (fixture case 10).
  THE FIXTURE IS EXECUTABLE AND RUNS ON EVERY INVOCATION. It generates a real miniature cargo workspace (real crate names; stub path crates literally named `axum`/`clap`/`hyper`/`reqwest`, so no registry and no network), runs real `cargo metadata` over it, and runs the SAME rule engine with the SAME policy and baseline, unmodified. One control case that must exit 0 plus nine deliberately-broken variants that must each exit non-zero with a named diagnostic; four of the nine are inversions cargo itself accepts (dev cycles, build cycles, transitive transport edges). The gate was ALSO observed failing against the real tree: adding `clap` to `swarm-policy`'s `[dependencies]` and `swarm-runtime` to its `[dev-dependencies]` produced five diagnostics including `LAYERING-VIOLATION[advisory-declared] swarm-policy declares 'swarm-runtime' as a dev dependency`, and the tree was restored.
### Collective Cyber Reasoning (v1.79)

The active v1.79 contract replaces the old executor-first queue with a collective reasoning milestone. Phase 285 is closed under a deliberately narrower, truthful assurance scope; phases 286-289 are accepted for implementation. Every metric below is evaluated against a checked-in benchmark manifest and a single-agent or pre-change control. No phase may claim a protected GitHub rule unless the repository independently proves provenance-distinct enforcement.

#### Phase 285: Assurance Foundation Closure

- [x] **ASSURE-01**: The combined-tree assurance bundle contains a parsed assumption registry, exact invariant-to-function mappings, negative-falsifiability entries, fixture freshness evidence, and supply-chain evidence; the local gates exit 0 on the declared commit and exit non-zero for each documented unmapped, missing-negative, stale-fixture, and dependency-policy mutation.
- [x] **ASSURE-02**: The SBOM is generated from locked `cargo metadata` resolution, includes package identities and dependency edges, validates against the declared CycloneDX schema, and rejects an invented dependency graph, invalid component type, or missing resolve edge in negative controls.
- [x] **ASSURE-03**: A hosted Linux run executes the local assurance gates on a fresh, credential-free checkout, publishes commit-bound machine-readable results, and records the exact runner/toolchain/input identity needed to reproduce the result.
- [x] **ASSURE-04**: Local and hosted evidence is reviewed on the combined tree, with no P0, P1, or P2 finding left unresolved in the phase review packet; isolated worktree or script-only green output is not sufficient evidence.
- [x] **ASSURE-05**: The assurance docs distinguish `wired`, `executed`, `passed`, and `protected-required`; the external provenance-distinct GitHub App check and repository-settings enforcement are explicitly deferred and are not required for Phase 285 acceptance.
- [x] **ASSURE-06**: Phase 285 verification is recorded as `passed` only for ASSURE-01..05 and the stated evidence boundary; it must not claim protected-branch enforcement, distributed failover coverage, or release authorization.

#### Phase 286: Collective Hypothesis Graph

- [ ] **COG-01**: A versioned, serializable hypothesis graph supports typed `actor`, `asset`, `credential`, `process`, and `event` nodes plus typed causal edges. Every edge carries confidence, source evidence IDs, producer role, observation time, and schema version; malformed or unproven edges are rejected rather than silently admitted.
- [ ] **COG-02**: A seed signal creates at least two competing attack hypotheses when the evidence is ambiguous. Hypotheses retain confidence distributions, explicit uncertainty, contradiction sets, and a decision history; no single detector classification may erase a live alternative before evidence resolution.
- [ ] **COG-03**: Evidence-hunter, challenger, and falsifier roles claim unresolved graph edges through a durable stigmergic task ledger. Claims have leases, idempotency keys, evidence scope, and completion/failure state; a 100-task duplicate-claim fixture keeps duplicate investigation work at or below 5%.
- [ ] **COG-04**: Process, identity, Kubernetes audit, CloudTrail, network, and threat-intelligence telemetry normalize into one evidence envelope with source lineage and clock/ordering metadata. The cross-telemetry fixture contains at least one corroborating and one conflicting signal from each source family.
- [ ] **COG-05**: The converged incident includes a reconstructed kill chain whose every node, edge, stage assignment, and narration claim links to one or more evidence IDs. A withheld multi-stage fixture must preserve declared stage order and report missing evidence instead of inventing a link.
- [ ] **COG-06**: Containment options are simulated and ranked by predicted blast radius, reversibility, evidence support, and required approval. Planning cannot execute a response; any selected live action must still enter the existing policy, receipt, and operator-approval path.
- [ ] **COG-07**: Completed investigations persist strategy memories containing the hypothesis delta, evidence utility, falsified alternatives, outcome, and provenance. A replayed investigation retrieves the memory without raw telemetry and changes task prioritization deterministically when the memory is applicable.
- [ ] **COG-08**: The benchmark reports median time to the correct causal hypothesis, attack-chain recall, false causal-edge rate, duplicate investigation work, and evidence coverage. Phase 286 passes when the collective lane beats the single-agent control by at least 20% median hypothesis time, improves chain recall by at least 10 percentage points, keeps false causal edges at or below 10%, duplicate work at or below 5%, and covers at least 90% of adjudicated evidence.

#### Phase 287: Adversarial Co-evolution Arena

- [ ] **ARENA-01**: Red agents compose bounded multi-stage campaigns from the catalogued tactic/technique corpus, with deterministic seeds, virtual time, event budgets, and no invented capabilities or live-target access.
- [ ] **ARENA-02**: Blue agents investigate the generated campaign through the real Ambush ingest, hypothesis-graph, detector, policy, and containment-planning path. Arena actions run against fixtures or an isolated sandbox; red code has no response-adapter or policy-authority capability.
- [ ] **ARENA-03**: Red mutation consumes observed blue evidence and changes ordering, timing, or tactic composition within the declared budget. A replay report must show which blue outcome caused each surviving mutation and must terminate on generation, budget, plateau, or coverage bounds.
- [ ] **ARENA-04**: Blue synthesis emits detector and response candidates from escapes and falsified hypotheses, each with evidence lineage, affected telemetry sources, expected coverage, safety constraints, and a reproducible candidate ID.
- [ ] **ARENA-05**: Candidates compete against historical attacks, benign controls, and counterexamples. A candidate cannot survive on aggregate catch rate alone: false positives, latency/resource budgets, containment safety, and withheld campaigns are separate scored dimensions.
- [ ] **ARENA-06**: The arena is structurally isolated from destructive authority. Static and runtime controls fail closed if red code imports response execution, blue simulation bypasses policy, or a generated action lacks a receipt/approval boundary; the controls include a negative fixture that proves they can fail.
- [ ] **ARENA-07**: Arena reports measure time to containment, containment blast radius, previously unseen evasions discovered, improvement over the single-agent baseline, and generalization to withheld campaigns. Acceptance requires at least 15% median containment-time improvement, no increase in median blast radius, at least one previously unseen evasion found in three consecutive seeded runs, at least 10% improvement over the single-agent baseline, and withheld-campaign performance no worse than 5% relative to the in-sample score.
- [ ] **ARENA-08**: A fixed seed, corpus digest, scheduler, and virtual clock produce byte-identical campaign decisions and candidate lineage; wall-clock guards, maximum generations, event budgets, and teardown checks prevent an unbounded or state-leaking run.

#### Phase 288: Autonomous Detector And Response Synthesis

- [ ] **SYNTH-01**: The synthesis lane derives detector candidates from graph gaps, evasion escapes, and falsifier findings using typed templates or bounded mutations; each candidate names the signal features, detector family, hypothesis edges addressed, and source evidence.
- [ ] **SYNTH-02**: The lane derives response-plan candidates only from the existing typed response library and policy vocabulary, attaching approval requirements, reversibility, blast-radius scope, and rollback expectations. It cannot invent or directly invoke a response adapter.
- [ ] **SYNTH-03**: Candidate evaluation runs historical attacks, benign controls, counterexamples, and withheld campaigns through the real replay/detection path, with deterministic reports for catch rate, false-positive rate, latency, resource cost, and causal-evidence coverage.
- [ ] **SYNTH-04**: Mutation, differential, and metamorphic controls prove candidate gains are not artifacts of a weakened oracle: removing a candidate rule, swapping a source adapter, or mutating an expected verdict must produce the documented regression or block the candidate.
- [ ] **SYNTH-05**: Promotion remains fail closed and operator-reviewed. A candidate without complete evidence lineage, safety checks, reproducible evaluation, and required solver/approval artifacts is rejected; accepted candidates produce a durable review packet and never silently replace the baseline.
- [ ] **SYNTH-06**: The synthesis report records candidate quality and safety deltas against the baseline, including attack-chain recall, false causal edges, evidence coverage, time to containment, blast radius, latency, and resource use. A candidate must improve at least one target metric by 10% while regressing none of the safety ceilings and must pass every withheld-campaign and counterexample gate.

#### Phase 289: Herd Memory

- [ ] **HERDMEM-01**: Investigations export typed attack abstractions, causal motifs, detector/response outcomes, and strategy utility without exporting raw telemetry, secrets, host identifiers, or operator credentials. The export schema is versioned and rejects unredacted fields.
- [ ] **HERDMEM-02**: Every memory record carries signer/provenance lineage, source-corpus digest, confidence, expiry, and transformation history. Import rejects tampered, replayed, stale, schema-invalid, or privacy-violating records and records the refusal reason.
- [ ] **HERDMEM-03**: A receiving swarm requires independent local corroboration before using a peer memory for prioritization. No single publisher can raise confidence or authorize containment; conflicting memories remain visible as contradictions.
- [ ] **HERDMEM-04**: Retrieved memory changes the next investigation's task ordering only when its context matches the current graph and source evidence. The benchmark compares memory-enabled, single-agent, and no-memory controls on hypothesis time, chain recall, false causal edges, duplicate work, and evidence coverage.
- [ ] **HERDMEM-05**: Memory retention, expiry, revocation, poisoning quarantine, and operator deletion are durable and restart-safe. Garbage collection removes expired payloads and dependent indexes without leaving actionable orphan state.
- [ ] **HERDMEM-06**: Herd-memory acceptance requires at least 20% lower median time to correct hypothesis or 10 percentage-point higher chain recall versus the single-agent control, no increase above the Phase 286 false-edge/duplicate-work ceilings, discovery of at least one previously unseen evasion across the withheld corpus, and withheld-campaign generalization within 5% of the in-sample score.

### Historical Assurance Foundation (retired 2026-08-21; not an acceptance set)

The former `MAPPING-*`, `FALSIFY-*`, `DST-*`, `FUZZ-*`, `LOOM-*`, and `SUPPLY-*` definitions below are retained as historical planning notes and evidence lineage. The deterministic-simulation, fuzz, and Loom executor backlog is not carried into active v1.79 acceptance. The local mapping, negative-registry, supply-chain, SBOM, and hosted-runner work is represented by the passed `ASSURE-*` scope above. The old definitions remain useful when tracing prior work, but their unchecked boxes do not indicate current blockers.

#### Fixture Determinism And Suite Health

- [x] **FIXTURE-01**: A deterministic fixture generator (`tools/regen-kitten-fixtures.sh`) regenerates every `experiments/*.yaml` consumed by `crates/swarm-runtime/src/kitten_agent.rs` tests from a pinned schema version.
- [x] **FIXTURE-02**: The 161 `experiments/*.yaml` files carrying the `command_line_normalization` field that `SuspiciousProcessTreeProfile` rejects under `deny_unknown_fields` are regenerated or removed; `cargo test -p swarm-runtime kitten_agent` passes with zero failures.
- [x] **FIXTURE-03**: `tools/check-fixture-freshness.sh` regenerates fixtures into a scratch directory, diffs against the checked-in copies, and fails CI on drift, so a "sync generated artifacts" commit can never again check in fixtures the parser rejects.
- [x] **FIXTURE-04**: Tests read fixtures from an isolated copy rather than the live repo-root `experiments/` directory, and no test or tool writes into the repository working tree during a run (closing the 48 untracked droppings under `crates/*/data/`).

#### Assumption Registry And Invariant Mapping

- [x] **MAPPING-01**: `docs/assurance/assumptions.toml` names at least 8 assumptions (ASSUME-OS-CLOCK, ASSUME-JETSTREAM-DURABILITY, ASSUME-KEYSTORE-ATOMICITY, ASSUME-ED25519, ASSUME-SHA256, ASSUME-CANONICAL-JSON, ASSUME-NETWORK-TRANSPORT, ASSUME-SUBPROCESS-ISOLATION), each with an owner and its dependent invariants. DELIVERED with 13. `ASSUME-STATEFUL-GATE-DETERMINISM` is limited to deterministic local policy state transitions; external adapter outcomes use `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR`, and release-signer membership uses `ASSUME-GOVERNANCE-TRUST-ANCHOR`. Assumptions are many-to-many and the gate enforces complete overlapping blast-radius sets.
- [x] **MAPPING-02**: `docs/assurance/MAPPING.md` carries one row per fail-closed invariant, covering `swarm-policy`'s gates, `SwarmRuntime::authorize_and_execute`, `SwarmRuntime::preflight_containment`, `swarm-spine`'s envelope signing and chain verification, and `swarm-response`'s dispatch, each naming an exact `crate::module::function` path and assumption IDs. DELIVERED with 59 mapped invariants and 5 owned omissions. `docs/assurance/universe.toml` records exact IDs/counts, mapped/omitted disjointness, and one-surface assignment. The local gate rejects deletion unless the checked-in ratchet and checker are coherently changed; that remaining trust-root problem is external, not described as immutable here.
- [x] **MAPPING-03**: A `// INVARIANT: <Name>` source-marker convention annotates every Rust call site named in MAPPING.md.
- [x] **MAPPING-04**: `scripts/check-mapping.sh` fails the build when a marker has no MAPPING.md row, or a MAPPING.md row names a Rust path that no longer exists. DELIVERED AT `tools/check-mapping.sh`; there is no `scripts/` directory in this repository and `tools/check-gates-wired.sh` only enumerates `tools/check-*.sh`, so the requirement's path would have made the gate invisible to the gate that catches unrun gates (same correction phase 283 recorded).
- [ ] **MAPPING-05**: `scripts/check-mapping.sh` runs as a required step in `.github/workflows/ci.yml`. WORKFLOW WIRING DELIVERED AT `tools/check-mapping.sh`; protected provenance remains open. The current Free organization cannot pin an organization-owned required workflow, and the existing Actions App plus the local `mapping-contract` / `negative-registry-contract` contexts remain spoofable. Acceptance needs a protected dedicated external GitHub App check with a separate integration ID (or an organization-plan upgrade and admin-owned required workflow).

#### Negative Falsifiability

- [x] **FALSIFY-01**: `docs/assurance/negative-registry.toml` maps each MAPPING.md invariant to a `crates/*/tests/negative_*.rs` test and the production function it targets.
- [x] **FALSIFY-02**: Each registered test constructs a deliberately-broken variant of the enforcing function and asserts the broken variant permits what the real function denies, proving the positive suite is not vacuous. DELIVERED for all 59 rows: every exact built-in `#[test]` invokes a registry-bound named case with one probe; the shared synchronous protocol executes one macro-owned production call through an exact crate-root external-crate alias, mirror(None), and mirror(BrokenVariant) operation and asserts real/control denial plus broken permission. A source-digested entry/completion sentinel surrounds the future driver. A separate five-test compiled contract uses typed counters/roles. The focused Rust-syntax checker parses each distinct registered source once and locally digests the complete source files and shared protocol, including imports, helper/wrapper bodies, setup, production arguments, normalization, mirror roles, and denial/permission predicates; actual-source attacks covering dead/control-flow calls, black-box and unrelated assertions, dependency-root shadows, aliases/re-exports/globs, dead genuine calls with fabricated results, forced mirror roles, identity-selective early returns, and constant/ignored/swapped/vacuous predicates fail. The gate binds checker-owned semantic digests of the four complete crate manifests plus root execution tables, exact Cargo.lock/metadata dependency identities, pinned toolchain semantics, canonical auto-discovered integration-test and production-library source paths, and absence of explicit target overrides or custom builds. Every Cargo command uses a fresh config-free home, pinned Cargo/rustc, a sanitized PATH, and no repository/ancestor config; a gate-owned isolated-Python wrapper forces and audits one exact test-mode compile per target, including canonical source realpath/hash. Emitted test binaries run directly under a sanitized environment for exact inventory/count proof. Executable attacks cover hostile external Cargo homes, compiler/workspace wrappers, build.rustc, rustflags, linker/runner, Python module shadowing, proc-macro body erasure, path build dependencies, and same-name target redirection. These co-located checks are tamper-evident against uncoordinated edits, not an external trust anchor, and handwritten-mirror fidelity beyond the probe remains a review claim.
- [x] **FALSIFY-03**: `scripts/check-negative-registry.sh` fails if any MAPPING.md row lacks a registry entry or names an absent test. DELIVERED AT `tools/check-negative-registry.sh`; there is no `scripts/` directory in this repository and `tools/check-gates-wired.sh` only enumerates `tools/check-*.sh`, so the requirement's path would have made the gate invisible to the gate that catches unrun gates (same correction phase 283 recorded).
- [ ] **FALSIFY-04**: `scripts/check-negative-registry.sh` is a required CI step. WORKFLOW WIRING DELIVERED AT `tools/check-negative-registry.sh`; the same protected-provenance acceptance as MAPPING-05 remains open and requires the external check anchor described there.

#### Deterministic Simulation Testing

- [ ] **DST-01**: `crates/swarm-runtime/tests/dst_fault_injection.rs` drives the real `SwarmRuntime::authorize_and_execute` (`crates/swarm-runtime/src/lib.rs:753`), a real approval gate, and the real pheromone substrate, with no mocks.
- [ ] **DST-02**: Seeded fault injection covers dropping the future mid-poll before dispatch, dropping it after dispatch but before receipt persistence, and closing/reopening the substrate between policy-allow and receipt-persist.
- [ ] **DST-03**: Three oracles assert receipt-before-action ordering, exact disposition against the deterministic policy verdict, and no double-dispatch per request.
- [ ] **DST-04**: A 64-seed corpus runs on every PR; a >=5,000-seed corpus runs in `.github/workflows/dst-nightly.yml`.
- [ ] **DST-05**: `SWARM_DST_SEED=<n>` replays one episode's exact fault plan for one-command reproduction.
- [ ] **DST-06**: `docs/assurance/MAPPING.md` gains a harness section stating the evidence boundary: single-process, single-substrate-instance, not distributed JetStream failover.

#### Fuzz And Loom Coverage

- [ ] **FUZZ-01**: A `fuzz/` cargo-fuzz workspace ships targets for `ingest_json_decode`, `ingest_sentinel_decode`, `ingest_tetragon_decode`, and `ruleset_yaml_parse`, each calling a real parse entry point.
- [ ] **FUZZ-02**: `tools/seed-fuzz-corpus.sh` seeds each target from `scenarios/*.yaml` and `rulesets/*.yaml`.
- [ ] **FUZZ-03**: `.github/workflows/fuzz-nightly.yml` runs each target for 600s nightly, failing on crash and uploading the crashing input.
- [ ] **FUZZ-04**: A 30s smoke pass per target is a required PR step so harness breakage is caught immediately.
- [ ] **LOOM-01**: `crates/swarm-pheromone/tests/loom_concurrent_write.rs` models concurrent deposit and decay-eviction.
- [ ] **LOOM-02**: `crates/swarm-policy/tests/loom_concurrent_decision.rs` models concurrent decision evaluation against ruleset reload.
- [ ] **LOOM-03**: `.github/workflows/loom-nightly.yml` runs both harnesses with a documented bounded preemption budget.
- [ ] **LOOM-04**: MAPPING.md labels each Loom harness `scope = "bounded_abstract_model"`.

#### Supply-Chain Hardening

- [x] **SUPPLY-01**: Every `deny.toml` `[advisories].ignore` entry carries a `last-checked` date, a blast-radius note, and a clearing condition. Also an `expires` date: an exception whose deadline has passed FAILS `tools/check-supply-chain.sh` (constructed and observed), and the last-checked..expires window is capped at 180 days. `[[bans.skip]]` entries carry `last-checked` and `pinned-by`/`clears-when` under the same parser. Selectors split at the final `@`; only non-empty name and exact SemVer syntax are checked locally, while exact Cargo.lock name matching authoritatively accepts Cargo-valid leading-underscore and Unicode-XID names. Executable fixtures require a full-text lock match including `+build`, refuse absent names, reject same-name same-precedence ambiguity for every selector (including registry+path same-version and stable-plus-build rows), list source/path identity, retain stable/prerelease/build/name pass controls, and prove a first-run locked resolution rejects a disposable path-dependency version change whose lock row is stale without changing its bytes.
- [x] **SUPPLY-02**: `tools/check-supply-chain.sh` fails if any ignore or skip entry is missing a date or justification. Before parsing Cargo.lock it runs `cargo metadata --locked --format-version 1`; its lock cross-check then owns exact full textual selector identity, and `cargo deny --locked check` plus denied `unmatched-skip` and `unnecessary-skip` lints and ordinary duplicate errors own applicability in the same locked graph. The gate also deduplicates the `cargo audit --ignore` list against `deny.toml` by DERIVATION rather than comparison: it reads `[advisories] ignore` and builds the flags, holds no id of its own, and fails if a RustSec id appears on any other enforcement surface. Cargo-audit has no locked mode, so the gate snapshots Cargo.lock and fails if any scanner rewrites it.
  The independently locked `tools/negative-registry-ast` executable is covered explicitly: locked metadata and lock immutability, a separate zero-waiver deny policy, cargo-deny, cargo-audit, and enforcement-surface inventory all run in the same gate.

### Historical Red Swarm Scope (retired 2026-08-21; not an acceptance set)

The former OPFOR/ATKSCORE/COEVOLVE/ARMSCI definitions are retained below for provenance only. They are superseded by the ARENA/SYNTH requirements in active v1.79 and do not create queued v1.80 acceptance.

#### Red Operator Genome And Target Graph

- [ ] **OPFOR-01**: Six red operator roles (`ReconOperator`, `InjectionOperator`, `AuthOperator`, `EvasionOperator`, `ChainOperator`, `OpsecOperator`) implement a shared `RedOperator` trait with `propose_steps(&self, graph, rng) -> Vec<GeneStep>`.
- [ ] **OPFOR-02**: `TargetGraph` is built from `rulesets/evasion/attack-technique-catalog.yaml` and every scenario's `metadata.techniques`; nodes are the 11 catalogued detectors, techniques, and `ThreatClass` values.
- [ ] **OPFOR-03**: `RedGenomeRng` is a deterministic `rand_core::RngCore` + `SeedableRng` PRNG with zero OS-entropy paths.
- [ ] **OPFOR-04**: `RedGenome::plan(seed, generation, campaign)` resolves every `GeneStep.technique` only to techniques already in the `TargetGraph` (no invented techniques or payload shapes); `swarmctl red-swarm plan` prints the plan with a `determinism` object (`rng_seed`, `virtual_clock_start_ms`, `scheduler`).

#### Attack Scoring, Stealth Budget And Pattern Memory

- [ ] **ATKSCORE-01**: `AttackScorer` computes `AttackFitness { evasion_rate, stealth, red_fitness }` from an adversarial sequence and an `EvasionCoverageSnapshot`, where `evasion_rate = 1.0 - detector-weighted catch_rate`.
- [ ] **ATKSCORE-02**: `StealthBudget` (`max_events_per_generation`, `max_distinct_hosts`, `max_technique_repeats`) deterministically truncates proposed steps once exhausted, so red cannot win by volume.
- [ ] **ATKSCORE-03**: `AttackPatternDb` is an append-only JSON-lines store recording `{generation, technique, detector, detected}` with `technique_success_rate` biasing later generations.
- [ ] **ATKSCORE-04**: `swarmctl red-swarm score --json` prints `red_fitness`, `evasion_rate`, `stealth`, and `events_emitted`.

#### Bidirectional Co-Evolution And Convergence

- [ ] **COEVOLVE-01**: `RedSwarmCampaign::run` plans, materializes events, runs them through the real detector pipeline, records outcomes, and computes both red fitness and blue catch rate per generation.
- [ ] **COEVOLVE-02**: A bounded stopping rule terminates every run on `max_generations`, fitness plateau within `convergence.min_delta` for `convergence.patience` generations, or full blue coverage; `stop_reason` is recorded.
- [ ] **COEVOLVE-03**: `GenomeRedSwarm` implements the existing `RedSwarmAdapter` trait alongside `SuiteRedSwarmAdapter`.
- [ ] **COEVOLVE-04**: `EvolutionAdversarialSummary.corpus_sequence_id` may reference a campaign generation without changing its public shape; campaign reports persist under `data/red-swarm/campaigns/`.

#### CI Arms Race Gate And Structural Isolation

- [ ] **ARMSCI-01**: CI runs a bounded campaign and fails the build if `final_blue_catch_rate` regresses below a checked-in threshold; the gate ships in the same phase as its executor.
- [ ] **ARMSCI-02**: `scripts/check-red-swarm-no-execution-authority.sh` fails if any forbidden symbol (`execute_response`, `ResponseAdapter`, `PolicyDecision::Authorize`, `live_response`) appears in red-swarm sources.
- [ ] **ARMSCI-03**: A Rust-side companion test performs the same check at `cargo test` time, with a documented counterexample fixture proving the check is not vacuous.
- [ ] **ARMSCI-04**: `swarmctl evolution status --json` includes a `red_swarm_campaign` object sourced from the on-disk report, reporting `null` rather than a stale value when absent.
- [ ] **ARMSCI-05**: A wall-clock budget guard fails the CI step loudly rather than silently inflating build time.

### Machine-Checked Decision Core (v1.81)

#### Pure Decision Core Extraction

- [ ] **DCORE-01**: `crates/swarm-policy/src/formal_core.rs` holds the approval and rate-limit logic as pure total functions taking window state and `now_ms: i64` explicitly, returning updated state instead of mutating `Arc<Mutex<HashMap<..>>>` in place.
- [ ] **DCORE-02**: The partition and governance predicates (`GovernancePolicy::can_act`, `ContingencyLease::verify`/`can_redeem`/`redeem`, `governance_quorum_threshold`) are ported into `formal_core.rs` with no `Mutex`, no `fs`, and no direct clock; the internal `now_ms()` call at `tom_agent.rs:508` becomes an explicit parameter.
- [ ] **DCORE-03**: `cargo tree -p swarm-policy` contains no `axum`, `hyper`, `tokio-rustls`, `reqwest`, `opentelemetry*`, `clap`, or `x509-parser`.
- [ ] **DCORE-04**: `docs/adr/ADR-0002-decision-core-boundary.md` plus `scripts/check-decision-core-boundary.sh` enforce the forbidden-dependency list in CI.
- [ ] **DCORE-05**: Every pre-existing `static_gate`, `configurable_gate`, and `tom_agent` governance test passes unchanged against the new call paths.

#### Kani Bounded Model Checking

- [ ] **KANI-01**: An optional `kani` feature and `crates/swarm-policy/src/kani_public_harnesses.rs` hold `#[kani::proof]` functions calling the real `pub fn`s from `formal_core.rs`.
- [ ] **KANI-02**: Harnesses prove fail-closed evaluation, severity-gate soundness, and rate-limit boundedness within a 60,000ms trailing window.
- [ ] **KANI-03**: Harnesses prove lease integrity: invalid signature, non-approve decision, and hash-mismatched proposal always deny; redemption never exceeds `blast_radius_cap`; expiry always denies. Model-only harnesses are labeled `MODEL-ONLY`.
- [ ] **KANI-04**: `formal/kani/swarm-policy-harnesses.toml` enumerates every harness; a unit test fails the build if a `#[kani::proof]` function is missing from the manifest.
- [ ] **KANI-05**: `scripts/run-kani-swarm-policy.sh` runs every PR-lane harness in CI.

#### Named Safety Properties And Partition-Lease Model

- [ ] **SAFEP-01**: `formal/PROPERTIES.md` defines P1-P6 (fail-closed evaluation, severity-gate soundness, partition-override receipt integrity, blast-radius conservation, quorum-transition soundness, rate-limit boundedness), each naming exact symbols and checking harnesses.
- [ ] **SAFEP-02**: P1-P6 gain rows in `docs/assurance/MAPPING.md` following its existing schema.
- [ ] **SAFEP-03**: `ASSUME-INJECTED-CLOCK` and `ASSUME-GOVERNOR-KEY-CUSTODY` are registered in `assumptions.toml` with owners and dependent properties.
- [ ] **SAFEP-04**: `formal/tla/PartitionContingency.tla` models the four partition states, lease issuance and redemption with blast-radius cap, and reconciliation on heal, with named invariants.
- [ ] **SAFEP-05**: At least 3 negative-falsifiability entries produce Apalache violations, each naming the runtime regression test pinning the same defect.

#### Historical Z3-Backed Promotion Gate (Phase 322; completed in v1.78.1)

- [x] **ZGATE-01**: `require_solver_result_for_promotion` is added to config, distinct from `evolution.assurance.require_solver_summary`, defaulting to `true` in the curated ruleset. SHIPPED 99733a0. "Defaults true in the curated ruleset" can only mean "a ruleset that omits the key resolves to true" — `rulesets/default.yaml` is frozen by the signed attestation and cannot carry the key — so the serde default is the mechanism, pinned by `tracked_default_ruleset_resolves_the_promotion_solver_gate_to_enabled`.
- [x] **ZGATE-02**: `crates/swarm-runtime/src/promotion.rs` rejects a candidate whose `solver_summary` is `None` when the gate is enabled; today `promotion.rs` never references `solver_summary` at all (verified: 0 occurrences). PATH CORRECTED 2026-08-13: `crates/swarm-evolution/src/promotion.rs` does not exist and never did — that crate owns four modules and re-exports `promotion` from `swarm-runtime` (`swarm-evolution/src/lib.rs:36-39`). The 0-occurrence measurement is correct for the real file, which is 2,901 lines and also has 0 occurrences of `z3`. SHIPPED 99733a0 as `ProductionPromotionError::SolverResultMissing`.
- [x] **ZGATE-03**: A `CustomZ3` bundle evaluated through the `z3`-feature-off path counts as no solver result, so a build without the feature fails closed rather than promoting on an unverified stub. SHIPPED. The code distinction was already right — the feature-off arm and `enable_z3: false` both record `EvolutionSolverProofStatus::Disabled`, and `promotion_solver_block` maps `Disabled` onto the SAME `Missing` variant as an absent status. What was open is that `rulesets/default.yaml:236-238` lists `disabled` in `evolution.assurance.allowed_solver_statuses`, and that file cannot be edited: its sha256 is inside the ed25519-signed `rulesets/attestation.json` and the signing key is deliberately absent. So the requirement is closed in the CONSUMING code instead — the promotion gate hardcodes `proved` and reads the assurance allow-list nowhere, enforced by `the_assurance_allow_list_cannot_authorize_a_promotion`, which is the only test that fails when `promotion_solver_block` is rewired to that field (measured).
- [x] **ZGATE-04**: The promotion report prints the solver proof id and attestation hash, or an explicit "NO SOLVER RESULT RECORDED" line. SHIPPED 99733a0 as the unconditional `Solver result:` line, either `<status> | required_for_promotion=<bool>` or the exact `NO_SOLVER_RESULT_RECORDED` literal.
- [x] **ZGATE-05**: `crates/swarm-runtime/tests/promotion_solver_gate.rs` covers denied-missing-summary, denied-feature-disabled, and allowed-with-proof, asserting on concrete variants rather than log lines. PATH CORRECTED 2026-08-13: `crates/swarm-evolution/tests/` does not exist. A test at the original path would compile, since `swarm_evolution::promotion` is a live re-export, but it would sit under a crate containing none of the code it exercises and would silently change meaning when a later SPLIT moves `promotion` for real. SHIPPED at the corrected path with five tests. denied-feature-disabled derives its status from the REAL formal-safety gate rather than a hand-typed literal, and the file also executes the operator recipe from `docs/EVOLUTION.md` by reading the query out of the doc.

### Provenance Memory And Correlation (v1.82)

#### Provenance Graph Substrate

- [ ] **GRAPH-01**: `KnowledgeGraphNode` gains `Process`, `File`, and `NetworkFlow` variants carrying raw telemetry identifiers, distinct from the existing detection-level `EngagementNode`.
- [ ] **GRAPH-02**: `CausalRelation` (today only `ProcessParentChild` and `NetworkFlowOrigin`) gains `FileWrite`, `FileExecute`, `DnsResolution`, and `CredentialAccess`, emitted from every processed observation.
- [ ] **GRAPH-03**: `KnowledgeGraphSnapshot::provenance_paths(from, to, max_hops)` returns bounded-hop paths and becomes the single read path `CorrelationEngine` uses, with a hub-degree cap so high-degree nodes cannot connect unrelated hunts.
- [ ] **GRAPH-04**: A property test over 200+ randomized `prune_stale` sequences proves GC never orphans an edge, never deletes a retention-window-protected record, and is idempotent.
- [ ] **GRAPH-05**: A soak test replays 100k synthetic events and asserts post-GC node+edge count stays under a fixed ceiling.
- [ ] **GRAPH-06**: Config validation rejects or loudly warns on `knowledge_retention_days == 0` while `memory.enabled` is true, closing the silent-no-op GC footgun at `sphinx_agent.rs:1097`.

#### Kill-Chain Reconstruction

- [ ] **CHAIN-01**: `chain_reconstruction.rs` walks causal, temporal, and semantic edges and maps observed paths onto the stage ordering in `sequences/kill-chain-v1.yaml`.
- [ ] **CHAIN-02**: `KillChainSequenceDetector` matches are written into the graph as semantic kill-chain-stage edges, making ephemeral detections durable evidence.
- [ ] **CHAIN-03**: Incidents referencing disjoint `hunt_id`s connected by a causal path emit a `ReconstructedKillChain` persisted alongside `IncidentRecord`.
- [ ] **CHAIN-04**: `narrate()` produces a stage-by-stage narrative, tested against at least two existing multi-stage fixtures with stage order matching each fixture's declared chain.

#### Cross-Hunt Correlation

- [ ] **XHUNT-01**: `CorrelationEngine`'s pairwise heuristics are replaced by graph traversal; all four `IncidentGraphDimension` tags come from real graph edges rather than string overlap.
- [ ] **XHUNT-02**: `IncidentEvidenceLink` gains an optional `graph_path` so a reopened incident is re-explainable without recomputation; pre-existing JSON still deserializes.
- [ ] **XHUNT-03**: An integration test disables `correlation.enabled` and `memory.enabled` together and asserts identical policy decisions, proving the optional lanes never gate the critical path.
- [ ] **XHUNT-04**: A restart-simulation test proves incidents reload with identical dimensions and evidence.

#### Dependency-Aware Triage

- [ ] **TRIAGE-01**: `triage_score.rs` implements NODOZE-style path-rarity scoring with at least 5 unit-tested scenarios.
- [ ] **TRIAGE-02**: The score suppresses `CorrelatedIncident.confidence_score`, gated by `correlation.enabled`, with no access from `swarm-policy`.
- [ ] **TRIAGE-03**: Measured false-positive rate across `benign-baseline.yaml`, `benign-dns-baseline.yaml`, and `python-maintenance-benign.yaml` drops at least 50% relative to the pre-triage baseline, and no benign scenario crosses the escalation threshold.
- [ ] **TRIAGE-04**: `FalsePositiveMeasurementReport` gains a dependency-score summary; a test asserts mean true-positive score exceeds mean false-positive score.
- [ ] **TRIAGE-05**: New signed record types go through the existing agent signing paths, with signature round-trip coverage.
### Distributed Governance (v1.83)

#### Historical BFT Correctness Repair (Phase 321; deliberate partial)

- [x] **BFT-01**: `recommended_max_faulty` in `crates/swarm-consensus/src/lib.rs:65` is corrected from `(committee_size - 1) / 2` to `(committee_size - 1) / 3` to match the module's own documented 2f+1-of-3f+1 model; a regression table asserts `recommended_max_faulty(4)==1`, `(7)==2`, `(10)==3`, `(13)==4`.
- [x] **BFT-02**: A round with a correctly sized `3f+1` committee still reaches `commits.len() == committee.threshold()` after excluding the maximum tolerable number of Byzantine members; today `ConsensusCommittee::threshold()` never shrinks after `exclude_sender`, so ejecting one bad actor can strand a round below its own threshold, and the existing Byzantine test never asserts the round still commits.
- [~] **BFT-03**: `simulate_governance_commit` (at `crates/swarm-agents/src/tom_agent.rs:1132` after phase 282, which today takes `governors: &BTreeMap<AgentId, SigningKey>`, holding every governor's private key in one process — note this describes the TYPE, not the deployed topology: production registers exactly one governor, so `state.governors.len() == 1` and every multi-key invocation is from tests) is removed from the production path; governors exchange `ConsensusSignedEnvelope` over the pheromone substrate, and no production path holds more than one governor's key in memory.
  PARTIAL 2026-08-14: the single-key half is DONE and structural — `GovernancePolicy` holds `local_governor: Option<LocalGovernorKey>` (no `SigningKey` accessor, custom `Debug` that never renders the private half) plus identity-only `peer_governors`; `simulate_governance_commit` and `collect_signed_progress` are DELETED, not moved behind `#[cfg(test)]`; and `tools/check-single-governor-key.sh` is wired into CI so a regression fails the build.
  DEFERRED: the "governors exchange `ConsensusSignedEnvelope` over the pheromone substrate" clause is NOT satisfied. What landed is the transport seam plus `SoloGovernorTransport`, which REFUSES a multi-member committee. Deliberate, to avoid pre-empting v1.83's VRF-02, which replaces `proposer_for` outright. See ROADMAP phase 321 criterion 5 and `docs/CONSENSUS.md`, both of which already say so — this ledger line was the one place the deferral was invisible.
- [~] **BFT-04**: `GovernancePolicy::can_act` drives authorization through the networked round while preserving the existing `GovernanceDecision::{Allow, Veto}` API and receipt shape, so `dispatcher.rs` and the documented receipt-backed flow are unchanged for callers.
  PARTIAL 2026-08-13, with the split stated at ROADMAP phase 321 criterion 5. The round is driven through a transport seam and one locally owned node; the transport that ships is solo-only and refuses multi-member committees, so the round is not yet networked. Note for whoever finishes it: `dispatcher.rs` never calls `can_act` (zero occurrences), so "callers unchanged" is a claim about the serialized receipt shape, which is pinned by a test, and NOT about `can_act`'s signature. Networking the round makes `can_act` async, which touches its 10 call sites and surfaces a confusing `MutexGuard`-across-`await` error at `PounceAgent::tick` rather than at `can_act`, because `SwarmAgent` is `#[async_trait]` without `?Send`.
- [x] **BFT-05**: A seeded message-loss and delay harness proves commit completes within `round_timeout_ms * (max_faulty + 1)` in the common case, and the phase states explicitly which fault classes it did not exercise.
  CORRECTION 2026-08-13: "in the common case" names no precondition, and the bound is not a property of this implementation. It presumes proposer rotation reaches a correct proposer within f+1 rounds; `ConsensusCommittee::proposer_for` is an independent per-round argmax, not a permutation, so f+1 consecutive faulty proposers are reachable and the corpus contains 5 such episodes out of 192. The harness therefore publishes the measured distribution and asserts only the conditional version. Read this requirement as satisfied by MEASUREMENT, not by proof; VRF-02 (phase 301) is the requirement that makes the unconditional bound assertable.

#### VRF Committee Selection

- [ ] **VRF-01**: `crates/swarm-consensus/src/vrf.rs` implements ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) over the existing Ed25519 keys, with prove and verify.
- [ ] **VRF-02**: An eligible-governor pool sourced from the identity registry computes each epoch's committee by VRF output, replacing "every registered governor is permanently seated"; today `proposer_for` derives the leader from `sha256` over the public previous-commit hash and public member list, so the entire future schedule is precomputable by anyone.
- [ ] **VRF-03**: An epoch-scoped committee wraps `ConsensusCommittee`, and the governance receipt payload gains an `epoch` field recording which committee authorized each commit.
- [ ] **VRF-04**: `runtime.governance_epoch_duration_ms` drives rotation; a test proves epoch N+1 membership cannot be derived from public data alone without candidate private keys.
- [ ] **VRF-05**: Single-governor bootstrap mode degenerates to a no-op selection and existing single-instance governance tests pass unmodified.

#### Key Rotation And Revocation

- [ ] **REVOKE-01**: `revoke_identity(agent_id, evidence, quorum_receipt)` is authorized by a quorum-signed receipt and does not require the revoked identity's cooperation, unlike `rotate_identity` which requires the retiring key to co-sign its own continuity proof.
- [ ] **REVOKE-02**: `is_admitted` returns false immediately after revocation while historical signature verification against the retired key still succeeds.
- [ ] **REVOKE-03**: `swarmctl identity revoke` fails closed with no partial registry mutation when quorum co-signature cannot be obtained.
- [ ] **REVOKE-04**: An in-protocol exclusion receipt updates the identity registry mid-epoch; a test proves an excluded member cannot be VRF-selected into the next epoch.
- [ ] **REVOKE-05**: Interleaved rotate and revoke calls keep the continuity-proof and retired-identity history consistent.

#### Fail-Closed Contract Preservation

- [ ] **DISTGOV-01**: Every row of the documented partition and recovery rules table has a passing integration test against the new VRF-rotated networked committee; the single-operator boundary language is preserved.
- [ ] **DISTGOV-02**: Leases and reconciliation reports gain epoch provenance; a lease issued by epoch N remains redeemable after epoch N+1 rotates the signers, without weakening blast-radius or TTL checks.
- [ ] **DISTGOV-03**: Quorum loss mid-epoch-transition falls back to the last-confirmed committee rather than seating a half-formed one; the scenario is handed to v1.81's TLA+ model as an extension rather than modeled twice.
- [ ] **DISTGOV-04**: Governance status and the health endpoints report current epoch, committee size, and time to next rotation, including eligible-pool exhaustion below `3f+1`.

### Herd Immunity (v1.84)

#### Historical Reversible Quarantine Execution (Phase 320; completed in v1.78.1)

- [x] **QRT-01**: `crates/swarm-response` gains a real executor for `QuarantineFile`, `SuspendProcess`, `IsolateHost`, and `TerminateUserSession` that persists a quarantine lease carrying blast radius, rollback plan, governance receipt, and expiry.
  UNCHECKED 2026-08-13, was marked `[x]` in error. 4d03543 added the TYPES (`ContainmentLease`, `ContainmentLedger`, `RollbackExecutor`, `RollbackReceipt`) and nothing that uses them: `rg -l 'ContainmentLease|ContainmentLedger|RollbackExecutor|RollbackReceipt|RollbackTrigger'` returns exactly `crates/swarm-response/src/lib.rs` (the re-export at :35-38) and `crates/swarm-response/src/rollback.rs` (the definitions plus their own `#[cfg(test)]` tests). Zero production code constructs a lease, so "persists a quarantine lease" is unmet for all four actions. The original trailing clause ("no rollback executor exists anywhere in `swarm-response`, verified: zero non-preview rollback references") was true before 4d03543 and is now false; the accurate measurement is that rollback types exist and are constructed only in tests.
  RECHECKED 2026-08-13 (later, phase 320 wave 1): now `[x]`. `SwarmRuntime::record_containment_lease` (`crates/swarm-runtime/src/lib.rs`) opens a lease on both success paths — `authorize_and_execute` and `audit_authorize_and_execute_instrumented_internal`, which is where the human-approved and dispatcher routes converge — for all four actions. The lease carries the blast radius AND the rollback plan from one `build_rehearsal_preview` derivation, the governance receipt id from `verified_governance_receipt`, the TYPED `ResponseAction`, and a mandatory expiry. `ContainmentLease::open` is the only constructor; `ContainmentTtl(NonZeroI64)` has no value meaning "no expiry"; the persisted form re-checks the bound in `TryFrom`, so a hand-edited stored lease with no expiry fails to parse.
- [x] **QRT-02**: The rollback executor performs the concrete inverse action per rollback step kind and emits a rollback receipt chained to the original governance receipt id.
  UNCHECKED 2026-08-13, was marked `[x]` in error, and RENAMED: there is no symbol `execute_rollback` anywhere in the tree (`rg execute_rollback` -> 0 hits). The shipped API is the trait method `RollbackExecutor::rollback` at `crates/swarm-response/src/rollback.rs:110`. Half of this is real and half is not: the receipt chaining exists (`origin_receipt_id` at rollback.rs:165), but `SandboxRollbackExecutor::rollback` (rollback.rs:126-179) never branches on `ResponseRollbackStepKind` — it copies `step.kind` into the outcome and performs no side effect at all. There is no adapter-backed rollback executor.
  Two constraints for the implementer, both measured: `CrowdStrikeRtrAdapter::execute` (crowdstrike_rtr.rs:453-481) handles only `IsolateHost`, `KillProcess` and `QuarantineFile`, so `SuspendProcess` and `TerminateUserSession` hit `unsupported_receipt` and cannot be reversed on a CrowdStrike deployment. And `TerminateUserSession`'s inverse is not an inverse — `service/preview.rs:295-305` says outright "the terminated session cannot be resumed" — so `RollbackReceipt::fully_reversed()` would overclaim for it.
  RECHECKED 2026-08-13 (later, phase 320 wave 1): now `[x]`, with both constraints above HONOURED rather than papered over. `resolve_inverse(action, step_kind)` is the single mapping from a plan step plus the lease's typed action to an addressable `ContainmentInverse`; `HttpEdrRollbackExecutor` issues it against the same endpoint `HttpEdrAdapter` used. Proven against a stateful fake EDR that holds a set of contained targets, so the assertion is on the EFFECT and not on the receipt.
  `TerminateUserSession` resolves to `InverseGap::Irreversible`, not to an inverse, and `fully_reversed()` is now "every step actually restored" — so it is false for that action, false for a simulated rollback, and false for an adapter with no mapping. CrowdStrike and webhook deployments get `SandboxRollbackExecutor` from `rollback_executor_from_config`, whose receipts report `Simulated`/`Irreversible`; wiring a real CrowdStrike inverse is open follow-up.
- [x] **QRT-03**: Every quarantine lease carries a mandatory expiry mirroring the existing contingency-lease TTL pattern; a background sweep rolls back automatically on expiry with zero operator action.
  CHECKED 2026-08-13 (phase 320 wave 1). `crates/swarm-runtime/src/containment.rs`: `ContainmentSweep::sweep(now_ms)` takes the clock as a PARAMETER, mirroring `prune_expired_contingency_leases(state, now_ms)`; only `run_until_shutdown` reads a clock, once per tick, at the call site. `swarm_detect --serve` spawns it and awaits its handle on both shutdown arms. The boundary test is two integer literals (4_999 releases nothing, 5_000 releases), not a sleep — the anti-pattern 1c4d728 documents.
  One limit to state: with no `runtime.containment.lease_store_path` configured, leases are in memory only, so a restart or a `reload_from_disk()` orphans anything open and no sweep will ever release it. `docs/CONFIGURATION.md` says so; `rulesets/default.yaml` cannot carry the key because it is digest-signed (task #23's constraint).
- [x] **QRT-04**: `swarmctl quarantine release <lease_id>` performs manual early rollback through the same governance signing path; an integration test executes containment, verifies effect, rolls back both manually and by TTL, and verifies both receipts.
  CHECKED 2026-08-13 (phase 320 wave 2), with one DEVIATION from the requirement's wording recorded in `docs/decisions/0010-containment-release-goes-through-the-daemon.md`: `swarmctl quarantine release` is an HTTP client of a running `swarm_detect --serve`, not a local harness. Blocker (a) below is why, and a third measurement decided where the endpoint went. `LocalOperatorSurface` was ruled out as the host: it builds its own `DefaultControlPlane` in its own process, so `containment_binding_from_config` hands it a SECOND `MemoryContainmentLeaseStore` whenever `runtime.containment.lease_store_path` is unset — the shipped default, since `rulesets/default.yaml` is digest-signed and cannot carry the key. A release route there would have answered "no open containment lease `x`" for every lease the daemon held. With a path configured it is worse: `FileContainmentLeaseStore`'s `locked()` is a per-process `std::sync::Mutex`, so two processes closing leases lose each other's closed receipts. The routes are therefore defined in `crates/swarm-runtime-http/src/http/containment.rs` (operator bearer auth, `OperatorScope::Maintenance`, operator API schema-version header) and mounted by `swarm_detect` onto its own listener, so the daemon is the one writer to the lease store AND to the governance chain.
  ONE FUNCTION, TWO TRIGGERS, STRUCTURALLY. `ContainmentSweep` now carries the governance authority as a FIELD, so `ContainmentSweep::release` (manual) and `ContainmentSweep::sweep` (TTL) read the same store, executor, mode and authority, and both call `swarm_runtime::containment::release_lease`. Manual and automatic differ in one argument, the `RollbackTrigger`. `swarm_detect` builds ONE `Arc<ContainmentSweep>` and gives it to both the TTL task and the router.
  SIGNING IS THE SAME PATH, AND THE TEST PROVES IT RATHER THAN ASSERTING IT. `GovernanceAuthority` gained `attest_release` (ADR 0010 states why the seal's bar is met: opaque `serde_json::Value` in and out, so no `swarm-consensus` edge is added to the TCB crate `swarm-policy`; no authorization verdict; still exactly one implementer). `GovernancePolicy::attest_release` holds the same mutex, keyring, `simulate_governance_commit`, `previous_commit_hash`, `receipt_counter` and `persist_locked` as `issue_governance_receipt`. The integration test asserts the TTL release's attestation names the MANUAL release's `commit_hash` as its `previous_commit_hash` — one chain, which a second signer could not produce.
  TAMPERING IS REFUSED BY TWO INDEPENDENT CHECKS. `verify_release_attestation` checks the ed25519 detached signature via `ConsensusGovernanceReceipt::verify` AND that the attestation's `proposal_id` equals `sha256(canonical(receipt-with-attestation-cleared))`. Measured with the second check disabled: a receipt whose `steps[0].status` was rewritten `Reversed` -> `Failed` verified against a genuine signature. Nine single-field mutations, a stripped attestation, and a genuine attestation lifted from a different release are each refused with a distinct error.
  A THIRD CHECK LANDED 2026-08-14 (task #27, ADR 0011), and the two above did not cover what it covers. Both were closed over the receipt -- the signature is verified against `signature.public_key_hex`, a FIELD OF THE RECEIPT -- so a full re-attestation passed: measured on cf48f7a, a receipt whose `steps[0].status` was rewritten `Reversed` -> `Failed` and then re-signed end to end by `SigningKey::from_bytes(&[251; 32])` verified `Ok`. `verify_release_attestation` now also requires the signing key to be one of `GovernanceAuthority::governor_public_keys()`, and refuses (rather than falling back) when no authority is available. `attestation_verified: true` on the release route therefore now means "a governor this process recognizes signed this exact body". Chain linkage remains unchecked; see ADR 0011's Consequences.
  Six mutants were run against the suite and each was caught: dropping `.with_governance(..)`; disabling the subject binding; letting an unattested receipt through; attesting only the expiry trigger; moving the expiry predicate by 1s (caught by the 5_999/6_001 boundary); and closing a lease whose inverse reported `Failed`.
  Open follow-up, not blocking: the routes are unavailable when the daemon is down, and `LocalOperatorSurface` still has none. Both are consequences recorded in ADR 0010.
  The original deferral note, kept for the record:
  NOT STARTED, and deliberately deferred 2026-08-13 rather than attempted. Manual release EXISTS as `ContainmentSweep::release`, and it is the same `release_lease` function the TTL sweep calls — a test asserts both triggers reach the executor in order with the instant each was told to act at. What is missing is the CLI surface and the governance SIGNATURE on the rollback receipt. Two measured blockers:
  (a) SPLIT-BRAIN GOVERNANCE STATE. `swarmctl quarantine release` and a running `swarm_detect --serve` would both open `data/governance-partition-state.json`. `GovernancePersistence::save` (tom_agent.rs:305-317) is tmp-write + rename with NO lock and the daemon holds `previous_commit_hash`/`receipt_counter` in memory, so a CLI release while the daemon runs forks the receipt chain. Shipping a silent fork of an audit chain is worse than shipping no CLI. Needs a decision: advisory lock the daemon takes and the CLI fails closed against, or route the CLI through the operator HTTP surface when a daemon is up.
  (b) `crates/swarm-cli/Cargo.toml` depends on core, crypto, evolution, ingest-runtime, runtime, runtime-http and runtime-workbench — NOT swarm-agents, swarm-response or swarm-policy. `GovernancePolicy`/`register_governor` and `FileContainmentLeaseStore` are unreachable from `core.inc`, which is `#[path]`-included into two crates and today names exactly one external crate path.
  Signing also requires widening the sealed `swarm_policy::governance::GovernanceAuthority` trait, because `swarm-agents` depends on `swarm-runtime` and the runtime cannot name `GovernancePolicy`. That widening is justifiable but its doc comment states the bar, so it wants an ADR and a reviewer, not a drive-by.

#### Information-Flow Control

- [ ] **IFC-01**: The knowledge graph gains a data-flow edge kind and a taint label carrying source indicator, confidence, first-observed timestamp, and provenance chain.
- [ ] **IFC-02**: `propagate_taint` walks causal and data-flow edges computing a decaying taint score whose half-life mirrors the pheromone default, reusing Sphinx's existing GC rather than adding a second retention path.
- [ ] **IFC-03**: Detector confidence is boosted by an active taint label's decayed score, capped at 1.0, with the propagation chain recorded on the finding.
- [ ] **IFC-04**: The policy gate fails closed on any containment proposal whose target has taint provenance but no independent detection corroboration, so taint raises scrutiny but never singlehandedly authorizes destructive response.

#### Cross-Instance Immunity Sharing

- [ ] **HERD-01**: An immunity record carrying threat class, indicator pattern, confirming instance, evidence, and signature publishes to the existing JetStream substrate, reusing proven multi-instance replication rather than inventing gossip.
- [ ] **HERD-02**: A receiving instance never auto-applies a peer's record; adoption requires the indicator to independently match a locally observed finding or replay-corpus entry, with the no-single-publisher invariant stated in the module doc.
- [ ] **HERD-03**: Adopted updates stage through a per-instance canary soak; a false-positive spike reverts that instance only, affecting neither the publisher nor other subscribers.
- [ ] **HERD-04**: A three-instance integration test proves a corroborating peer adopts, a non-corroborating peer does not, and a fabricated record injected directly is rejected by both.

#### Adaptive Deception Depth

- [ ] **DECOY-01**: Deception playbook entries gain a fidelity tier; interactive and stateful decoys return believable payloads rather than bare tripwires.
- [ ] **DECOY-02**: Decoy placement adapts toward zones adjacent to recently tainted entities, with the repo-owned playbook remaining the floor so placement never leaves operator-approved zones.
- [ ] **DECOY-03**: Higher-fidelity decoy engagement seeds proportionally stronger taint, producing higher-confidence containment candidates.
- [ ] **DECOY-04**: A full-loop integration test proves decoy interaction to taint propagation to receipt-backed quarantine to automatic rollback to immunity publication to corroborated peer adoption, serving as the milestone's executor rather than an attested claim.

### The Detection Commons (v1.85)

#### Normative Spec

- [ ] **SPEC-01**: `spec/README.md` gives three named reading orders (Implementer, Auditor, SDK author), each citing `spec/PROTOCOL.md`, `spec/PHEROMONE.md`, `spec/RECEIPT-CHAIN.md`, and `spec/WIRE.md` by path, under one shared v1 banner.
- [ ] **SPEC-02**: `spec/PHEROMONE.md` normatively specifies every `PheromoneDeposit` field including the schema-version compatibility window; `spec/RECEIPT-CHAIN.md` specifies the envelope, chain linkage, checkpoint, and Merkle proof; `spec/WIRE.md` specifies only the stable external HTTP subset, explicitly excluding operator-internal routes.
- [ ] **SPEC-03**: `spec/schemas/` ships JSON Schema for the deposit, envelope, chain-link verdict, and one wire body; a CI test serializes real runtime-produced values and validates them against the checked-in schemas so schema and Rust type cannot drift.

#### External Conformance Suite

- [ ] **CONFORM-01**: `swarmctl conformance-package` bundles all 19 scenarios, all 3 suites, the default ruleset, and pinned expected verdicts into a checksummed archive an external implementer can verify without cloning the monorepo.
- [ ] **CONFORM-02**: `swarmctl conformance-verify <package>` drives replay and evaluation for every packaged scenario and exits non-zero on verdict mismatch; `--evidence` additionally verifies every exported receipt and fails closed.
- [ ] **CONFORM-03**: A CI job builds the package and verifies against that fresh build as a round-trip self-check; `docs/CONFORMANCE.md` documents the flow in commands runnable without repo access.

#### Detector-Authoring SDK

- [ ] **SDK-01**: `crates/swarm-detector-sdk` exposes the minimal detector-authoring surface depending only on `swarm-core`, with a CI dependency check proving no `swarm-runtime`, axum, hyper, reqwest, or OpenTelemetry entry.
- [ ] **SDK-02**: `examples/hello-detector/` ships a detector authored purely against the SDK, a ruleset entry, and a smoke script that runs `swarmctl first-run` and prints an emitted deposit and a verified receipt id.
- [ ] **SDK-03**: `tools/run-hello-smokes.sh` is the single CI entry point for the hello-example family; `spec/SDK.md` states SDK-to-schema-version compatibility.

#### Generated Coverage And Adopter IA

- [ ] **COVDOC-01**: `tools/gen-coverage-doc` generates `docs/security/detection-coverage.md` from `rulesets/evasion/attack-technique-catalog.yaml`, reproducing each intentionally-uncovered technique and rationale verbatim, idempotent and stamped as generated.
- [ ] **COVDOC-02**: A `--check` mode fails CI when the generated doc is stale, wired into the documented contributor gate.
- [ ] **COVDOC-03**: `docs/README.md` provides four role-indexed reading orders; `README.md` and `spec/README.md` each point at `docs/REFERENCE-STATUS.md` as the qualified-claims gate separating aspirational narrative from shipped contract.

### Federation (v1.86)

#### Cross-Operator Evidence Exchange

- [ ] **FEDX-01**: `crates/swarm-federation` defines an evidence-exchange envelope wrapping one existing signed spine envelope plus exporting-operator provenance, with no embedded local paths, hostnames, or store internals.
- [ ] **FEDX-02**: Verification uses only signature checking plus existing chain and checkpoint verification with zero network calls, returning the same verdict taxonomy so import fails closed exactly like local verification.
- [ ] **FEDX-03**: `swarmctl federation export` and `import` round-trip a self-contained directory with no server; the format conforms to the v1.85 normative spec rather than inventing its own.
- [ ] **FEDX-04**: Federation config defaults to disabled so the feature is strictly opt-in per operator.

#### Local Activation Boundary

- [ ] **LOCACT-01**: Deposits gain federated-peer provenance with a distinct lower base weight, so every deposit is tagged by origin.
- [ ] **LOCACT-02**: An audited proof plus named test establishes that no code path lets federated evidence alone satisfy the conditions checked before issuing a governance receipt.
- [ ] **LOCACT-03**: An integration test imports a maximal-severity federated envelope with zero corroborating local telemetry and asserts no dispatch, no signed receipt, and only an advisory-received audit event; this is the regression test for the anti-single-publisher property.
- [ ] **LOCACT-04**: The architecture and consensus docs replace the blanket "multi-operator governance plane is deferred" line with the precise new boundary: exchange exists, activation stays local, and the governance-mode table gains no new row.

#### Reputation And Anti-Equivocation

- [ ] **FEDREP-01**: Peer reputation is computed purely locally from that peer's own prior-import outcomes, with no shared registry or global score.
- [ ] **FEDREP-02**: Peer admission is bilateral and locally signed; a peer below the configured minimum reputation is demoted to advisory-only weight zero without deleting history, producing a signed audit event.
- [ ] **EQUIV-01**: Conflicting checkpoint statements for the same log and sequence from the same issuer produce independently re-verifiable equivocation evidence, detectable from locally held imports with no central witness.
- [ ] **EQUIV-02**: Confirmed equivocation revokes the issuer locally and is exportable so other operators can verify the same proof independently.

#### Privacy-Preserving Sharing

- [ ] **FEDPRIV-01**: A redaction layer pseudonymizes hostnames, usernames, and internal addresses with keyed pseudonyms stable within one export relationship but not reversible by the receiver.
- [ ] **FEDPRIV-02**: An explicit allowlist defines which detection-relevant fields may cross the boundary; export fails closed on any field not on the list.
- [ ] **FEDPRIV-03**: `--dry-run` prints the exact redacted payload for operator review before any signed package is written; the docs enumerate every infrastructure-identifying field class and its handling.
- [ ] **FEDPRIV-04**: A CI test exports a fixture containing known hostnames, usernames, and internal CIDRs and asserts none of those literal byte strings appear anywhere in the exported package, plus a documented pseudonym rotation path bounding long-term linkability.

### Fleet Scale (v1.87)

#### Sharded Substrate And Horizontal Scale

- [ ] **SHARD-01**: The JetStream backend gains a documented deterministic shard function mapping telemetry onto one of N streams, replacing the current single-bucket design, with stable assignment across restarts.
- [ ] **SHARD-02**: The Helm chart supports N runtime pods each claiming a disjoint shard set via a startup lease, with per-shard readiness shedding so one hot shard sheds independently.
- [ ] **SHARD-03**: A fleet benchmark reruns the existing fixed and ramp-to-shed profiles at N=1, 3, and 10 concurrent instances, publishing measured throughput and first shed point per N; no capacity number is asserted without a rerun.

#### Fleet-Wide Blast Radius And Tenant Isolation

- [ ] **FCAP-01**: `runtime.fleet_blast_radius_cap` is added, distinct from the existing per-instance `partition_contingency_blast_radius_cap`, and fails config validation fail-closed at zero.
- [ ] **FCAP-02**: A durable fleet ledger tracks cumulative destructive actions across instances and denies further action once the cap is reached, even when an individual instance's own quorum would approve; ledger unavailability fails closed for response while health endpoints stay observable.
- [ ] **TENANT-01**: Config resolves per-tenant policy and detector thresholds with no cross-tenant leakage, proven by a test that tenant A's resolved policy never reflects tenant B's values.
- [ ] **TENANT-02**: Identity admission and receipt persistence are partitioned per tenant with separate chain roots; a replay or query scoped to one tenant never returns another's records on the shared substrate.

#### Fleet Operational Maturity

- [ ] **FLEETOPS-01**: Fleet-scale alert baselines are added, every threshold traceable to a measured row in the fleet benchmark rather than assumed.
- [ ] **FLEETOPS-02**: The DR runbook gains a fleet upgrade and rollback drill preserving shard assignment and ledger state across a rolling upgrade.
- [ ] **FLEETOPS-03**: A capacity-model doc states the fleet-sizing method and requires a benchmark rerun on the target host before any capacity number is treated as valid.
- [ ] **FLEETOPS-04**: Metrics series gain instance and shard labels so fleet-wide aggregation works without a new metrics system.

#### Signed Release Supply Chain

- [ ] **RELSIGN-01**: The release workflow inherited from the v1.74-v1.77 branch is extended to publish multi-arch container images on tag push, and its coverage is reconciled against the `RELEASE-01` requirement currently marked Complete.
- [ ] **RELSIGN-02**: Published images are signed with keyless signing, and a required check verifies the signature before the release is marked complete.
- [ ] **RELSIGN-03**: SBOM and provenance attestation attach to the release artifact and become required fields in the recovery evidence packet for any live-response deployment.
- [ ] **RELSIGN-04**: Signature verification blocks deployment mechanically for fleets running live response, extending the existing startup attestation to the container supply chain rather than relying on a runbook instruction an operator can skip.

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
| DEFAULTS-01 | Phase 268 | Complete |
| DEFAULTS-02 | Phase 268 | Complete |
| OPEXP-01 | Phase 268 | Complete |
| OPEXP-02 | Phase 268 | Complete |
| DEPLOY-01 | Phase 269 | Complete |
| DEPLOY-02 | Phase 269 | Complete |
| EMULATION-01 | Phase 270 | Complete |
| EMULATION-02 | Phase 270 | Complete |
| EMULATION-03 | Phase 270 | Complete |
| DEPLOY-03 | Phase 271 | Complete |
| THREATINTEL-01 | Phase 272 | Complete |
| THREATINTEL-02 | Phase 272 | Complete |
| THREATINTEL-03 | Phase 272 | Complete |
| CLOUDBR-01 | Phase 273 | Complete |
| CLOUDBR-02 | Phase 273 | Complete |
| CLOUDBR-03 | Phase 273 | Complete |
| CLOUDDET-01 | Phase 274 | Complete |
| CLOUDDET-02 | Phase 275 | Complete |
| CLOUDDET-03 | Phase 275 | Complete |
| EDRINT-01 | Phase 276 | Complete |
| EDRINT-02 | Phase 276 | Complete |
| EDRINT-03 | Phase 276 | Complete |
| SIEMINT-01 | Phase 277 | Complete |
| SIEMINT-02 | Phase 277 | Complete |
| SIEMINT-03 | Phase 277 | Complete |
| E2EPROOF-01 | Phase 278 | Complete |
| E2EPROOF-02 | Phase 278 | Complete |
| E2EPROOF-03 | Phase 279 | Complete |
| GATEFIX-01 | Phase 280 | Satisfied |
| GATEFIX-02 | Phase 280 | Satisfied |
| GATEFIX-03 | Phase 280 | Satisfied |
| GATEFIX-04 | Phase 280 | Satisfied |
| INCFIX-01 | Phase 281 | Satisfied |
| INCFIX-02 | Phase 282 | Pending |
| INCFIX-03 | Phase 281 | Satisfied |
| SPLIT-01 | Phase 282 | Pending |
| SPLIT-02 | Phase 282 | Pending — workbench delivered (4,064 LOC), replay not; 8,142 LOC remain, blocked on SEAM-03 (2026-08-13, task #14) |
| SPLIT-03 | Phase 282 | Pending — 5 of 8 roles delivered; 3 remain (8,932 LOC), mutually blocked with SPLIT-04 (2026-08-13, task #14) |
| SPLIT-04 | Phase 282 | Pending — 4 of 11 modules delivered (7,067 LOC); 7 remain (31,860 LOC), blocked on SEAM-01 AND SEAM-02 (2026-08-13, task #14) |
| SPLIT-05 | Phase 282 | Pending |
| SPLIT-06 | Phase 282 | Pending — both numeric clauses SUPERSEDED 2026-08-13 (task #14): 25,000 unreachable (measured floor 31,681), 20,000 self-contradicted (38,927); re-derive from the A/B/C condensation |
| TCBOUND-01 | Phase 283 | Satisfied 2026-08-13 as `docs/decisions/0009-...` (stale `docs/adr/` path corrected) |
| TCBOUND-02 | Phase 283 | Satisfied 2026-08-13 — all six crates measured to exist; sections enforced by RULE 5 |
| TCBOUND-03 | Phase 283 | Satisfied 2026-08-13 as `tools/check-workspace-layering.sh` (stale `scripts/` path corrected) |
| TCBOUND-04 | Phase 283 | Satisfied 2026-08-13 — fixture runs on every invocation, 1 control + 9 broken variants |
| FIXTURE-01 | Phase 284 | Satisfied |
| FIXTURE-02 | Phase 284 | Satisfied |
| FIXTURE-03 | Phase 284 | Satisfied |
| FIXTURE-04 | Phase 284 | Satisfied |
| ASSURE-01 | Phase 285 | Satisfied (revised scope) |
| ASSURE-02 | Phase 285 | Satisfied (revised scope) |
| ASSURE-03 | Phase 285 | Satisfied (revised scope) |
| ASSURE-04 | Phase 285 | Satisfied (revised scope) |
| ASSURE-05 | Phase 285 | Satisfied (external App enforcement deferred) |
| ASSURE-06 | Phase 285 | Satisfied (scope verification only) |
| COG-01 | Phase 286 | Pending |
| COG-02 | Phase 286 | Pending |
| COG-03 | Phase 286 | Pending |
| COG-04 | Phase 286 | Pending |
| COG-05 | Phase 286 | Pending |
| COG-06 | Phase 286 | Pending |
| COG-07 | Phase 286 | Pending |
| COG-08 | Phase 286 | Pending |
| ARENA-01 | Phase 287 | Pending |
| ARENA-02 | Phase 287 | Pending |
| ARENA-03 | Phase 287 | Pending |
| ARENA-04 | Phase 287 | Pending |
| ARENA-05 | Phase 287 | Pending |
| ARENA-06 | Phase 287 | Pending |
| ARENA-07 | Phase 287 | Pending |
| ARENA-08 | Phase 287 | Pending |
| SYNTH-01 | Phase 288 | Pending |
| SYNTH-02 | Phase 288 | Pending |
| SYNTH-03 | Phase 288 | Pending |
| SYNTH-04 | Phase 288 | Pending |
| SYNTH-05 | Phase 288 | Pending |
| SYNTH-06 | Phase 288 | Pending |
| HERDMEM-01 | Phase 289 | Pending |
| HERDMEM-02 | Phase 289 | Pending |
| HERDMEM-03 | Phase 289 | Pending |
| HERDMEM-04 | Phase 289 | Pending |
| HERDMEM-05 | Phase 289 | Pending |
| HERDMEM-06 | Phase 289 | Pending |
| DCORE-01 | Phase 292 | Pending |
| DCORE-02 | Phase 292 | Pending |
| DCORE-03 | Phase 292 | Pending |
| DCORE-04 | Phase 292 | Pending |
| DCORE-05 | Phase 292 | Pending |
| KANI-01 | Phase 293 | Pending |
| KANI-02 | Phase 293 | Pending |
| KANI-03 | Phase 293 | Pending |
| KANI-04 | Phase 293 | Pending |
| KANI-05 | Phase 293 | Pending |
| SAFEP-01 | Phase 292 | Pending |
| SAFEP-02 | Phase 292 | Pending |
| SAFEP-03 | Phase 292 | Pending |
| SAFEP-04 | Phase 292 | Pending |
| SAFEP-05 | Phase 292 | Pending |
| ZGATE-01 | Phase 322 | Satisfied |
| ZGATE-02 | Phase 322 | Satisfied |
| ZGATE-03 | Phase 322 | Satisfied |
| ZGATE-04 | Phase 322 | Satisfied |
| ZGATE-05 | Phase 322 | Satisfied |
| GRAPH-01 | Phase 296 | Pending |
| GRAPH-02 | Phase 296 | Pending |
| GRAPH-03 | Phase 296 | Pending |
| GRAPH-04 | Phase 296 | Pending |
| GRAPH-05 | Phase 296 | Pending |
| GRAPH-06 | Phase 296 | Pending |
| CHAIN-01 | Phase 297 | Pending |
| CHAIN-02 | Phase 297 | Pending |
| CHAIN-03 | Phase 297 | Pending |
| CHAIN-04 | Phase 297 | Pending |
| XHUNT-01 | Phase 298 | Pending |
| XHUNT-02 | Phase 298 | Pending |
| XHUNT-03 | Phase 298 | Pending |
| XHUNT-04 | Phase 298 | Pending |
| TRIAGE-01 | Phase 299 | Pending |
| TRIAGE-02 | Phase 299 | Pending |
| TRIAGE-03 | Phase 299 | Pending |
| TRIAGE-04 | Phase 299 | Pending |
| TRIAGE-05 | Phase 299 | Pending |
| BFT-01 | Phase 321 | Satisfied |
| BFT-02 | Phase 321 | Satisfied |
| BFT-03 | Phase 321 | Partial (single-key done; substrate exchange deferred) |
| BFT-04 | Phase 321 | Partial (transport seam only; solo transport refuses multi-member) |
| BFT-05 | Phase 321 | Satisfied (bound NOT asserted; measured distribution published instead) |
| VRF-01 | Phase 301 | Pending |
| VRF-02 | Phase 301 | Pending |
| VRF-03 | Phase 301 | Pending |
| VRF-04 | Phase 301 | Pending |
| VRF-05 | Phase 301 | Pending |
| REVOKE-01 | Phase 302 | Pending |
| REVOKE-02 | Phase 302 | Pending |
| REVOKE-03 | Phase 302 | Pending |
| REVOKE-04 | Phase 302 | Pending |
| REVOKE-05 | Phase 302 | Pending |
| DISTGOV-01 | Phase 303 | Pending |
| DISTGOV-02 | Phase 303 | Pending |
| DISTGOV-03 | Phase 303 | Pending |
| DISTGOV-04 | Phase 303 | Pending |
| QRT-01 | Phase 320 | Satisfied |
| QRT-02 | Phase 320 | Satisfied |
| QRT-03 | Phase 320 | Satisfied |
| QRT-04 | Phase 320 | Satisfied |
| IFC-01 | Phase 305 | Pending |
| IFC-02 | Phase 305 | Pending |
| IFC-03 | Phase 305 | Pending |
| IFC-04 | Phase 305 | Pending |
| HERD-01 | Phase 306 | Pending |
| HERD-02 | Phase 306 | Pending |
| HERD-03 | Phase 306 | Pending |
| HERD-04 | Phase 306 | Pending |
| DECOY-01 | Phase 307 | Pending |
| DECOY-02 | Phase 307 | Pending |
| DECOY-03 | Phase 307 | Pending |
| DECOY-04 | Phase 307 | Pending |
| SPEC-01 | Phase 308 | Pending |
| SPEC-02 | Phase 308 | Pending |
| SPEC-03 | Phase 308 | Pending |
| CONFORM-01 | Phase 309 | Pending |
| CONFORM-02 | Phase 309 | Pending |
| CONFORM-03 | Phase 309 | Pending |
| SDK-01 | Phase 310 | Pending |
| SDK-02 | Phase 310 | Pending |
| SDK-03 | Phase 310 | Pending |
| COVDOC-01 | Phase 311 | Pending |
| COVDOC-02 | Phase 311 | Pending |
| COVDOC-03 | Phase 311 | Pending |
| FEDX-01 | Phase 312 | Pending |
| FEDX-02 | Phase 312 | Pending |
| FEDX-03 | Phase 312 | Pending |
| FEDX-04 | Phase 312 | Pending |
| LOCACT-01 | Phase 313 | Pending |
| LOCACT-02 | Phase 313 | Pending |
| LOCACT-03 | Phase 313 | Pending |
| LOCACT-04 | Phase 313 | Pending |
| FEDREP-01 | Phase 314 | Pending |
| FEDREP-02 | Phase 314 | Pending |
| EQUIV-01 | Phase 314 | Pending |
| EQUIV-02 | Phase 314 | Pending |
| FEDPRIV-01 | Phase 315 | Pending |
| FEDPRIV-02 | Phase 315 | Pending |
| FEDPRIV-03 | Phase 315 | Pending |
| FEDPRIV-04 | Phase 315 | Pending |
| SHARD-01 | Phase 316 | Pending |
| SHARD-02 | Phase 316 | Pending |
| SHARD-03 | Phase 316 | Pending |
| FCAP-01 | Phase 317 | Pending |
| FCAP-02 | Phase 317 | Pending |
| TENANT-01 | Phase 317 | Pending |
| TENANT-02 | Phase 317 | Pending |
| FLEETOPS-01 | Phase 318 | Pending |
| FLEETOPS-02 | Phase 318 | Pending |
| FLEETOPS-03 | Phase 318 | Pending |
| FLEETOPS-04 | Phase 318 | Pending |
| RELSIGN-01 | Phase 319 | Pending |
| RELSIGN-02 | Phase 319 | Pending |
| RELSIGN-03 | Phase 319 | Pending |
| RELSIGN-04 | Phase 319 | Pending |

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
- v1.74 deferred: 10 requirements across phases 264-267 (TESTFIX-01-02 -> Phase 264; DEADCODE-01 -> Phase 264; DECOMP-01 -> Phase 265; DECOMP-02-03 -> Phase 266; EXTRACT-01-03 -> Phase 267)
- v1.75 complete: 10 requirements satisfied across phases 268-271
- v1.76 complete: 9 requirements satisfied across phases 272-275
- v1.77 complete: 9 requirements satisfied across phases 276-279 (EDRINT-01-03 -> Phase 276; SIEMINT-01-03 -> Phase 277; E2EPROOF-01-02 -> Phase 278; E2EPROOF-03 -> Phase 279)
- v1.78 complete as scoped: phases 280-283 shipped; GATEFIX-01-04 and TCBOUND-01-04 are satisfied, while phase 282's measured SPLIT remainder remains explicit rather than silently claimed
- v1.78.1 closed locally with a deliberate partial: phases 320 and 322 complete; phase 321's substrate exchange and networked round are deferred to v1.83 rather than claimed
- v1.79 active: 34 requirements across phases 284-289; Phase 285 is passed under the revised ASSURE-01..06 scope, and COG/ARENA/SYNTH/HERDMEM are accepted for implementation
- v1.80 historical only: the former OPFOR/ATKSCORE/COEVOLVE/ARMSCI block (phases 288-291) is superseded by active v1.79 ARENA/SYNTH and creates no queued acceptance set
- v1.81 queued: 15 requirements across phases 292-294 (DCORE-01-05 -> Phase 292; KANI-01-05 -> Phase 293; SAFEP-01-05 -> Phase 294)
- v1.82 queued: 19 requirements across phases 296-299 (GRAPH-01-06 -> Phase 296; CHAIN-01-04 -> Phase 297; XHUNT-01-04 -> Phase 298; TRIAGE-01-05 -> Phase 299)
- v1.83 queued: 14 requirements across phases 301-303 (VRF-01-05 -> Phase 301; REVOKE-01-05 -> Phase 302; DISTGOV-01-04 -> Phase 303)
- v1.84 queued: 12 requirements across phases 305-307 (IFC-01-04 -> Phase 305; HERD-01-04 -> Phase 306; DECOY-01-04 -> Phase 307)
- v1.85 queued: 12 requirements across phases 308-311 (SPEC-01-03 -> Phase 308; CONFORM-01-03 -> Phase 309; SDK-01-03 -> Phase 310; COVDOC-01-03 -> Phase 311)
- v1.86 queued: 16 requirements across phases 312-315 (FEDX-01-04 -> Phase 312; LOCACT-01-04 -> Phase 313; FEDREP-01-02, EQUIV-01-02 -> Phase 314; FEDPRIV-01-04 -> Phase 315)
- v1.87 queued: 15 requirements across phases 316-319 (SHARD-01-03 -> Phase 316; FCAP-01-02, TENANT-01-02 -> Phase 317; FLEETOPS-01-04 -> Phase 318; RELSIGN-01-04 -> Phase 319)

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-08-21 - Reset v1.79 around Collective Cyber Reasoning and explicitly deferred the external GitHub App enforcement gate*
