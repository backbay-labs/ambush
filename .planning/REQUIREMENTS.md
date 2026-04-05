# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.26 Requirements

### Detection Breadth

- [ ] **DET-01**: swarm-whisker includes a DNS exfiltration detector that flags suspicious DNS query patterns (high entropy subdomains, excessive query volume, known tunneling signatures)
- [ ] **DET-02**: swarm-whisker includes a lateral movement detector that flags remote execution patterns (WMI, PsExec, SSH from unusual sources, RDP brute-force indicators)
- [ ] **DET-03**: swarm-whisker includes a credential access detector that flags credential dumping indicators (LSASS access, SAM registry reads, Kerberoasting patterns)
- [ ] **DET-04**: swarm-whisker includes a suspicious scripting detector that flags encoded command execution, download-and-execute chains, and living-off-the-land binary abuse

### Telemetry Ingestion

- [ ] **INGEST-01**: swarm-detect accepts telemetry events over HTTP POST (JSON) on a configurable ingest endpoint without requiring the operator workbench
- [ ] **INGEST-02**: Telemetry ingest normalizes incoming events into the existing TelemetryPayload schema with validation and rejection of malformed inputs
- [ ] **INGEST-03**: The Tetragon bridge pattern from vendor reference is ported into an active crate that can consume Tetragon gRPC events and publish normalized telemetry

### Test Coverage

- [ ] **DET-05**: Each new detector has MITRE ATT&CK-tagged scenario fixtures exercised by integration tests

## Future Requirements

### Live Response And Deployment (v1.27)

- **RESP-01**: At least two real response adapters exist behind the ResponseExecutor trait (HTTP-based EDR block/isolate, webhook-based credential revocation or escalation notification)
- **RESP-02**: Response adapters fire only after guard pipeline and policy gate approval with signed receipt
- **DEPLOY-01**: Dockerfile exists with multi-stage build for swarm-detect and swarmctl binaries
- **DEPLOY-02**: docker-compose exists for local development (runtime + optional NATS)
- **DEPLOY-03**: Health check endpoint and graceful shutdown are implemented
- **DEPLOY-04**: Policy can be reloaded at runtime without binary restart

### Durable Substrate And Multi-Instance (v1.28)

- **SUB-01**: NATS JetStream pheromone substrate backend persists deposits across restarts
- **SUB-02**: Multiple swarm-detect instances contribute deposits to shared substrate with correct concentration aggregation
- **SUB-03**: min_sources_for_escalation enforcement works correctly across multiple instances
- **CLEAN-01**: swarm-bridge (dead PyO3 shim) and kernel/ Python stubs are removed or archived

## Out of Scope

| Feature | Reason |
|---------|--------|
| eBPF program development | Tetragon provides kernel instrumentation; we consume its output, not write eBPF |
| ML/statistical anomaly detection | Start with deterministic rule-based detectors; ML detectors are future work |
| Real-time streaming ingestion (Kafka/Kinesis) | HTTP POST and gRPC are sufficient for v1.26; streaming is future |
| Distributed consensus | Still deferred until multi-instance substrate proves the need |
| LLM-powered investigation | Async lane remains deferred |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| DET-01 | — | Pending |
| DET-02 | — | Pending |
| DET-03 | — | Pending |
| DET-04 | — | Pending |
| INGEST-01 | — | Pending |
| INGEST-02 | — | Pending |
| INGEST-03 | — | Pending |
| DET-05 | — | Pending |

**Coverage:**
- v1.26 requirements: 8 total
- Mapped to phases: 0
- Unmapped: 8

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after milestone v1.26 definition*
