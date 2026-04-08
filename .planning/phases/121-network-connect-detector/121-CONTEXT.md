# Phase 121: Network Connect Detector - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a NetworkConnectDetector that evaluates TelemetryPayload::NetworkConnect events for C2 beaconing patterns, queries threat-intel for IP matches, and flags anomalous port usage. Currently zero detectors evaluate NetworkConnect events.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — infrastructure phase. Requirements define:
- NETWORK-01: Stateful detector tracking periodic connections with low jitter to same destination (C2 beaconing)
- NETWORK-02: Query threat-intel cache for destination IP matches, boost confidence on hit
- NETWORK-03: NetworkConnectProfile with suspicious_ports and process_port_allowlist for anomalous port detection

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `TelemetryPayload::NetworkConnect(NetworkConnectEvent)` in swarm-core/src/telemetry.rs (exists, never evaluated)
- `NetworkConnectEvent` with process_name, destination_ip, destination_port, protocol
- `ThreatClass::CommandAndControl` in pheromone.rs (exists, never emitted)
- `DnsExfiltrationDetector` in swarm-whisker uses stateful tracking with Arc<Mutex<HashMap<String, VecDeque<i64>>>> — same pattern needed for beaconing
- `ThreatIntelEntry` and `query_threat_intel_entry()` on PheromoneSubstrate for IP matching
- Existing profile pattern: each detector has a *Profile struct with validate()

### Integration Points
- swarm-whisker/src/ for new detector file
- detector.rs for DetectionStrategy trait
- config.rs for DetectorProfilesConfig entries
- pipeline.rs for threat-intel enrichment pattern (already does DNS/network enrichment)

</code_context>

<specifics>
## Specific Ideas

Follow DnsExfiltrationDetector's stateful tracking pattern for beaconing interval analysis.

</specifics>

<deferred>
## Deferred Ideas

- NETWORK-04 and NETWORK-05 (integration proofs) belong to Phase 123

</deferred>
