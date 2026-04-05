# Phase 81: Detection Strategy Expansion -- Context

## User Decisions

### Locked Decisions

- Four new detectors: DNS exfiltration, lateral movement, credential access, suspicious scripting
- Each detector implements the existing `DetectionStrategy` trait in swarm-whisker
- Each detector is deterministic, side-effect-free, and configurable via YAML profile (same pattern as `SuspiciousProcessTreeDetector`)
- New detectors live in swarm-whisker/src/ as separate modules
- Scenario fixtures live in scenarios/ as YAML files with MITRE ATT&CK technique tags
- TelemetryPayload enum in swarm-core gets new variants as needed (DnsQuery, RegistryAccess, etc.)

### Deferred Ideas

- ML/statistical anomaly detection -- start with deterministic rule-based detectors
- Real-time streaming ingestion -- handled in Phase 82/83
- Response adapter changes -- response behavior remains static

### Claude's Discretion

- Exact MITRE ATT&CK technique IDs for each scenario
- Specific heuristic thresholds (entropy calculations, volume thresholds)
- Whether to add `AuthenticationEvent` as a separate payload variant or reuse existing types
- Internal module organization within each detector file

## Phase Goal

The runtime can detect DNS exfiltration, lateral movement, credential access, and suspicious scripting threats through the existing DetectionStrategy trait.

## Key Interfaces

From `crates/swarm-whisker/src/detector.rs`:
```rust
pub trait DetectionStrategy: Send + Sync {
    fn id(&self) -> &str;
    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding>;
}

pub enum TelemetryPayload {
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
}
```

From `crates/swarm-core/src/pheromone.rs`:
```rust
pub enum ThreatClass {
    LateralMovement, DataExfiltration, PrivilegeEscalation,
    CommandAndControl, InitialAccess, Persistence,
    DefenseEvasion, CredentialAccess, Discovery,
    Execution, Impact, Custom(String),
}
```

From `crates/swarm-runtime/src/control.rs`:
```rust
pub enum SupportedDetector {
    SuspiciousProcessTree(SuspiciousProcessTreeDetector),
}

pub fn supported_detector(strategy: &str) -> Result<SupportedDetector, ControlError> { ... }
```

## Requirements Mapped

| Requirement | Detector | ThreatClass |
|-------------|----------|-------------|
| DET-01 | DnsExfiltrationDetector | DataExfiltration |
| DET-02 | LateralMovementDetector | LateralMovement |
| DET-03 | CredentialAccessDetector | CredentialAccess |
| DET-04 | SuspiciousScriptingDetector | Execution / DefenseEvasion |
| DET-05 | All four -- MITRE-tagged scenario fixtures with integration tests |
