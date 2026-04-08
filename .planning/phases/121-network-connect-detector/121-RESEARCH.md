# Phase 121 Research: Network Connect Detector

## Planning Summary

Phase 121 is a detector-addition phase, not a telemetry-schema phase. `TelemetryPayload::NetworkConnect(NetworkConnectEvent)` already exists in `crates/swarm-core/src/telemetry.rs`, the composite detector runtime from Phase 120 is already live, and the runtime detection pipeline already performs threat-intel enrichment for `NetworkConnect` destination IPs in `crates/swarm-runtime/src/detection/pipeline.rs`.

The most important planning fact is that the current detector contract is synchronous and substrate-free:

- `DetectionStrategy::evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding>` in `crates/swarm-whisker/src/detector.rs`
- existing detectors are explicitly side-effect free
- substrate lookups currently happen in runtime, after detector evaluation

Because of that, the literal roadmap wording "`NetworkConnectDetector::evaluate()` queries the substrate threat-intel cache" does not fit the current architecture cleanly. The least disruptive implementation is:

- keep threat-intel lookup in `swarm-runtime/src/detection/pipeline.rs`
- make sure `NetworkConnectDetector` emits `ThreatClass::CommandAndControl` findings for network events
- prove that `detect_and_deposit()` boosts network findings on IP matches end to end

If the phase must satisfy the roadmap text literally, that is a separate interface change and should be planned consciously, not slipped in implicitly.

## What You Need To Know Before Planning

1. `NetworkConnect` telemetry is already normalized and available everywhere that matters.
   - `NetworkConnectEvent` already has `process_name`, `destination_ip`, `destination_port`, and `protocol`.
   - No schema or ingest work is required for this phase.

2. Composite strategy wiring is already complete for the live runtime.
   - `build_composite_detector()` in `crates/swarm-runtime/src/control.rs` is now the live construction path.
   - `DetectionConfig.active_strategies()` in `crates/swarm-core/src/config.rs` already supports multi-strategy configs.

3. Stateful detector patterns already exist and should be reused.
   - `DnsExfiltrationDetector` and `LateralMovementDetector` both use `Arc<Mutex<HashMap<_, VecDeque<i64>>>>`.
   - Both normalize event timestamps to milliseconds before applying time-window logic.

4. Threat-intel enrichment for network events already exists in runtime.
   - `candidate_threat_intel_queries()` in `crates/swarm-runtime/src/detection/pipeline.rs` already maps `TelemetryPayload::NetworkConnect` to `ThreatIntelIndicatorType::IpAddress`.
   - `enrich_findings_with_threat_intel()` already boosts confidence and annotates evidence.

5. Phase 121 should stop short of cross-strategy escalation proofs.
   - `121-CONTEXT.md` explicitly defers `NETWORK-04` and `NETWORK-05` integration proofs to Phase 123.
   - Plan only enough runtime integration to prove single-strategy detection and signed deposit flow.

## Standard Stack

- New detector module in `crates/swarm-whisker/src/network_connect.rs`
- Existing detector contract in `crates/swarm-whisker/src/detector.rs`
- Existing profile validation pattern via `ProfileValidationError` and `validate_confidence_thresholds()` in `crates/swarm-whisker/src/lib.rs`
- Existing state pattern via `Arc<Mutex<HashMap<BeaconKey, VecDeque<i64>>>>`
- Existing runtime profile merge path in `crates/swarm-runtime/src/config.rs`
- Existing runtime detector factory in `crates/swarm-runtime/src/control.rs`
- Existing threat-intel enrichment path in `crates/swarm-runtime/src/detection/pipeline.rs`
- Existing signed deposit flow via `detect_and_deposit()`

No external crate appears necessary for this phase. Simple interval math is enough.

## Architecture Patterns

### 1. Keep The Detector Synchronous

Recommended approach:

- `NetworkConnectDetector` should remain a normal `DetectionStrategy`
- it should evaluate only `TelemetryPayload::NetworkConnect`
- it should not reach into the substrate directly
- threat-intel boost should remain a runtime pipeline concern

Why:

- this matches every existing detector
- it avoids widening `DetectionStrategy` into async or stateful I/O
- it reuses the already-working DNS threat-intel pattern

### 2. Emit At Most One Finding Per Event

Recommended approach:

- combine beaconing, suspicious-port, and process-port-mismatch heuristics into one `DetectionFinding`
- record which heuristics triggered in `evidence`
- choose severity/confidence from the strongest triggered combination

Why:

- existing detectors usually produce at most one finding per event
- multiple findings from the same strategy on the same event create duplicate deposits and noisier evidence

### 3. Key Beacon State On The Full Destination Tuple

Recommended beacon key:

- `host_id` if present, otherwise `event.source`
- normalized `process_name`
- normalized `destination_ip`
- `destination_port`
- normalized `protocol`

Why:

- keying only by IP or only by process will mix unrelated traffic
- `host_id` matters because detector instances are process-global inside the runtime
- port and protocol belong in the key because a single IP may host many unrelated services

### 4. Use Sliding-Window Timestamp Tracking

Reuse the existing pattern from DNS and lateral movement detectors:

- normalize timestamp to milliseconds
- keep a `VecDeque<i64>` per beacon key
- drop entries older than `beacon_window_ms`
- append the current event
- only compute periodicity once `beacon_min_sample_count` is reached

### 5. Reuse The Existing Profile-Merge Pattern

The profile should follow the same structure as the current detectors:

- defaults live in `NetworkConnectProfile::default()`
- runtime-level thresholds flow in from `DetectionConfig`
- raw profile overrides live in `DetectorProfilesConfig.network_connect`
- `swarm-runtime/src/config.rs` merges defaults plus overrides and validates once

## Recommended Detector Design

### Detector ID

Use `network_connect` as the strategy id.

That matches:

- config naming style
- `DetectionConfig.active_strategies()`
- existing strategy ids such as `dns_exfiltration` and `lateral_movement`

### Threat Class

Emit `ThreatClass::CommandAndControl`.

That enum already exists in `crates/swarm-core/src/pheromone.rs`, but nothing currently emits it.

### Heuristics

Recommended heuristic order:

1. Normalize and reject obviously unusable events.
   - empty `destination_ip`
   - empty `process_name`
   - optionally empty `protocol`

2. Evaluate port anomaly heuristics.
   - `destination_port in suspicious_ports`
   - `process_port_allowlist[process_name]` exists and `destination_port` is not allowed

3. Evaluate beaconing.
   - same beacon key
   - enough samples in the sliding window
   - periodic intervals with low jitter

4. Emit no finding if nothing triggered.

5. Emit one `CommandAndControl` finding if any heuristic triggered.

### Recommended Confidence / Severity Mapping

- Port anomaly only: `Severity::Medium`, `medium_confidence_threshold`
- Process-port mismatch only: `Severity::Medium`, `medium_confidence_threshold`
- Beaconing only: `Severity::High`, `high_confidence_threshold`
- Beaconing plus any port anomaly: `Severity::High`, `high_confidence_threshold`

Important:

- existing runtime threat-intel enrichment boosts confidence only
- it does not currently change severity

So if you want IP intel matches to feel more urgent, the detector should already choose a sensible base severity.

### Recommended Evidence Shape

Include enough fields for review, replay, and tests:

```json
{
  "process_name": "...",
  "destination_ip": "...",
  "destination_port": 443,
  "protocol": "tcp",
  "host_id": "...",
  "heuristics": {
    "beaconing": true,
    "suspicious_port": false,
    "process_port_mismatch": true
  },
  "beacon": {
    "sample_count": 4,
    "intervals_ms": [60000, 61000, 59000],
    "mean_interval_ms": 60000.0,
    "jitter_ratio": 0.016
  },
  "allowlist": {
    "process_has_allowlist": true,
    "allowed_ports": [80, 443]
  }
}
```

The runtime can then append `threat_intel_matches` later, using the existing pipeline enrichment path.

## Stateful Beaconing Detection

### Recommended Minimal Algorithm

Use coefficient of variation over inter-arrival intervals:

1. sort or otherwise compare consecutive timestamps in ascending order
2. compute `intervals_ms`
3. compute `mean_interval_ms`
4. compute `stddev(intervals_ms)`
5. compute `jitter_ratio = stddev / mean`
6. classify as beaconing when:
   - `sample_count >= beacon_min_sample_count`
   - `mean_interval_ms >= beacon_min_interval_ms`
   - `jitter_ratio <= beacon_max_jitter_ratio`

This is simple, deterministic, and good enough for the event shape currently available.

### Recommended Default Beacon Settings

- `beacon_min_sample_count: 4`
- `beacon_window_ms: 900_000`
- `beacon_min_interval_ms: 15_000`
- `beacon_max_jitter_ratio: 0.20`

Why these defaults are reasonable:

- 4 samples gives 3 intervals, which is enough to measure periodicity
- 15 minutes catches common 30s to 5m beacon intervals without needing long-lived state
- 15s minimum interval avoids treating short connection bursts as beacons
- 20% jitter tolerance is strict enough to reject noisy traffic but lenient enough for real systems

## Threat-Intel Lookup Patterns

### Recommended Planning Decision

Treat threat-intel lookup as a runtime-owned enrichment step, not detector-owned I/O.

### Why This Fits The Current Codebase

- `DetectionStrategy::evaluate()` has no substrate access
- the runtime pipeline already enriches `NetworkConnect` events by IP
- DNS already uses this architecture successfully

### What To Prove In Tests

- seed `ThreatIntelEntry { indicator_type: IpAddress, value: <destination_ip> }`
- run `detect_and_deposit()` on a network event that already triggers a detector finding
- assert:
  - finding confidence increased
  - evidence contains `threat_intel_matches`
  - deposit confidence reflects the boosted value

### What Not To Do

- do not make the detector async just for this phase
- do not add a detector-specific substrate dependency
- do not duplicate threat-intel lookup in both detector and runtime

## Profile Validation Patterns

### Recommended Profile Shape

```rust
pub struct NetworkConnectProfile {
    pub suspicious_ports: Vec<u16>,
    pub process_port_allowlist: HashMap<String, Vec<u16>>,
    pub beacon_min_sample_count: usize,
    pub beacon_window_ms: i64,
    pub beacon_min_interval_ms: i64,
    pub beacon_max_jitter_ratio: f64,
    pub high_confidence_threshold: f64,
    pub medium_confidence_threshold: f64,
}
```

### Validation Rules

- `beacon_min_sample_count >= 3`
- `beacon_window_ms > 0`
- `beacon_min_interval_ms > 0`
- `0.0 < beacon_max_jitter_ratio <= 1.0`
- `beacon_window_ms >= beacon_min_interval_ms * (beacon_min_sample_count - 1)`
- reject empty process names in `process_port_allowlist`
- lowercase and dedupe allowlist keys in the detector instance
- use `validate_confidence_thresholds()` for confidence settings

### Normalization Rules

- lowercase `process_name`
- lowercase `protocol`
- lowercase and trim `destination_ip`
- leave ports numeric
- dedupe `suspicious_ports`
- dedupe per-process allowlist ports

## Likely Integration Points

### Minimum Required For Phase 121

- `crates/swarm-whisker/src/network_connect.rs`
  - new detector and profile
- `crates/swarm-whisker/src/lib.rs`
  - `mod network_connect;`
  - re-export detector and profile
- `crates/swarm-core/src/config.rs`
  - add `network_connect: Option<serde_json::Value>` to `DetectorProfilesConfig`
- `crates/swarm-runtime/src/config.rs`
  - import `NetworkConnectProfile`
  - add `network_connect_profile()`
  - extend `validate_detector_profiles()` and `validate_all_detector_profiles()`
- `crates/swarm-runtime/src/control.rs`
  - extend `build_single_detector()` with `network_connect`
- `rulesets/default.yaml`
  - update supported-strategy comments
  - optionally add commented example profile block

### Broad Strategy-Surface Support If Required This Phase

These files manually enumerate supported detector types:

- `crates/swarm-runtime/src/canary.rs`
- `crates/swarm-runtime/src/promotion.rs`
- `crates/swarm-runtime/src/replay/core.inc`
- `crates/swarm-runtime/tests/critical_path_integration.rs`

Planning decision:

- if Phase 121 only needs live runtime support plus detector integration, these can be deferred
- if `network_connect` must be a first-class strategy everywhere immediately, include them in scope now

## Testing Strategy

### 1. Whisker Unit Tests

Add focused tests in `crates/swarm-whisker/src/network_connect.rs`:

- profile validation rejects impossible beacon settings
- non-`NetworkConnect` payloads produce no findings
- suspicious port alone produces a medium-confidence finding
- process-port mismatch alone produces a medium-confidence finding
- allowlisted process-port pair produces no anomaly finding
- periodic same-destination connections with low jitter produce a beacon finding
- noisy intervals do not produce a beacon finding
- timestamp normalization handles second-based inputs

### 2. Runtime Pipeline Tests

Extend `crates/swarm-runtime/src/detection/pipeline.rs` tests:

- IP threat-intel hit boosts confidence for a network finding
- evidence includes runtime-added intel annotations

This is the best place to prove the existing enrichment path is reused instead of duplicated.

### 3. Runtime Integration Tests

Add or extend a runtime integration test similar to `persistence_supply_chain_integration.rs`:

- configure `strategy: network_connect`
- feed a synthetic `NetworkConnect` event sequence that triggers the detector
- assert:
  - one or more findings are emitted
  - `strategy_id == "network_connect"`
  - `threat_class == ThreatClass::CommandAndControl`
  - signed deposit is written to the substrate

### 4. Factory Coverage Tests

If broad strategy support is in scope, update supported-strategy coverage lists in:

- `crates/swarm-runtime/tests/critical_path_integration.rs`
- any other test that enumerates all supported strategies

## Don’t Hand-Roll

- Do not invent a new async detector interface for threat-intel lookup in this phase.
- Do not add a new telemetry payload or change `NetworkConnectEvent`; the current schema is enough.
- Do not bring in a stats crate for beacon math; a few helper functions are sufficient.
- Do not produce multiple findings for one event unless there is a very strong reason.
- Do not solve cross-strategy `agent_id` distinct-source behavior here; that belongs to Phase 122.

## Common Pitfalls

- Assuming event timestamps are always milliseconds. Existing detectors already guard against seconds-vs-ms drift.
- Keying state too broadly and mixing hosts or ports together.
- Forgetting that runtime threat-intel enrichment only happens after a detector already emitted a finding.
- Expecting an IP intel hit to change severity; current runtime only boosts confidence.
- Letting state cardinality grow silently by keying on high-cardinality tuples without trimming old timestamps.
- Forgetting to update `DetectorProfilesConfig`, runtime profile resolution, and the detector factory together.
- Updating live runtime support but forgetting manual detector enums in canary, promotion, or replay if those paths must support the new strategy.

## Code Examples

### Detector Skeleton

```rust
impl DetectionStrategy for NetworkConnectDetector {
    fn id(&self) -> &str {
        "network_connect"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        let TelemetryPayload::NetworkConnect(connect) = &event.payload else {
            return Vec::new();
        };

        self.evaluate_connect(event, connect).into_iter().collect()
    }
}
```

### Beacon Evaluation Sketch

```rust
let key = BeaconKey::from_event(event, connect);
let timestamps = self.record_connection(&key, normalized_timestamp_ms(event.timestamp));

let intervals = consecutive_intervals_ms(&timestamps);
let mean = mean_ms(&intervals);
let jitter_ratio = coefficient_of_variation(&intervals, mean);

let beaconing = timestamps.len() >= self.beacon_min_sample_count
    && mean >= self.beacon_min_interval_ms as f64
    && jitter_ratio <= self.beacon_max_jitter_ratio;
```

### Runtime Profile Merge Hook

```rust
pub(crate) fn network_connect_profile(
    config: &DetectionConfig,
) -> Result<NetworkConnectProfile, DetectorProfileError> {
    resolve_detector_profile(
        "network_connect",
        NetworkConnectProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..NetworkConnectProfile::default()
        },
        config.profiles.network_connect.as_ref(),
        NetworkConnectProfile::validate,
    )
}
```

## Suggested Plan Shape

### Plan 01: Detector And Profile

- add `NetworkConnectDetector`
- add `NetworkConnectProfile`
- implement beaconing and port heuristics
- add whisker unit tests

### Plan 02: Runtime Integration

- add config/profile/factory wiring
- prove `strategy: network_connect` builds and runs
- add detect-and-deposit integration coverage
- add IP threat-intel enrichment coverage for network events

### Plan 03: Optional Full Strategy Surface

- extend canary, promotion, replay, and full supported-strategy tests if Phase 121 must make `network_connect` universally selectable

## Open Decisions Before Planning

1. Interpret `NETWORK-02` as end-to-end threat-intel enrichment, or broaden the detector trait to support literal detector-side lookup.
   - Recommendation: end-to-end enrichment only.

2. Decide whether Phase 121 includes only live-runtime support or also canary/promotion/replay support.
   - Recommendation: keep Phase 121 focused on live runtime unless milestone acceptance explicitly requires broader strategy selection.

3. Decide whether to include any finding cooldown logic.
   - Recommendation: no cooldown in Phase 121 unless testing shows noisy duplicate findings are unmanageable.

## Bottom Line

The safe plan is to add a normal stateful `NetworkConnectDetector` in `swarm-whisker`, reuse the existing runtime threat-intel enrichment path, wire the new profile through the existing config/factory flow, and prove the behavior with unit tests plus a single-strategy runtime integration test. The main thing to avoid is quietly widening the detector/runtime contract just to satisfy roadmap wording that the current architecture already solves one layer later.
