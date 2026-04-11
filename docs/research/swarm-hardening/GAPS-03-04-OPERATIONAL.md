---
title: "Gap Analysis: Docs 03 and 04 -- Threat Intel + Performance"
series: Swarm Hardening
version: "0.1"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# Gap Analysis: Threat Intelligence Lifecycle (03) and Performance Characterization (04)

## Executive Summary

- **GC is never invoked by the runtime.** Both documents identify this, but neither provides a complete fix. Wiring GC into the concentration monitor creates a new hot-path write-lock holder that interacts with the enrichment read path -- this interaction is unanalyzed.
- **Enrichment-induced backpressure is not modeled.** Doc 03 proposes L1/L2/L3 caching and external API queries; Doc 04's latency budget allocates only 2-10us for threat intel enrichment. The proposed external enrichment mode (10-500ms per lookup) would blow the entire latency budget, yet Doc 04 does not model this scenario.
- **Feed failure and degraded-mode operation are unaddressed.** Doc 03 mentions polling backoff and circuit breakers in passing but provides no analysis of what happens to detection quality when feeds go dark, nor how stale-cache-only operation affects false positive/negative rates.
- **The beacon tracker in `NetworkConnectDetector` is an unbounded memory growth vector** that neither document identifies. It holds a `HashMap<BeaconKey, VecDeque<i64>>` behind a `std::sync::Mutex` with no eviction of stale keys.
- **No benchmark infrastructure exists in the production crates.** Doc 04 designs a comprehensive benchmarking framework but the codebase has zero Criterion benchmarks or load test harnesses. The gap between proposal and executability is large.
- **The double signature verification is confirmed in code** (`ConfiguredPheromoneSubstrate::deposit()` line 274 and `InMemoryPheromoneSubstrate::deposit()` line 442 both call `validate_deposit_signature`), but the proposed fix does not address the `LocalJournalPheromoneSubstrate` which also double-verifies and additionally performs blocking file I/O in async context.
- **Threat intel entry count has no upper bound.** Doc 03 proposes scaling to 1M entries with L2 caching, but the `BTreeMap` GC for threat intel (`gc_expired_threat_intel`) is also never called. Feed ingestion would grow the map without bound.
- **Cross-document latency assumptions are inconsistent.** Doc 03 targets <5ms per event including enrichment (Section 14 cross-reference). Doc 04 estimates 66-160us total per event. These targets are compatible only if enrichment remains purely local and fast -- a condition that the proposed L3 external enrichment mode violates.
- **Deployment scenario analysis is absent from both documents.** Edge nodes (Raspberry Pi 4, 256MB) face fundamentally different constraints than cloud deployments, but neither document analyzes how the threat intel cache, feed polling, or GC parameters should adapt.
- **The escalation vector lockout is fragile.** Doc 04 notes that `gc_evaporated` acquires deposits write-lock then threat_class_configs read-lock. If any future code path acquires these in reverse order, deadlock results. No lock-ordering discipline is documented or enforced.

---

## 1. Enrichment-Performance Cross-Cutting Gaps

### 1.1 Enrichment Latency Not Modeled Under Load (Critical)

**Gap:** Doc 04 Section 4.2 allocates 3us (p50) / 10us (p99) for threat intel enrichment. This assumes the current minimal implementation: 0-3 read-lock acquisitions against a small BTreeMap. Doc 03 proposes:
- Expanding from 2 to 7 event types producing IOC queries (Section 8.1)
- Adding CIDR range matching requiring trie traversal
- Adding parent-domain expansion (already partially implemented but linear in label count)
- Multi-factor confidence scoring with per-source iteration (Section 7.2)

With 7 event types producing up to 5 candidate queries each, and the noisy-OR scoring model iterating over multiple sources per match, the enrichment cost could grow by 5-10x. Doc 04's latency budget does not account for this.

**Recommendation:** Add an "enriched enrichment" latency tier to Doc 04's budget table. Model the expected cost of: (a) expanded candidate query generation, (b) CIDR trie lookup vs. exact BTreeMap lookup, (c) noisy-OR scoring iteration. Revise the p99 estimate accordingly and verify it still fits within the 10ms SLO.

**Priority:** Critical

### 1.2 External Enrichment Breaks the Latency Model (Critical)

**Gap:** Doc 03 Section 6.2 proposes "Mode 3: External enrichment" with 10-500ms per lookup to VirusTotal, AbuseIPDB, etc. Doc 03 says this should be "non-blocking for the detection pipeline" and that external results arrive asynchronously via supplementary deposits. However, the architectural mechanism for this is not specified:
- How are supplementary deposits created? They need signing keys and agent IDs.
- How are they correlated back to the original finding?
- What happens to the original finding's confidence -- does it get retroactively adjusted, or does a new finding appear?
- Doc 04 models no async enrichment path at all.

**Recommendation:** Define the supplementary deposit lifecycle concretely. Specify whether external enrichment produces new deposits (requiring a dedicated "enrichment agent" identity) or modifies existing ones (requiring signature re-computation). Add the async enrichment path to Doc 04's architecture diagram and analyze its impact on substrate write pressure.

**Priority:** Critical

### 1.3 Enrichment Read-Lock vs. GC Write-Lock Contention (High)

**Gap:** Doc 04 Section 5.3 analyzes GC write-lock pauses on the deposits vector. But threat intel enrichment acquires the `threat_intel_entries` read-lock on every detection pipeline invocation (pipeline.rs lines 92-93, via `threat_intel_matches_for_event`). When `gc_expired_threat_intel` is eventually wired up, it will need the write-lock on the same `threat_intel_entries` BTreeMap. Under sustained load at 10K events/sec, the read-lock is held approximately 10K times/second. If GC runs on a 100ms tick, it must acquire the write-lock while 1000 read-lock acquisitions are in-flight per tick window. Neither document analyzes this specific contention.

**Recommendation:** Extend Doc 04's lock inventory (Section 2.3) to explicitly model threat_intel_entries write-lock contention from GC. Estimate GC pause duration for the threat intel BTreeMap at 10K, 100K, and 1M entries. Consider whether threat intel GC should run at a different cadence than deposit GC.

**Priority:** High

---

## 2. Feed Reliability and Degraded Mode

### 2.1 Feed Failure Mode Analysis Missing (High)

**Gap:** Doc 03 Section 5.4 mentions "exponential backoff on failure and circuit-breaker patterns" for feed polling but provides no analysis of:
- How long the system operates on stale cache before detection quality degrades meaningfully
- Whether the decay model (Section 4.3) naturally handles this (IOCs decay even without feed refresh) or whether it creates a cliff where the entire feed's IOCs simultaneously fall below the confidence floor
- What the operator observes when feeds fail -- are there health check endpoints, alerts, or metrics for feed freshness?
- How many feeds must be operational simultaneously for the noisy-OR scoring model to function correctly

**Recommendation:** Add a "Feed Failure Scenarios" section to Doc 03 analyzing: (a) single-feed failure with cache retention, (b) all-feeds-down with cache-only operation, (c) feed poisoning (false IOCs injected). For each scenario, quantify the detection quality impact over time using the decay model. Define monitoring requirements (feed freshness metric, staleness alert threshold).

**Priority:** High

### 2.2 Cache Warmup and Cold-Start Behavior (Medium)

**Gap:** Neither document addresses the cold-start scenario: the system starts with an empty threat intel cache. How long does it take to populate the cache from feeds? What is the detection quality during warmup? Doc 03 Section 12.3 describes the feed ingestion pipeline but not the bootstrap sequence.

**Recommendation:** Define a cache warmup protocol. Specify whether the system should delay accepting telemetry until a minimum cache population is achieved, or accept events at reduced enrichment quality. Estimate warmup time for the recommended feed portfolio (Section 5.3) based on typical TAXII pagination rates.

**Priority:** Medium

---

## 3. GC Architecture Gaps

### 3.1 GC Fix Is Necessary But Structurally Incomplete (Critical)

**Gap:** Both documents identify that `gc_evaporated()` and `gc_expired_threat_intel()` are never called. Doc 04 Section 12.1 proposes wiring GC into the ConcentrationMonitor at 100ms ticks. But this introduces several problems that are acknowledged but not resolved:

1. **GC holds the deposits write-lock for O(n) time.** At 100K deposits, the `retain()` call iterates all deposits with decay computation per entry. Doc 04 estimates this as problematic but does not provide a concrete pause-time estimate.
2. **The 100ms tick means GC runs frequently.** At 100K deposits, running `retain()` 10 times/second is ~1M decay computations/second just for GC, consuming significant CPU.
3. **The incremental GC proposal (Section 12.1, item 3) is listed as P0 alongside wiring up GC.** But these are contradictory -- you either wire up the full-sweep GC now or build incremental GC. Doing the full sweep first and then replacing it with incremental GC doubles the work.

**Recommendation:** Skip the full-sweep GC wire-up entirely. Go directly to incremental GC: maintain a `BinaryHeap` or sorted index of evaporation timestamps, evict only the top-N expired deposits per tick, bound hold time to a configurable maximum (e.g., 1ms). This avoids shipping a known-problematic O(n) GC and then immediately replacing it.

**Priority:** Critical

### 3.2 Lock Ordering Discipline (High)

**Gap:** Doc 04 Section 5.3 notes that `gc_evaporated()` acquires `deposits` write-lock then `threat_class_configs` read-lock, and warns that reverse ordering elsewhere would deadlock. The current code does not exhibit the reverse, but there is no enforcement mechanism. The codebase has 7+ locks in the critical path (Doc 04 Section 2.3), and adding GC increases the lock interaction surface.

**Recommendation:** Document a canonical lock acquisition order in a code comment or module-level doc. Consider using a lock-ordering wrapper type (e.g., numbered lock tiers) that makes out-of-order acquisition a compile-time or debug-time error. At minimum, add a `// LOCK ORDER:` comment to the substrate module documenting the required sequence.

**Priority:** High

### 3.3 Journal Compaction Missing (Medium)

**Gap:** Doc 04 Section 5.5 notes that LocalJournal files grow monotonically -- GC removes entries from memory but not from the JSONL file. This is stated as a fact but not treated as a problem to solve. In a long-running deployment, the journal file becomes arbitrarily large, and replay-on-startup re-reads all entries (including long-evaporated ones) only to discard them during the first GC pass.

**Recommendation:** Add journal compaction to the GC design. Options: (a) periodic rewrite of the journal with only live entries, (b) segment-based journal where old segments are deleted, (c) embedded database (redb/sled) that handles compaction natively. Estimate journal growth rate at 3K deposits/second and derive when compaction becomes necessary.

**Priority:** Medium

---

## 4. Memory Model Gaps

### 4.1 Beacon Tracker Unbounded Growth (Critical)

**Gap:** Neither document identifies that `NetworkConnectDetector::beacon_tracker` (`crates/swarm-whisker/src/network_connect.rs` line 58) is a `HashMap<BeaconKey, VecDeque<i64>>` behind an `Arc<Mutex<...>>` with **no eviction of stale keys**. The `record_connection` method (line 211) evicts old timestamps from each key's VecDeque but never removes keys whose VecDeque is empty or whose last timestamp is outside the beacon window.

In a deployment seeing connections to many distinct (host, process, IP, port, protocol) tuples, the HashMap grows without bound. At 10K events/second with even 10% being unique tuples, this adds 1K new keys/second. Each key is ~200 bytes (five Strings + VecDeque overhead). After one hour: 3.6M keys consuming ~720MB.

**Recommendation:** Add key eviction to the beacon tracker. Options: (a) remove keys with empty VecDeques during `record_connection`, (b) periodic sweep of the HashMap removing keys with `last_timestamp < now - beacon_window_ms`, (c) use an LRU cache with bounded capacity. This should be covered in Doc 04's memory pressure analysis as an additional unbounded growth vector.

**Priority:** Critical

### 4.2 Threat Intel Entry Growth Unbounded (High)

**Gap:** Doc 03 proposes scaling the threat intel cache to 1M entries (Section 6.3, L2 cache target). But `gc_expired_threat_intel()` is never called (same bug as deposit GC), and the `store_threat_intel_entry` method (substrate.rs line 472) simply inserts into the BTreeMap. If feeds are ingested faster than entries expire, or if the GC is never wired up, the BTreeMap grows without bound.

Doc 04's memory analysis (Section 5) focuses entirely on PheromoneDeposit memory. Threat intel entries are unaccounted. Each entry is approximately 150-300 bytes (two strings, a float, two i64s, plus BTreeMap node overhead). At 100K entries, this is ~30MB -- significant on edge devices with a 256MB budget.

**Recommendation:** Add threat intel memory to Doc 04's memory pressure analysis. Provide per-entry size estimates and steady-state projections. Wire up `gc_expired_threat_intel()` alongside the deposit GC fix. Consider adding a hard cap on threat intel entry count with LRU eviction.

**Priority:** High

### 4.3 Evidence JSON Blob Size Uncapped (Medium)

**Gap:** Doc 04 Section 5.1 estimates the `indicator` JSON field at 200-800 bytes. But the enrichment pipeline (pipeline.rs `annotate_threat_intel_evidence`, line 192) appends the full `threat_intel_matches` array to the evidence. If an event matches 10+ IOCs (plausible with expanded indicator types and CIDR ranges), each match is serialized as a full `ThreatIntelEntry` JSON object. With Doc 03's expanded entry format (adding `sources: Vec<ThreatIntelSource>`, tags, campaign names), each match could be 500+ bytes, pushing the evidence blob to 5KB+ per finding.

This matters because the evidence blob is cloned into the PheromoneDeposit, signed, stored, and included in replay bundles. It multiplies the memory impact identified in Doc 04 Section 5.1.

**Recommendation:** Cap the number of threat intel matches serialized into evidence (e.g., top-5 by confidence). Summarize rather than inline full match details. Revise Doc 04's per-deposit memory estimate to account for the enriched evidence payloads.

**Priority:** Medium

---

## 5. Allocation and Hot-Path Blind Spots

### 5.1 String Cloning in Detection Pipeline (Medium)

**Gap:** Doc 04 does not analyze allocation patterns in the detection hot path. The pipeline clones aggressively:
- `event.clone()` in `DetectionPipelineOutcome` (pipeline.rs line 52) -- clones the entire TelemetryEvent including all payload strings
- `finding.evidence.clone()` in `resolve_deposits` (pipeline.rs line 259) -- clones the JSON evidence blob
- `deposit.clone()` in the deposit loop (pipeline.rs line 48) -- clones the entire deposit before passing to `substrate.deposit()`
- `entry.cloned()` in `query_threat_intel_entry` (substrate.rs line 558) -- clones the threat intel entry out of the read-locked BTreeMap

These clones are cheap at current scale but become allocation-heavy at 10K events/second. The `event.clone()` alone copies 5-10 string fields per event.

**Recommendation:** Add an allocation analysis subsection to Doc 04. Profile with `dhat` to measure per-event allocation counts and bytes. Consider using `Arc<TelemetryEvent>` for zero-copy sharing, returning `&ThreatIntelEntry` from substrate queries (requires lifetime management), or using a pre-allocated finding buffer.

**Priority:** Medium

### 5.2 Sequential Threat Intel Queries Per Event (Medium)

**Gap:** The `threat_intel_matches_for_event` function (pipeline.rs line 122) queries the substrate sequentially for each candidate indicator. For DNS events with parent-domain expansion, this produces multiple queries (e.g., `sub.evil.com`, `evil.com`). Doc 03 Section 8.1 proposes expanding enrichment to 7 event types, some producing multiple candidate queries (file hash + URL extraction from command lines). Sequential queries multiply the read-lock acquisition count.

Doc 04's per-event enrichment estimate of 2-10us assumes 0-3 queries. With expanded enrichment producing 5-10 queries per event, the estimate should be 5-25us.

**Recommendation:** Consider batch query support on the substrate trait (`query_threat_intel_entries_batch`) that acquires the read-lock once and performs multiple lookups. This reduces lock acquisition overhead from O(queries) to O(1) per event.

**Priority:** Medium

---

## 6. Benchmark Executability

### 6.1 No Benchmark Infrastructure Exists (High)

**Gap:** Doc 04 Section 10 designs a comprehensive benchmarking framework with Criterion microbenchmarks, end-to-end load tests, and stress test scenarios. The codebase has zero benchmark files in the production crates. The only Criterion benchmarks are in `vendor/reference/clawdstrike/` which is reference-only material. No `[[bench]]` sections exist in any production `Cargo.toml`.

The benchmarks are not runnable today. Creating them requires:
1. Adding `criterion` to dev-dependencies of relevant crates
2. Writing benchmark harnesses that construct realistic substrate state
3. Building the synthetic load generator (`SyntheticLoadConfig`)
4. Setting up CI infrastructure with CPU affinity and cgroups

**Recommendation:** Treat benchmark creation as a prerequisite task, not future work. Start with the three highest-value benchmarks: (a) `detect_and_deposit` end-to-end with realistic substrate, (b) `gc_evaporated` at 10K/100K deposits, (c) substrate write-lock contention under concurrent access. These directly validate the cost estimates in Doc 04 Sections 3-5.

**Priority:** High

### 6.2 Load Test Assumes Unrestricted HTTP Client (Medium)

**Gap:** Doc 04's load test design (Section 10.2) uses concurrent HTTP clients to drive events through the ingest API. But the current Axum server has no concurrency limits (Doc 04 Section 7.1). A load test with 100 concurrent clients could overwhelm the tokio thread pool before the substrate or detection stages become the bottleneck, producing misleading results.

**Recommendation:** Add Axum concurrency limits (e.g., `tower::limit::ConcurrencyLimitLayer`) as a prerequisite for meaningful load testing. Alternatively, design the load test to bypass HTTP and drive events directly through `RuntimeService::process_event()` for a more focused critical-path measurement.

**Priority:** Medium

---

## 7. Deployment and Operational Gaps

### 7.1 No Deployment Scenario Analysis (High)

**Gap:** Neither document analyzes how configuration should vary across deployment targets. Doc 04 Section 11.2 provides a scaling envelope table (4-core edge to 16-core production) but does not address:
- **Edge nodes:** Should feeds be polled at all, or should edge nodes receive pre-filtered IOC snapshots from a central coordinator? A Raspberry Pi with 256MB cannot host a 1M-entry threat intel cache.
- **Cloud deployments:** Should the JetStream backend be default? How does NATS latency (1-5ms per operation per Doc 04 Section 8.2) affect the enrichment latency budget?
- **Air-gapped environments:** Doc 03's feed polling architecture assumes internet connectivity. What is the offline operating model?

**Recommendation:** Add a "Deployment Profiles" section to both documents defining at least three tiers (edge, standard, enterprise) with specific parameter recommendations for: threat intel cache size limit, GC frequency, feed polling strategy, substrate backend choice, and memory ceiling.

**Priority:** High

### 7.2 No Self-Monitoring for Enrichment Quality (Medium)

**Gap:** Doc 03 proposes provenance tracking and source reputation but provides no metrics for enrichment effectiveness. Questions that operators cannot currently answer:
- What fraction of findings are enriched by threat intel?
- What is the average confidence boost from enrichment?
- Which feeds contribute the most true-positive enrichments?
- How old are the IOCs that produce matches?

Doc 04 documents existing instrumentation (Section 4.4) but notes a gap: "No instrumentation exists for substrate lock wait time, GC pause duration, or channel send/receive latency." The enrichment-specific metrics gap is equally important.

**Recommendation:** Define enrichment metrics: `enrichment_hit_rate` (fraction of events matching at least one IOC), `enrichment_boost_mean` (average confidence increase), `enrichment_age_p50` (median age of matched IOCs in seconds), `feed_hit_rate_by_id` (per-feed contribution). Expose via the existing Prometheus pipeline.

**Priority:** Medium

### 7.3 Alerting for GC and Memory Pressure (Medium)

**Gap:** Doc 04 Section 5.4 describes the heap pressure safety valve (reject at 90% memory) but does not define alerting for approaching the limit. The system goes from "accepting events" to "rejecting everything" with no warning. Similarly, once GC is wired up, GC pause duration should be alerted on but no thresholds are proposed.

**Recommendation:** Define alerting thresholds: warn at 70% heap pressure, critical at 85%. Alert on GC pause duration exceeding 5ms (warn) or 50ms (critical). Alert on deposit count exceeding 80% of the expected steady-state maximum. Add these to the operational runbook.

**Priority:** Medium

---

## 8. Confidence Model Transition Risk

### 8.1 Scoring Model Migration Unvalidated (High)

**Gap:** Doc 03 Section 7.2 proposes replacing the current additive max-based confidence boost with a noisy-OR model. The mathematical difference is significant:
- Current: `enriched = base + max(matches)`, capped at 1.0
- Proposed: `enriched = base + (1 - PRODUCT(1 - w_i * c_i)) * (1 - base)`

Doc 03 correctly notes this should be gated behind a configuration flag for A/B testing. But there is no analysis of how the change affects the downstream pheromone concentration thresholds (`alert_threshold: 2.0`, `incident_threshold: 5.0`) which were presumably tuned for the current scoring model. Changing the confidence model without retuning thresholds could cause alert storms or missed incidents.

**Recommendation:** Before implementing the scoring model change, establish a baseline of finding confidence distributions under the current model using production-representative telemetry. Then simulate the noisy-OR model against the same data and quantify the impact on: (a) mean finding confidence, (b) escalation trigger rate, (c) false positive rate. Provide a threshold retuning guide.

**Priority:** High

---

## 9. Specific Code-Level Issues Underanalyzed

### 9.1 `normalized_timestamp_ms` Inconsistency (Low)

**Gap:** Both `pipeline.rs` (line 229) and `network_connect.rs` (line 410) contain identical `normalized_timestamp_ms` functions that heuristically convert seconds to milliseconds when `timestamp.abs() < 100_000_000_000`. This heuristic breaks for timestamps before 1973 (epoch seconds > 100B) or after 5138 (milliseconds > 100T). Neither document notes this as a correctness risk. More importantly, Doc 03's decay model (Section 4.3) requires precise elapsed time computation. If timestamps are inconsistently normalized, the decay curve is wrong.

**Recommendation:** Centralize the timestamp normalization function in `swarm-core`. Add validation that rejects timestamps outside a reasonable range (e.g., 2000-2100). Document the canonical timestamp unit for each struct field.

**Priority:** Low

### 9.2 Blocking File I/O Scope Broader Than Documented (Medium)

**Gap:** Doc 04 Section 6.2 identifies `append_jsonl_line()` as blocking file I/O in async context. But the scope is broader: `LocalJournalPheromoneSubstrate::open()` (substrate.rs line 624) performs synchronous file reads (`load_jsonl`) during initialization, and every `store_threat_intel_entry` call (line 690) also calls `append_jsonl_line`. With Doc 03's automated feed ingestion producing bulk inserts, the journal write path becomes a sustained blocking I/O source, not just an occasional one.

**Recommendation:** Extend the `spawn_blocking` recommendation (Doc 04 Section 12.1, item 4) to cover all LocalJournal write operations, not just deposit appends. Consider batching journal writes for bulk feed ingestion (write N entries per fsync rather than one).

**Priority:** Medium

---

## Priority Summary

| Priority | Count | Items |
|----------|-------|-------|
| **Critical** | 4 | Enrichment latency unmodeled (1.1), External enrichment breaks model (1.2), GC fix incomplete (3.1), Beacon tracker growth (4.1) |
| **High** | 6 | Enrichment vs. GC lock contention (1.3), Feed failure modes (2.1), Lock ordering (3.2), Threat intel growth (4.2), No benchmarks (6.1), No deployment profiles (7.1), Scoring migration risk (8.1) |
| **Medium** | 8 | Cache warmup (2.2), Journal compaction (3.3), Evidence blob size (4.3), String cloning (5.1), Sequential queries (5.2), Load test design (6.2), Self-monitoring (7.2), Alerting (7.3), Blocking I/O scope (9.2) |
| **Low** | 1 | Timestamp normalization (9.1) |

---

## Appendix: Code References

| File | Relevant Lines | Finding |
|------|---------------|---------|
| `crates/swarm-pheromone/src/substrate.rs` | 240-242 | `gc_evaporated` and `gc_expired_threat_intel` defined on trait, never called by runtime |
| `crates/swarm-pheromone/src/substrate.rs` | 273-274, 441-442, 651-652 | Double `validate_deposit_signature` in ConfiguredPheromoneSubstrate + each inner backend |
| `crates/swarm-pheromone/src/substrate.rs` | 561-576 | `gc_evaporated` acquires deposits write-lock then threat_class_configs read-lock |
| `crates/swarm-runtime/src/detection/pipeline.rs` | 48 | `deposit.clone()` in hot loop |
| `crates/swarm-runtime/src/detection/pipeline.rs` | 52 | `event.clone()` in outcome construction |
| `crates/swarm-runtime/src/detection/pipeline.rs` | 122-141 | Sequential substrate queries per candidate indicator |
| `crates/swarm-whisker/src/network_connect.rs` | 58, 211-226 | Beacon tracker HashMap with no key eviction |
| `crates/swarm-runtime/src/escalation.rs` | (entire file) | ConcentrationMonitor -- no GC invocation |
| `crates/swarm-runtime/src/bin/swarm_detect.rs` | (entire file) | Main binary -- no GC invocation |
