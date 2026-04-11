---
title: "03 -- Threat Intelligence Lifecycle and Enrichment"
series: Swarm Hardening (3 of 8)
version: "0.3"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# 03 -- Threat Intelligence Lifecycle and Enrichment

| | |
|---|---|
| **Series** | Swarm Hardening (Document 03 of 08) |
| **Version** | 0.3 |
| **Date** | 2026-04-08 |
| **Status** | Draft |
| **Primary Crate** | `crates/swarm-pheromone` -- substrate-resident threat intel cache |
| **Enrichment Pipeline** | `crates/swarm-runtime/src/detection/pipeline.rs` -- enrichment at detection time |
| **Core Types** | `crates/swarm-core/src/pheromone.rs` -- `ThreatIntelEntry`, `ThreatIntelIndicatorType` |

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Current State Analysis](#2-current-state-analysis)
3. [IOC Taxonomy and Lifecycle](#3-ioc-taxonomy-and-lifecycle)
4. [IOC Freshness and Decay](#4-ioc-freshness-and-decay)
5. [Feed Sourcing Strategy](#5-feed-sourcing-strategy)
6. [Enrichment Pipeline Architecture](#6-enrichment-pipeline-architecture)
7. [Confidence Scoring](#7-confidence-scoring)
8. [Integration with Detection Pipeline](#8-integration-with-detection-pipeline)
9. [Integration with Pheromone Substrate](#9-integration-with-pheromone-substrate)
10. [STIX/TAXII Rust Implementation Considerations](#10-stixtaxii-rust-implementation-considerations)
11. [Privacy and Legal Considerations](#11-privacy-and-legal-considerations)
12. [Proposed Architecture](#12-proposed-architecture)
13. [Open Questions and Future Work](#13-open-questions-and-future-work)
14. [Enrichment Quality Metrics](#14-enrichment-quality-metrics)
15. [Deployment Profiles](#15-deployment-profiles)
16. [Cross-References](#16-cross-references)
17. [References](#17-references)

---

## 1. Abstract

Threat intelligence is the connective tissue between external knowledge about
adversary infrastructure and internal detection logic. Swarm Team Six already
implements a foundational threat-intel cache with TTL-based garbage collection,
query-time enrichment of detection findings, and operator-facing HTTP APIs for
IOC management. This document analyzes that implementation in depth, identifies
its limitations, and proposes a comprehensive threat-intelligence lifecycle --
from IOC ingestion through enrichment, scoring, decay, and retirement -- that
is compatible with the pheromone substrate's stigmergic coordination model.

The central thesis: IOCs are not static blocklists. They are living data with
measurable half-lives that vary by indicator type, source reputation, and
adversary behavior. A detection engine that treats a six-month-old IP address
indicator with the same confidence as a fresh one will produce false positives
that erode operator trust. Conversely, an engine that naively discards all aged
indicators will miss persistent infrastructure reused across campaigns. The
correct approach is a decay model -- mathematically compatible with the existing
pheromone half-life framework -- that continuously adjusts IOC confidence based
on age, corroboration, and type-specific empirical half-lives.

We propose extending the current three-type indicator taxonomy (`IpAddress`,
`Domain`, `FileHash`) to six types, introducing a multi-source confidence
scoring model, designing a STIX/TAXII 2.1 feed ingestion pipeline, and
formalizing the IOC-as-pheromone mapping that enables cross-detector correlation
through the shared substrate.

---

## 2. Current State Analysis

### 2.1 What STS Already Implements

The Swarm Team Six codebase contains a working, tested threat-intel subsystem
distributed across three crates. A precise inventory follows.

**Core types** (`crates/swarm-core/src/pheromone.rs`):

```rust
pub enum ThreatIntelIndicatorType {
    IpAddress,
    Domain,
    FileHash,
}

pub struct ThreatIntelEntry {
    pub indicator_type: ThreatIntelIndicatorType,
    pub value: String,
    pub confidence: f64,
    pub expires_at: i64,
}
```

The `ThreatIntelEntry` is the canonical IOC record. It carries a confidence
score (0.0--1.0) and an absolute expiration timestamp in milliseconds. The
`indicator_type` enum currently supports three families: IPv4/IPv6 addresses,
domain names, and file hashes (algorithm-agnostic -- the value field stores
the hash string directly).

**Substrate storage** (`crates/swarm-pheromone/src/substrate.rs`):

The `PheromoneSubstrate` trait exposes two threat-intel operations:

- `store_threat_intel_entry(entry)` -- upserts an IOC record, keyed by
  `(indicator_type, normalized_value)`.
- `query_threat_intel_entry(indicator_type, value, now)` -- exact-match lookup
  that filters out expired entries where `entry.expires_at <= now`.

All three substrate backends (InMemory, LocalJournal, JetStream) implement
these operations. The InMemory backend uses a `BTreeMap<ThreatIntelKey,
ThreatIntelEntry>` with the key defined as `(ThreatIntelIndicatorType,
String)`. The LocalJournal backend persists entries to a JSONL file
(`*.threat-intel.jsonl`) and replays them on startup.

**Normalization** (`substrate.rs`):

```rust
pub(crate) fn normalize_threat_intel_value(
    indicator_type: &ThreatIntelIndicatorType,
    value: &str,
) -> String {
    let trimmed = value.trim();
    match indicator_type {
        ThreatIntelIndicatorType::Domain =>
            trimmed.trim_end_matches('.').to_ascii_lowercase(),
        ThreatIntelIndicatorType::IpAddress
        | ThreatIntelIndicatorType::FileHash =>
            trimmed.to_ascii_lowercase(),
    }
}
```

Domain values receive trailing-dot removal (FQDN normalization) and
case-folding. IP addresses and file hashes receive case-folding only.

**Garbage collection** (`substrate.rs`):

```rust
async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError> {
    // ... retains only entries where entry.expires_at > now
}
```

The GC pass is TTL-based: entries whose `expires_at` timestamp has passed are
purged. This is a binary alive/dead model -- there is no gradual confidence
decay as the entry ages.

**Detection-time enrichment** (`crates/swarm-runtime/src/detection/pipeline.rs`):

The `enrich_findings_with_threat_intel` function runs after detector evaluation
and before pheromone deposit signing. It:

1. Extracts candidate IOC queries from the event payload via
   `candidate_threat_intel_queries`. Currently this extracts:
   - `Domain` indicators from `DnsQuery` events (with parent-domain expansion)
   - `IpAddress` indicators from `NetworkConnect` events
   - No indicators from `ProcessStart`, `RegistryAccess`,
     `RegistryPersistence`, `FilePersistence`, or `AuthenticationEvent` payloads
2. Queries the substrate for each candidate
3. If matches are found, applies a confidence boost: the maximum confidence
   across all matching entries is added to the finding's base confidence,
   capped at 1.0
4. Annotates the finding evidence with `threat_intel_matches`,
   `threat_intel_base_confidence`, `threat_intel_confidence_boost`, and
   `threat_intel_enriched_confidence` fields

**HTTP API** (`crates/swarm-runtime/src/http/core.inc`):

Two operator-facing routes are registered behind bearer-token authentication:

- `GET /v1/operator/threat-intel/entries` -- lookup by `indicator_type`,
  `value`, and optional `now` timestamp
- `POST /v1/operator/threat-intel/entries` -- upsert a `ThreatIntelEntry`

### 2.2 Limitations of the Current Implementation

The existing system is a correct, minimal foundation. Its limitations are:

| Area | Limitation |
|------|-----------|
| **Indicator types** | Only three types (IP, domain, hash). No support for URLs, email addresses, certificate fingerprints, CIDR ranges, or YARA signatures. |
| **Confidence model** | Single static confidence per entry. No decay over time, no source reputation weighting, no multi-source corroboration. |
| **Expiration model** | Binary TTL. An IOC at 99% of its TTL has the same confidence as one freshly ingested. |
| **Feed ingestion** | Manual operator-seeded via HTTP POST. No automated feed polling, no STIX/TAXII integration, no bulk import. |
| **Enrichment scope** | Only DNS and network-connect events are enriched. Process-start events with known-bad hashes, registry persistence with known-bad domains, and authentication events from known-bad IPs are not covered. |
| **Enrichment model** | Additive confidence boost using max-match. Does not account for multiple matches reinforcing each other, nor for the age of the matched IOC. |
| **Query model** | Exact-match only. No CIDR range matching for IPs, no wildcard/subdomain matching for domains, no fuzzy matching for hashes (e.g., ssdeep). |
| **Auditability** | No provenance tracking. Once stored, the source feed, original STIX object ID, and ingestion timestamp are lost. |
| **Scale** | In-memory `BTreeMap` with linear GC scan. Adequate for thousands of entries; will not scale to millions without indexing. |

---

## 3. IOC Taxonomy and Lifecycle

### 3.1 Indicator Types

The threat intelligence community has converged on a practical taxonomy of
indicator types. We propose extending `ThreatIntelIndicatorType` from three
to six variants, plus a structured extension point:

| Type | Current | Description | Example |
|------|---------|-------------|---------|
| `IpAddress` | Yes | IPv4 or IPv6 address | `198.51.100.42` |
| `Domain` | Yes | Fully qualified domain name | `evil.example.com` |
| `FileHash` | Yes | Cryptographic file hash (MD5, SHA-1, SHA-256) | `a1b2c3...` |
| `Url` | **New** | Full URL including path and query | `https://evil.com/payload.exe` |
| `EmailAddress` | **New** | Sender address in phishing campaigns | `attacker@evil.com` |
| `CertificateFingerprint` | **New** | TLS certificate SHA-256 fingerprint | `ab:cd:ef:...` |

Additionally, a `Custom(String)` variant allows operators to define
organization-specific indicator types (e.g., JA3 fingerprints, AS numbers)
without requiring code changes.

### 3.2 Indicator Normalization

Each indicator type requires specific normalization to ensure consistent
matching:

- **IpAddress**: Parse and re-serialize to canonical form. IPv4-mapped IPv6
  addresses (`::ffff:192.0.2.1`) should be stored as IPv4 (`192.0.2.1`).
  Consider storing CIDR ranges as separate entries with a `cidr_mask` field
  to support range queries.
- **Domain**: Current normalization (trim, remove trailing dot, lowercase) is
  correct. Add punycode normalization for internationalized domain names.
  Store both the unicode and punycode forms.
- **FileHash**: Store with an explicit `hash_algorithm` field (md5, sha1,
  sha256, sha512). Normalize to lowercase hexadecimal. Reject hashes with
  incorrect length for their algorithm.
- **Url**: Parse with a URL library, normalize scheme and host, preserve path
  case (paths are case-sensitive on most servers), strip tracking parameters.
- **EmailAddress**: Split at `@`, lowercase the domain portion, preserve local
  part case (per RFC 5321, local parts are case-sensitive in theory, though
  most servers treat them as case-insensitive).
- **CertificateFingerprint**: Normalize to lowercase hexadecimal without
  separators. Store the hash algorithm used (SHA-256 is standard).

### 3.3 Lifecycle Stages

An IOC passes through a defined lifecycle within the system:

```
Creation --> Validation --> Enrichment --> Active --> Aging --> Retirement
   |             |              |           |          |           |
   |        dedup/normalize  add context  detection   decay     GC/archive
   |                         and scoring  matching   scoring
   v                                                              v
 Rejection                                                     Archive
(invalid format,                                          (audit trail)
 known false positive)
```

**Stage 1: Creation.** An IOC enters the system via one of:
- Operator manual entry (current HTTP POST endpoint)
- STIX/TAXII feed poll (proposed)
- MISP event synchronization (proposed)
- Detection-generated IOC (a detector discovers a new indicator and
  back-populates the intel store)
- Incident response import (bulk CSV/JSON ingestion)

**Stage 2: Validation.** The system verifies format correctness (is this a
valid IP address?), checks for duplicates, and normalizes the value. If the
IOC already exists, the system merges rather than overwrites -- updating
confidence if the new source is more authoritative, extending TTL if the new
observation is fresher.

**Stage 3: Enrichment.** Context is added: which feeds reported this IOC,
what MITRE ATT&CK techniques are associated, what malware families use this
infrastructure, what campaigns have been linked. This metadata is stored
alongside the core indicator.

**Stage 4: Active.** The IOC participates in detection-time enrichment. When
a detector evaluates a telemetry event, the enrichment pipeline queries the
substrate for matching IOCs and adjusts finding confidence accordingly.

**Stage 5: Aging.** As time passes, the IOC's effective confidence decays
according to a type-specific half-life model (Section 4). The IOC is still
active but contributes less to detection confidence.

**Stage 6: Retirement.** When effective confidence drops below a configurable
floor, or the absolute TTL expires, the IOC is retired. Retired IOCs are
moved to an archive (for audit and false-positive analysis) rather than
silently deleted.

---

## 4. IOC Freshness and Decay

### 4.1 The Problem with Binary TTL

The current implementation uses a binary expiration model: an IOC with
`expires_at > now` is fully active; one with `expires_at <= now` is fully
dead. This creates a cliff effect -- an IOC at 99.9% of its TTL has
identical detection weight to one ingested moments ago.

In practice, IOC relevance degrades continuously. Adversaries rotate
infrastructure, abandon domains, and update tooling. The rate of rotation
varies dramatically by indicator type.

### 4.2 Empirical IOC Half-Lives

Research from multiple threat intelligence providers [1, 2, 3] suggests the
following approximate half-lives for different IOC types:

| Indicator Type | Median Active Life | Suggested Half-Life | Rationale |
|---------------|-------------------|--------------------|-----------|
| IP Address (C2) | 3--7 days | 4 days (345,600s) | Adversaries rotate C2 IPs frequently; bulletproof hosting may extend this. Mandiant M-Trends 2024 reports median C2 IP lifespan of 4.5 days [1]. |
| IP Address (scanning) | 12--48 hours | 1 day (86,400s) | Mass-scanning IPs (Shodan-like reconnaissance, botnet spray) rotate rapidly. Greynoise data shows 80% of scanner IPs inactive within 48 hours [2]. |
| Domain (C2) | 7--30 days | 14 days (1,209,600s) | Domain infrastructure is more expensive to rotate. DGA domains are shorter-lived; registered domains with established DNS records persist longer. |
| Domain (phishing) | 1--5 days | 2 days (172,800s) | Phishing domains are burned quickly once reported. Google Safe Browsing median detection-to-takedown is 27 hours [3]. |
| File Hash (commodity) | 30--180 days | 60 days (5,184,000s) | Commodity malware samples persist. Polymorphic packers reduce effective hash life; unpacked/behavioral hashes last longer. |
| File Hash (targeted) | 6--24 months | 120 days (10,368,000s) | APT tooling is reused across campaigns. Custom implants may be used for years with minor modifications. |
| URL | 1--7 days | 3 days (259,200s) | Payload delivery URLs are ephemeral. Path rotation is cheaper than domain rotation. |
| Email Address | 7--90 days | 30 days (2,592,000s) | Phishing sender addresses persist across campaigns but are eventually burned by reputation systems. |
| Certificate Fingerprint | 90--365 days | 180 days (15,552,000s) | TLS certificates have long validity periods. Adversaries reuse certificates across infrastructure more than they reuse IPs or domains. |

These values should be treated as defaults. Operators must be able to override
per-feed and per-indicator, and the system should eventually learn empirical
half-lives from its own false-positive and true-positive feedback.

### 4.3 Decay Model

We propose a decay model that mirrors the existing pheromone half-life
framework. For a `ThreatIntelEntry` with initial confidence `c_0`, ingested
at time `t_0`, with type-specific half-life `h`:

```
effective_confidence(t) = c_0 * 2^(-(t - t_0) / h)
```

This is mathematically identical to `PheromoneDeposit::strength_at`:

```rust
// Existing pheromone decay (crates/swarm-core/src/pheromone.rs)
pub fn strength_at(&self, now: i64) -> f64 {
    if now <= self.timestamp {
        return self.confidence;
    }
    let elapsed = (now - self.timestamp) as f64;
    self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life)
}
```

**Unit note**: Pheromone deposits use seconds for both `timestamp` and
`decay_half_life`, so `elapsed` is in seconds and no conversion is needed.
`ThreatIntelEntry` timestamps (`expires_at`) are in milliseconds. The
proposed `effective_confidence` method below converts elapsed milliseconds
to seconds before dividing by the half-life.

The `ThreatIntelEntry` struct needs two additional fields to support this:

```rust
pub struct ThreatIntelEntry {
    pub indicator_type: ThreatIntelIndicatorType,
    pub value: String,
    pub confidence: f64,            // initial confidence at ingestion
    pub expires_at: i64,            // hard TTL (unix timestamp milliseconds)
    pub ingested_at: i64,           // NEW: ingestion time (unix timestamp milliseconds)
    pub decay_half_life_secs: f64,  // NEW: type-specific half-life in seconds
}
```

Both `ingested_at` and `expires_at` use millisecond timestamps, matching
the existing convention for `ThreatIntelEntry`. The half-life is in
seconds for consistency with `PheromoneDeposit::decay_half_life` and to
avoid sub-second precision that has no empirical basis for IOC aging.

The effective confidence at query time becomes:

```rust
impl ThreatIntelEntry {
    pub fn effective_confidence(&self, now: i64) -> f64 {
        if now <= self.ingested_at {
            return self.confidence;
        }
        if now >= self.expires_at {
            return 0.0;
        }
        let elapsed = (now - self.ingested_at) as f64 / 1000.0; // ms to seconds
        self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life_secs)
    }
}
```

This provides smooth degradation instead of a cliff. An IOC ingested 7 days
ago with a 4-day half-life retains approximately 30% of its original
confidence -- still useful as a weak signal but no longer sufficient to
drive high-confidence detections on its own.

### 4.4 Interaction with Pheromone Decay

Threat intel decay and pheromone decay are complementary but distinct:

- **Pheromone decay** models the aging of a *specific detection event*. A
  deposit saying "we saw C2 traffic to 198.51.100.42 at 14:00" loses
  relevance as time passes because the situation may have changed.
- **Threat intel decay** models the aging of *knowledge about adversary
  infrastructure*. The assertion "198.51.100.42 is a known C2 server" loses
  relevance as the adversary may have abandoned that IP.

When both apply (a finding enriched by threat intel and then deposited as a
pheromone), the effective signal strength at time `t` is:

```
S(t) = deposit_confidence(t) * intel_confidence_factor(t)
```

Where `deposit_confidence(t)` follows pheromone decay and
`intel_confidence_factor(t)` follows IOC decay. This double-decay ensures
that stale intelligence about stale detections attenuates faster than either
factor alone.

### 4.5 Refresh and Reinforcement

When a feed re-reports an IOC that already exists in the cache, the system
should:

1. Reset `ingested_at` to the current time (the indicator is confirmed still
   active)
2. Recompute `expires_at` based on the new ingestion time plus the
   feed-specific TTL
3. Increase confidence if the new source is independent (multi-source
   corroboration -- see Section 7)
4. Preserve the original provenance record (append, do not overwrite)

This refresh mechanism is analogous to pheromone reinforcement: repeated
observations of the same threat indicator strengthen the signal, just as
multiple agent deposits into the same threat class increase concentration.

---

## 5. Feed Sourcing Strategy

### 5.1 STIX/TAXII 2.1 Protocol Overview

STIX (Structured Threat Information Expression) 2.1 is the OASIS standard for
threat intelligence exchange [4]. TAXII (Trusted Automated eXchange of
Indicator Information) 2.1 is the transport protocol. Together they define:

- **STIX Domain Objects (SDOs)**: Indicator, Malware, Attack-Pattern,
  Campaign, Threat-Actor, etc.
- **STIX Cyber-observable Objects (SCOs)**: ipv4-addr, domain-name, file,
  url, email-addr, x509-certificate, etc.
- **STIX Relationships (SROs)**: Links between SDOs (e.g., indicator
  "indicates" malware, malware "uses" attack-pattern)
- **TAXII Collections**: Named sets of STIX objects served by a TAXII server
- **TAXII Channels**: Real-time notification streams (TAXII 2.1)

The relevant TAXII operations for feed ingestion:

1. **Discovery** (`GET /taxii2/`): Enumerate available API roots
2. **Collection listing** (`GET /{api-root}/collections/`): Enumerate
   available collections
3. **Object retrieval** (`GET /{api-root}/collections/{id}/objects/`):
   Paginated retrieval of STIX objects, with `added_after` filtering for
   incremental polling

### 5.2 Feed Evaluation Criteria

Not all threat intelligence feeds are equal. We propose evaluating feeds
across five dimensions:

| Criterion | Weight | Description |
|-----------|--------|-------------|
| **Accuracy** | 0.30 | False-positive rate. Measured empirically by correlating feed IOCs against known-benign traffic in a staging environment. |
| **Timeliness** | 0.25 | Time-to-publication after indicator first observed in the wild. Faster feeds get higher weight in confidence scoring. |
| **Coverage** | 0.20 | Breadth of indicator types and threat categories. A feed covering only IP addresses is less valuable than one covering IPs, domains, hashes, and URLs. |
| **Stability** | 0.15 | API reliability, uptime, pagination correctness, schema compliance. Feeds that frequently break or return malformed STIX objects impose engineering cost. |
| **Attribution depth** | 0.10 | Whether the feed provides context beyond bare IOCs: campaign linkage, MITRE ATT&CK mapping, malware family association. |

### 5.3 Recommended Feed Portfolio

A balanced deployment should ingest from multiple source tiers:

- **Tier 1 -- Open Source**: Abuse.ch (URLhaus, MalwareBazaar, ThreatFox),
  AlienVault OTX, EmergingThreats (Proofpoint), Feodo Tracker, CISA KEV.
  No cost, moderate quality, high update frequency (minutes to daily).
- **Tier 2 -- Community**: MISP default feeds, CIRCL OSINT, Botvrij.
  Free registration, strong curation, event-based context via MISP API.
- **Tier 3 -- Commercial**: CrowdStrike Falcon Intelligence, Recorded Future,
  Mandiant Advantage, VirusTotal Premium. Paid, high accuracy, full STIX 2.1
  support, campaign attribution and MITRE ATT&CK mapping.

### 5.4 Polling Strategy

Each feed should be polled at a cadence matching its update frequency and the
half-life of its primary indicator types:

```
poll_interval = min(feed_update_frequency, min_indicator_half_life / 4)
```

The division by 4 ensures that the system samples the feed at least four
times per half-life period, satisfying the Nyquist criterion for tracking
confidence changes. For a C2 IP feed with a 4-day half-life, this gives a
maximum poll interval of 1 day. For a URL feed updated every 5 minutes, the
poll interval should be 5 minutes.

Rate limiting must be enforced per-feed to respect API quotas. The polling
scheduler should use exponential backoff on failure and circuit-breaker
patterns to avoid hammering a degraded feed.

### 5.5 Feed Reliability and Degraded-Mode Operation

Feed infrastructure is inherently unreliable. TAXII servers go down, rate
limits are exceeded, TLS certificates expire, and API endpoints are
decommissioned without notice. The system must define explicit behavior for
every failure scenario.

**Single-feed failure with cache retention.** When one feed becomes
unreachable, the system continues operating on cached IOCs from that feed.
The decay model (Section 4.3) naturally handles staleness: IOCs from the
failed feed decay toward zero confidence at their type-specific half-life
rate. For a C2 IP feed with a 4-day half-life, detection quality degrades
gradually over days, not instantly. The operator impact is a slow increase
in false negatives for that feed's coverage area, not a cliff.

**All-feeds-down (cache-only operation).** When all feeds are unreachable,
the system operates entirely on cached IOCs. The critical question is
whether the decay model creates a simultaneous expiration cliff. It does
not, because entries arrive at different times with different TTLs. However,
after approximately `2 * max_half_life` without any feed refresh, the
effective confidence of the oldest entries will be negligible (below 25% of
original). The system should emit a `feed_all_stale` health event when no
feed has been successfully polled within `max(feed_half_lives) / 2`,
alerting operators that detection quality is degrading.

**Feed poisoning (false IOCs injected).** A compromised feed may inject
false positives (benign IPs flagged as malicious) or false negatives
(known-bad IOCs removed). Mitigations:

- **Cross-feed consistency checks:** Flag IOCs reported by only one
  low-reputation feed. Require `min_independent_sources >= 2` before
  applying full confidence weighting for feeds below reputation 0.5.
- **Velocity limits:** Cap the number of new IOCs accepted per feed per
  poll interval (e.g., 10,000). A sudden spike in IOC volume from a
  single feed should trigger a circuit breaker and operator alert.
- **Retroactive audit:** When a feed is identified as compromised, the
  system must be able to purge all IOCs sourced exclusively from that
  feed and re-evaluate recent findings that were enriched by those IOCs.

**Circuit breaker implementation.** Each feed client should implement a
three-state circuit breaker (closed/open/half-open):

| State | Behavior | Transition |
|-------|----------|------------|
| Closed | Normal polling at configured interval | Open after N consecutive failures (default: 5) |
| Open | No polling; emit `feed_circuit_open` event | Half-open after cooldown (default: 5 minutes) |
| Half-open | Single probe request | Closed on success; open on failure |

The `governor` crate's rate-limiter combined with a manual state machine
provides this pattern without external dependencies.

**Feed freshness monitoring.** The system should expose per-feed health
metrics:

- `feed_last_success_timestamp` -- wall-clock time of last successful poll
- `feed_staleness_seconds` -- `now - feed_last_success_timestamp`
- `feed_consecutive_failures` -- count of sequential poll failures
- `feed_circuit_state` -- current circuit breaker state

Alert thresholds: warn when `feed_staleness_seconds > 2 * poll_interval`,
critical when `feed_staleness_seconds > max_half_life / 2`.

### 5.6 Cache Warmup and Cold-Start Behavior

On first startup with an empty threat-intel cache, the system has zero
enrichment capability. The cold-start protocol:

1. **Feed bootstrap phase.** The FeedScheduler performs an initial full
   pull from all configured feeds before the runtime begins accepting
   telemetry. For TAXII feeds, this means paginating from `added_after=0`
   until all available indicators are ingested. Typical TAXII servers
   paginate at 1000-5000 objects per page with ~200ms per page. A feed
   with 50,000 indicators requires ~10-50 pages, taking 2-10 seconds.

2. **Parallel feed ingestion.** Multiple feeds should be bootstrapped
   concurrently. With 5 feeds bootstrapping in parallel, total warmup
   time is bounded by the slowest feed, typically 5-15 seconds.

3. **Readiness gating.** The runtime should expose a readiness probe that
   reports `not_ready` until at least one feed has been successfully
   ingested. In Kubernetes deployments, this prevents the pod from
   receiving traffic before enrichment is available. Configuration:
   `min_feeds_for_ready: usize` (default: 1).

4. **Graceful degradation during warmup.** If the operator configures
   `allow_unenriched_detection: true` (default), the system accepts
   events during warmup at reduced enrichment quality. Events processed
   before the cache is populated receive no threat-intel enrichment but
   are still evaluated by detectors. Batch enrichment (Mode 2, Section
   6.2) retroactively enriches these early events once the cache is warm.

Estimated warmup time for the recommended feed portfolio (Section 5.3)
is 10-30 seconds from cold start, assuming typical TAXII server response
times and 5 concurrent feed connections.

---

## 6. Enrichment Pipeline Architecture

### 6.1 Current Architecture

The current enrichment pipeline is synchronous and query-time:

```
TelemetryEvent
  --> DetectionStrategy::evaluate()        [detector produces findings]
  --> enrich_findings_with_threat_intel()   [substrate lookup per candidate IOC]
  --> resolve_deposits()                   [findings become pheromone deposits]
  --> sign_deposit() + substrate.deposit() [signed deposits enter substrate]
```

This is the `detect_and_deposit` function in `pipeline.rs`. The enrichment
step runs between detection and deposit, modifying finding confidence before
the finding is converted to a signed pheromone deposit.

### 6.2 Enrichment Modes

We propose three enrichment modes, selected by IOC type and operational
context:

**Mode 1: Inline enrichment (current model, enhanced)**

The detector evaluates an event, the enrichment layer queries the local
threat-intel cache, and findings are annotated before deposit. This is the
only mode that exists today. It should be extended to:

- Support all six indicator types (currently only Domain and IpAddress)
- Use effective confidence (decayed) rather than raw confidence
- Support CIDR range matching for IP indicators
- Support parent-domain matching for domain indicators (already partially
  implemented via `candidate_domain_values`)

**Mode 2: Batch enrichment (new)**

A background task periodically scans recent deposits and re-evaluates them
against the current threat-intel cache. This catches cases where:

- A detection occurred before the relevant IOC was ingested
- An IOC was updated (higher confidence, new source) after the original
  detection
- A previously unknown IP/domain was added to a feed, retroactively
  making a prior detection more significant

Batch enrichment should produce *supplementary deposits* rather than
modifying existing signed deposits (which would invalidate signatures).

**Mode 3: External enrichment (new)**

For IOCs not found in the local cache, the system can optionally query
external services (VirusTotal, AbuseIPDB, Shodan) at detection time. This
mode introduces latency and external dependencies, so it must be:

- Gated behind a feature flag (`external_enrichment_enabled`)
- Rate-limited per service (configurable tokens-per-second)
- Cached aggressively (negative results cached for shorter TTL than
  positive results)
- Non-blocking for the detection pipeline (findings proceed with local
  enrichment; external results arrive asynchronously and trigger
  supplementary deposits)

**Supplementary deposit lifecycle.** External enrichment results must not
block the detection pipeline. The concrete mechanism:

1. The detection pipeline completes normally with L1/L2 enrichment only.
   Findings are deposited as signed pheromones immediately.
2. For cache-miss indicators, the pipeline enqueues an
   `ExternalEnrichmentRequest { indicator_type, value, original_finding_id,
   event_id }` to a bounded async channel (capacity: 1,000).
3. A dedicated `ExternalEnrichmentWorker` task drains this channel,
   queries external services (VirusTotal, AbuseIPDB) with rate limiting,
   and on a hit:
   a. Stores the result in L2 (substrate) via `store_threat_intel_entry`
   b. Creates a **supplementary deposit** -- a new `PheromoneDeposit` with
      `agent_id = "enrichment-external:{service_name}"`, carrying the
      external enrichment result as evidence. This deposit is signed with
      a dedicated "enrichment agent" signing key provisioned at startup.
   c. The supplementary deposit references `original_finding_id` in its
      `indicator` JSON, enabling correlation with the original detection.
4. The original finding's confidence is **not retroactively modified**
   (that would invalidate its signature). Instead, the supplementary
   deposit adds to the threat-class concentration, indirectly increasing
   the swarm's aggregate signal for that threat class.

This design means external enrichment latency (10-500ms) never appears in
the critical detection path. The trade-off is that external enrichment
contributes to concentration-based escalation (which may trigger alerts)
rather than directly boosting individual finding confidence.

**Impact on substrate write pressure.** At 10K events/sec with a 5% L2
cache miss rate and 20% external hit rate, external enrichment produces
~100 supplementary deposits/sec -- negligible relative to the 3,000
deposits/sec from direct detection (Section 3.2 of Doc 04)

### 6.3 Caching Strategy

The threat-intel cache should be layered:

```
L1: Hot cache (in-memory HashMap, <1us lookup)
    - Most recently queried IOCs
    - Capacity: 100K entries (configurable)
    - Eviction: LRU with TTL floor

L2: Substrate cache (current BTreeMap, ~1us lookup)
    - All active IOCs from ingested feeds
    - Capacity: 1M entries target
    - Eviction: TTL-based GC (current gc_expired_threat_intel)

L3: External query (10-500ms per lookup)
    - On-demand queries to VirusTotal, AbuseIPDB, etc.
    - Results promoted to L2 on hit
    - Negative results cached in L1 with short TTL (5 minutes)
```

The current implementation operates entirely at L2. Adding L1 is a
performance optimization for high-throughput deployments where the same IOCs
are queried repeatedly (e.g., a beaconing host hitting the same C2 IP every
60 seconds). Adding L3 is a coverage optimization for environments with
external API access.

### 6.4 Rate Limiting for External APIs

External enrichment queries must respect per-service rate limits. Each service
is configured with `requests_per_minute`, `timeout_ms`, supported indicator
types, and per-polarity cache TTLs (positive hits cached longer than negative
misses). A token-bucket rate limiter (e.g., `governor` crate) is instantiated
per service. When the bucket is empty, queries are queued rather than dropped,
with a maximum queue depth to prevent unbounded memory growth.

### 6.5 Enrichment Latency Impact Analysis

The current enrichment implementation (Section 6.1) operates within Doc 04's
latency budget of 2-10us per event, because it performs at most 0-3
`BTreeMap` lookups against a small cache. The enhancements proposed in this
document significantly increase enrichment cost. This section models the
impact explicitly.

**Current state (2 event types, exact-match only):**

| Component | Cost | Frequency |
|-----------|------|-----------|
| Read-lock acquisition on `threat_intel_entries` | ~0.5us | Per query |
| `BTreeMap::get` (exact key) | ~0.3us | Per query |
| `.cloned()` on `ThreatIntelEntry` | ~0.2us | Per hit |
| Candidate query generation | ~0.5us | Per event |
| **Total per event (0-3 queries)** | **~2-4us** | |

**Proposed state (7 event types, CIDR + parent-domain + noisy-OR):**

| Component | Cost | Frequency |
|-----------|------|-----------|
| Read-lock acquisition | ~0.5us | Per query |
| `BTreeMap::get` (exact key) | ~0.3us | Per exact query |
| CIDR trie traversal (Patricia trie, 32-bit depth) | ~2-5us | Per IP query |
| Parent-domain expansion (avg 2.5 labels) | ~1.5us | Per DNS query |
| Noisy-OR scoring iteration | ~0.5us per source | Per match |
| `.cloned()` on expanded `ThreatIntelEntry` (with `Vec<ThreatIntelSource>`) | ~0.5us | Per hit |
| Candidate query generation (URL/hash extraction from command lines) | ~2-5us | Per ProcessStart event |
| **Total per event (3-10 queries, with 1-3 matches)** | **~15-50us** | |

The enriched enrichment path pushes the per-event cost from 2-10us to
15-50us -- a 5-10x increase. This remains within Doc 04's 10ms p99 SLO
with substantial headroom, but it is no longer negligible relative to
detection (10-50us) and must be accounted for in the latency budget.

**Tiered enrichment strategy.** To bound worst-case enrichment latency,
the pipeline should implement two enrichment tiers:

- **Fast-path (inline, <10us target):** Exact-match lookups in L1/L2
  for the primary indicator extracted from the event (destination IP for
  NetworkConnect, query domain for DNS). This is the current model
  applied to the dominant indicator.
- **Supplementary (async, unbounded):** CIDR range matching, parent-domain
  expansion beyond the registrable domain, command-line URL/hash extraction,
  and noisy-OR multi-source scoring. These run in a post-deposit enrichment
  task that produces supplementary deposits (same mechanism as Mode 3
  external enrichment, Section 6.2).

This tiered approach preserves the current 2-10us inline enrichment budget
while still achieving comprehensive enrichment. The configuration knob
`enrichment_inline_max_queries: usize` (default: 3) caps the number of
substrate queries in the fast path.

**Batch query optimization.** Whether enrichment runs inline or async,
multiple lookups against the same `BTreeMap` should acquire the read-lock
once. A `query_threat_intel_entries_batch` method on the substrate trait
would accept a `&[(ThreatIntelIndicatorType, &str)]` slice and return
results for all queries under a single lock acquisition, reducing lock
overhead from O(queries) to O(1) per event.

---

## 7. Confidence Scoring

### 7.1 Current Model

The current confidence model is minimal:

```rust
let confidence_boost = matches
    .iter()
    .map(|entry| entry.confidence)
    .fold(0.0, f64::max);
// ...
let enriched_confidence = (base_confidence + confidence_boost).min(1.0);
```

This takes the maximum confidence across all matching IOCs and adds it to the
base detection confidence. Problems:

1. **No diminishing returns**: If two feeds both report an IP at 0.8
   confidence, the system uses 0.8 (max). It should use something higher
   than 0.8 but less than 1.6 (sum) -- corroboration matters but should
   not produce unbounded confidence.
2. **No source weighting**: A hit from a high-quality commercial feed is
   treated identically to a hit from a noisy open-source list.
3. **No age weighting**: A fresh IOC and a 6-month-old IOC contribute
   equally (until the old one hits its hard TTL and vanishes entirely).

### 7.2 Proposed Multi-Factor Confidence Model

We propose replacing the max-based boost with a multi-factor model:

```
effective_boost = 1 - PRODUCT_i(1 - w_i * c_i(t))
```

Where:
- `c_i(t)` is the effective (decayed) confidence of the i-th matching IOC
  at query time `t`
- `w_i` is the source reputation weight for the feed that contributed the
  i-th IOC (0.0--1.0)
- The product-of-complements formula ensures diminishing returns: two
  independent sources at 0.5 confidence produce `1 - (1-0.5)(1-0.5) = 0.75`,
  not 1.0

This is the standard "noisy-OR" model from probabilistic reasoning [5],
widely used in Bayesian threat scoring. The model assumes conditional
independence between sources -- each feed's report is treated as an
independent observation. In practice, feeds share upstream data (e.g.,
multiple aggregators re-publishing the same VirusTotal sample), so
correlated sources should be deduplicated before applying the formula.
The `feed_id` provenance field (Section 7.4) enables this deduplication.

The enriched finding confidence becomes:

```
enriched_confidence = min(base_confidence + effective_boost * (1.0 - base_confidence), 1.0)
```

The `(1.0 - base_confidence)` factor ensures that threat intel lifts toward
1.0 but never overshoots. A high base confidence leaves less room for intel
to increase it; a low base confidence benefits more from corroborating intel.

Note that this is a semantically different formula from the current additive
model (`base + max_match`). The transition should be gated behind a
configuration flag so operators can A/B test the scoring models against
their environment's false-positive baseline before committing to the switch.

**Migration validation requirements.** Changing the confidence model affects
downstream pheromone concentration thresholds (`alert_threshold: 2.0`,
`incident_threshold: 5.0` in default `PheromoneConfig`) which were tuned
for the current additive scoring model. Before enabling the noisy-OR model
in production:

1. **Baseline capture:** Record the distribution of finding confidence
   values under the current additive model using production-representative
   telemetry (minimum 24 hours of representative traffic). Key metrics:
   mean finding confidence, p50/p95/p99 confidence, escalation trigger
   rate, false-positive rate.
2. **Shadow scoring:** Run the noisy-OR model in parallel (shadow mode)
   against the same telemetry, logging the alternative confidence values
   without applying them. Compare distributions.
3. **Threshold retuning guide:** Quantify the expected impact on
   escalation rates. The noisy-OR model generally produces lower single-
   match boosts (e.g., one source at 0.8 confidence yields 0.8 with
   additive vs. 0.8 with noisy-OR for a single source -- identical) but
   higher multi-match boosts (two sources at 0.8 yield 0.8 additive vs.
   0.96 noisy-OR). This means alert storms are more likely when multiple
   feeds corroborate an IOC. Operators may need to raise
   `alert_threshold` by 10-20% to maintain the same alert volume.
4. **Rollback plan:** The configuration flag must support runtime
   switching without restart, so operators can revert immediately if the
   new model produces unacceptable false-positive rates.

### 7.3 Source Reputation Weighting

Each feed is assigned a reputation score `w` between 0.0 and 1.0:

| Reputation Tier | Score Range | Description |
|----------------|------------|-------------|
| Authoritative | 0.9--1.0 | CISA, vendor-specific feeds for own products |
| High | 0.7--0.89 | Major commercial feeds (CrowdStrike, Mandiant) |
| Medium | 0.4--0.69 | Curated community feeds (MISP communities, Abuse.ch) |
| Low | 0.1--0.39 | Unvetted open-source lists, user-submitted IOCs |

Reputation scores should be stored per-feed and adjustable by operators.
Over time, the system should track per-feed true-positive and false-positive
rates and automatically adjust reputation scores.

### 7.4 Provenance Tracking

To support multi-source corroboration and source reputation, each IOC must
track its provenance:

```rust
pub struct ThreatIntelEntry {
    // ... existing fields ...
    pub sources: Vec<ThreatIntelSource>,
}

pub struct ThreatIntelSource {
    pub feed_id: String,
    pub feed_reputation: f64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub stix_indicator_id: Option<String>,
    pub tags: Vec<String>,  // malware family, campaign, ATT&CK technique
}
```

When a new feed reports an IOC already in the cache, a new `ThreatIntelSource`
entry is appended rather than overwriting the existing one. The effective
confidence computation iterates over all sources, applying per-source
reputation weighting and temporal decay.

---

## 8. Integration with Detection Pipeline

### 8.1 Enrichment Scope Expansion

The current `candidate_threat_intel_queries` function covers two event types.
We propose expanding to all payload variants:

| Event Type | IOC Queries |
|-----------|------------|
| `DnsQuery` | Domain (with parent-domain expansion) -- **already implemented** |
| `NetworkConnect` | IpAddress -- **already implemented** |
| `ProcessStart` | FileHash (from `executable_path` or `command_line` hash), Domain (from `command_line` URL extraction) -- **new** |
| `RegistryAccess` | Domain/URL/IP extracted from registry value data -- **new** |
| `RegistryPersistence` | Domain/URL/IP extracted from persistence value, FileHash of target executable -- **new** |
| `FilePersistence` | FileHash of persisted file, Domain/URL extracted from file path or content -- **new** |
| `AuthenticationEvent` | IpAddress of source, EmailAddress of authenticating identity -- **new** |

### 8.2 Confidence Adjustment Logic

The enrichment pipeline should apply different confidence adjustments based
on the nature of the match:

**Direct match** (IP in network event matches IP IOC): Full confidence boost.
This is a first-order correlation -- the observed indicator directly matches
known-bad infrastructure.

**Derived match** (domain in DNS query matches domain IOC, and the resolved
IP also matches an IP IOC): Enhanced confidence boost. Two independent
indicator types corroborate the same observation.

**Contextual match** (process that made the connection has a hash matching a
known-bad hash IOC): Maximum confidence boost. The combination of a known-bad
process communicating with known-bad infrastructure is extremely high-signal.

```rust
enum MatchType {
    Direct,     // single indicator match
    Derived,    // two related indicators match
    Contextual, // indicator + behavioral context match
}

fn confidence_multiplier(match_type: MatchType) -> f64 {
    match match_type {
        MatchType::Direct => 1.0,
        MatchType::Derived => 1.3,
        MatchType::Contextual => 1.6,
    }
}
```

### 8.3 False-Positive Suppression

Threat intel should also support negative indicators -- entries that suppress
false positives rather than boosting confidence:

- **Known-benign infrastructure**: CDN IP ranges (Cloudflare, Akamai),
  cloud provider ranges (AWS, Azure, GCP), popular SaaS domains
- **Organization-specific allowlists**: Internal DNS names, partner IPs,
  approved software hashes

These are stored as `ThreatIntelEntry` instances with negative confidence
values (e.g., -0.5), which reduce finding confidence when matched. This
requires relaxing the current `confidence` field's implicit 0.0--1.0
range to -1.0--1.0, with validation enforced at the API boundary. The
enrichment pipeline applies them identically to positive indicators, but
the math naturally produces suppression:

```
enriched_confidence = base_confidence + effective_boost
// If effective_boost is negative, confidence decreases
```

A floor of 0.0 prevents confidence from going negative. Operators should
be able to mark specific suppression entries as "hard allowlist" which
cause findings to be dropped entirely rather than merely downweighted.

---

## 9. Integration with Pheromone Substrate

### 9.1 IOCs as Pheromone Deposits

The insight connecting threat intelligence to the stigmergic model:
**IOCs are a form of externally-sourced pheromone deposit**. When a feed
reports that `198.51.100.42` is a C2 server, this is equivalent to an
external "agent" depositing a pheromone of class `CommandAndControl` with
the indicator `{"ip": "198.51.100.42"}`.

The key difference is provenance: pheromone deposits originate from local
detection agents and carry Ed25519 signatures; threat intel entries originate
from external feeds and carry feed provenance records. But their function
in the system is identical -- they increase the swarm's sensitivity to
specific threat indicators.

### 9.2 Concentration-Based Relevance

The pheromone substrate already computes per-threat-class concentration:

```rust
pub struct PheromoneConcentration {
    pub threat_class: ThreatClass,
    pub total_strength: f64,
    pub distinct_sources: usize,
    pub peak_confidence: f64,
}
```

Threat intel entries should contribute to this concentration. If the threat
intel cache contains 50 `CommandAndControl` IP indicators with average
effective confidence 0.6, the C2 concentration should reflect this
heightened awareness -- even before any detection event occurs.

This creates a "priming" effect: when the swarm has high threat-intel
concentration for a particular threat class, detectors operating in that
class should lower their thresholds (become more sensitive). This is the
stigmergic equivalent of ants detecting high pheromone concentration and
increasing their foraging intensity.

### 9.3 Cross-Detector Correlation via Shared Intel

The current enrichment pipeline queries threat intel independently per
detector invocation. With IOCs modeled as pheromone deposits, cross-detector
correlation becomes natural:

1. The DNS detector sees a query for `evil.example.com` and deposits a
   pheromone for `CommandAndControl`
2. The network detector sees a connection to `198.51.100.42` (which resolves
   from `evil.example.com`) and also deposits a pheromone for
   `CommandAndControl`
3. Both deposits reference threat-intel entries that link to the same campaign
4. The substrate's concentration aggregation combines these deposits, and the
   `distinct_sources >= min_sources_for_escalation` check triggers an
   escalation

Without shared threat intel, these two detections are independent signals.
With shared threat intel providing the campaign linkage, they become
correlated observations of the same adversary activity -- which is precisely
what the pheromone model was designed to surface.

### 9.4 Proposed Substrate Extensions

To support IOC-as-pheromone, the `PheromoneSubstrate` trait should add three
operations: `threat_intel_concentration` (aggregate per-threat-class intel
strength, mirroring `PheromoneConcentration`), `store_threat_intel_batch`
(bulk insert for feed ingestion), and `query_threat_intel_by_class` (retrieve
active IOCs for a threat class, enabling priming). The concentration result
tracks `total_effective_confidence`, `distinct_indicators`,
`distinct_sources`, and `peak_confidence` -- the same shape as
`PheromoneConcentration` to enable unified threshold evaluation.

---

## 10. STIX/TAXII Rust Implementation Considerations

### 10.1 Crate Ecosystem

The Rust ecosystem for STIX/TAXII is nascent. As of early 2026, the
available options are:

| Crate | Status | Notes |
|-------|--------|-------|
| `stix` | Unmaintained (last update 2023) | STIX 2.0 only, incomplete SDO coverage. No STIX 2.1 pattern support. |
| `taxii2-client` | Prototype | Basic TAXII 2.1 discovery and collection listing. No pagination or `added_after` support. |
| `serde_json` + manual parsing | Production-viable | Full control over schema, no external dependency risk |

*These assessments should be re-verified against crates.io before
implementation begins, as the Rust security ecosystem evolves quickly.*

Given the immaturity of existing crates, we recommend the manual-parsing
approach: define Rust structs for the STIX 2.1 objects we actually consume
(Indicator, Observable, Relationship) and deserialize them with `serde_json`.
This avoids taking a dependency on unmaintained crates and allows us to
validate exactly the fields we need.

### 10.2 STIX Indicator to ThreatIntelEntry Mapping

A STIX 2.1 Indicator object contains a `pattern` field in the STIX Pattern
Language:

```
[ipv4-addr:value = '198.51.100.42']
[domain-name:value = 'evil.example.com']
[file:hashes.'SHA-256' = 'a1b2c3...']
```

Parsing the full STIX Pattern Language (which supports AND, OR, comparison
operators, and object path expressions) is complex. For the initial
implementation, we recommend a restricted parser that handles only the
equality patterns above, which cover the vast majority of IOC indicators
in practice [6]. Patterns that cannot be parsed should be logged and
skipped rather than causing ingestion failures.

The mapping:

| STIX SCO Type | STIX Pattern | ThreatIntelIndicatorType |
|--------------|-------------|-------------------------|
| `ipv4-addr` | `[ipv4-addr:value = '...']` | `IpAddress` |
| `ipv6-addr` | `[ipv6-addr:value = '...']` | `IpAddress` |
| `domain-name` | `[domain-name:value = '...']` | `Domain` |
| `file` | `[file:hashes.'SHA-256' = '...']` | `FileHash` |
| `url` | `[url:value = '...']` | `Url` |
| `email-addr` | `[email-addr:value = '...']` | `EmailAddress` |
| `x509-certificate` | `[x509-certificate:hashes.'SHA-256' = '...']` | `CertificateFingerprint` |

### 10.3 Parsing Performance

STIX/TAXII responses can be large (tens of megabytes for bulk feed pulls).
Performance considerations:

- **Streaming deserialization**: Use `serde_json::StreamDeserializer` to
  process STIX bundles without loading the entire response into memory.
  A STIX Bundle's `objects` array can contain thousands of entries.
- **Parallel parsing**: For bulk ingestion, use `rayon` to parallelize
  the parsing of individual STIX objects within a bundle.
- **Schema validation**: Validate lazily. Parse the minimum fields needed
  for IOC extraction (`type`, `pattern`, `confidence`, `valid_from`,
  `valid_until`); ignore unknown fields. Note: while internal STS types
  like `NetworkConnectProfile` use `#[serde(deny_unknown_fields)]` for
  strict config validation, STIX parsing structs should use
  `#[serde(default)]` and allow unknown fields for resilience against
  schema evolution in external feeds.
- **Deduplication**: Track `id` fields to skip duplicate objects across
  paginated responses (TAXII pagination can repeat objects at page
  boundaries).

### 10.4 TAXII Client Implementation

A minimal TAXII 2.1 client wraps `reqwest` with rate limiting and supports
three credential modes: HTTP Basic, Bearer token, and mutual TLS. The three
essential operations are discovery (enumerate API roots), collection listing,
and paginated object retrieval with `added_after` filtering.

The `added_after` parameter is critical for incremental polling. The client
must persist the `X-TAXII-Date-Added-Last` header from each response and
use it as the `added_after` value in subsequent polls.

---

## 11. Privacy and Legal Considerations

### 11.1 Data Classification

Threat intel data falls into several sensitivity categories:

| Category | Example | Handling |
|----------|---------|----------|
| **Public IOCs** | Known-malicious IPs from public feeds | No restrictions on storage or sharing |
| **TLP:GREEN** | Community-shared MISP events | Share within the security community |
| **TLP:AMBER** | Commercial feed IOCs under license | Do not share outside the organization |
| **TLP:RED** | Incident-specific IOCs from active response | Do not share; restrict to named recipients |
| **Internal observables** | IPs, domains from internal telemetry | Subject to internal data governance |

The system must track TLP (Traffic Light Protocol) markings per IOC and
enforce sharing constraints. An IOC marked TLP:RED must not appear in
API responses to unauthorized consumers, must not be forwarded to external
feeds, and should be encrypted at rest with access-controlled keys.

### 11.2 GDPR and Data Protection

IOCs can constitute personal data under GDPR: IP addresses (Breyer v.
Germany, Case C-582/14), email addresses, and domain names containing
personal names. Key implications:

- **Lawful basis**: Legitimate interest (Article 6(1)(f)) is the applicable
  basis for cybersecurity processing, per Recital 49.
- **Data minimization**: Store only indicator values and operational metadata;
  no WHOIS registrant data unless strictly necessary.
- **Retention**: IOC TTLs serve as retention limits; GC must actually delete
  expired entries, not merely filter them from queries.
- **Right to erasure**: The operator API needs a DELETE endpoint for
  incorrectly flagged IOCs.
- **Cross-border transfers**: TAXII server jurisdiction must comply with
  GDPR Chapter V (adequacy decisions, SCCs, or BCRs).

### 11.3 Feed License Compliance

Commercial feeds impose redistribution prohibitions, usage restrictions
(detection-only vs. active blocking), and post-termination deletion
requirements. The system must track per-feed license metadata via a
`feed_license` field on `ThreatIntelSource` and enforce constraints
programmatically -- preventing, for example, a TLP:AMBER commercial IOC
from appearing in a shared TAXII collection.

---

## 12. Proposed Architecture

### 12.1 Crate Organization

We propose adding a new `swarm-intel` crate rather than expanding
`swarm-pheromone`, to maintain separation of concerns:

```
crates/
  swarm-core/          # shared types (ThreatIntelEntry, ThreatIntelIndicatorType)
  swarm-pheromone/     # substrate storage (unchanged storage trait)
  swarm-intel/         # NEW: feed ingestion, enrichment pipeline, scoring
    src/
      lib.rs
      feed/
        mod.rs         # FeedManager trait and scheduler
        taxii.rs       # TAXII 2.1 client
        misp.rs        # MISP API client
        abusech.rs     # Abuse.ch REST client
        otx.rs         # AlienVault OTX client
      stix/
        mod.rs         # STIX 2.1 type definitions
        parser.rs      # Pattern parser (restricted subset)
        mapper.rs      # STIX Indicator -> ThreatIntelEntry conversion
      scoring/
        mod.rs         # Multi-factor confidence model
        decay.rs       # Type-specific decay computation
        reputation.rs  # Source reputation management
      enrichment/
        mod.rs         # EnrichmentPipeline trait
        inline.rs      # Inline (current model, enhanced)
        batch.rs       # Batch re-evaluation
        external.rs    # External API enrichment
      cache/
        mod.rs         # L1 hot cache (LRU + TTL)
  swarm-whisker/       # detectors (unchanged)
  swarm-runtime/       # composition root (wires swarm-intel into pipeline)
```

### 12.2 Extended ThreatIntelEntry

The core type expands to support the full lifecycle. Key additions beyond the
current four fields: `decay_half_life_secs` and `ingested_at` for temporal
decay; `sources: Vec<ThreatIntelSource>` for multi-source provenance;
`threat_classes: Vec<ThreatClass>` for classification; `tlp:
TrafficLightProtocol` (White/Green/Amber/Red) for data-sharing governance;
and context fields for MITRE technique IDs, campaign names, and malware
family associations.

### 12.3 Feed Ingestion Pipeline

The ingestion pipeline flows through four stages: (1) **FeedScheduler** polls
TAXII servers, MISP instances, and REST APIs with per-feed rate limiting;
(2) **Feed Adapter** normalizes, validates, and deduplicates raw feed data
into canonical IOC records; (3) **Scoring Engine** applies the decay model,
source reputation weighting, and multi-source corroboration; (4) **Substrate
batch insert** via `store_threat_intel_batch()`.

### 12.4 Detection-Time Enrichment (Enhanced)

```
TelemetryEvent
  |
  v
DetectionStrategy::evaluate()
  |
  v
candidate_threat_intel_queries()  <-- expanded to all event types
  |
  v
L1 Cache Lookup (hot cache)
  |-- hit --> use cached entry (with effective_confidence(now))
  |-- miss --> L2 Substrate Lookup
                |-- hit --> promote to L1, use entry
                |-- miss --> (optional) L3 External Query
                              |-- hit --> store in L2, promote to L1, use entry
                              |-- miss --> cache negative result in L1
  |
  v
Multi-Factor Confidence Scoring
  |
  v
Annotate Finding Evidence
  |
  v
resolve_deposits() --> sign_deposit() --> substrate.deposit()
```

### 12.5 Migration Path

The architecture is designed for incremental adoption:

**Phase 1** (minimal disruption): Add `ingested_at` and `decay_half_life_secs`
fields to `ThreatIntelEntry` with backward-compatible defaults (`ingested_at`
defaults to 0, `decay_half_life_secs` defaults to `f64::INFINITY` to preserve
current binary-TTL behavior for entries lacking these fields). Modify
`enrich_findings_with_threat_intel` in `pipeline.rs` to use
`effective_confidence(now)` instead of raw `confidence`. This touches
`swarm-core` (type change), `swarm-pheromone` (all three backend
store/query implementations and JSONL deserialization), and `swarm-runtime`
(enrichment logic).

**Phase 2**: Create `swarm-intel` crate with the scoring engine and inline
enrichment enhancements. Expand `candidate_threat_intel_queries` to all event
types. Add CIDR range matching for IP indicators.

**Phase 3**: Implement TAXII 2.1 client and feed scheduler. Add Abuse.ch
and OTX adapters as the first automated feeds.

**Phase 4**: Implement batch enrichment, external enrichment (L3), and the
L1 hot cache. Add provenance tracking and multi-source corroboration.

---

## 13. Open Questions and Future Work

### 13.1 Open Questions

1. **Hash algorithm disambiguation**: The current `FileHash` type does not
   distinguish MD5 from SHA-256. Should the `ThreatIntelIndicatorType` include
   a hash algorithm field, or should the value format self-identify (e.g., by
   length)?

2. **CIDR range indexing**: Efficient CIDR matching against millions of
   entries requires a trie-based index (e.g., Patricia trie). Should this live
   in the substrate (adding complexity to all backends) or in a specialized
   index maintained by `swarm-intel`?

3. **Negative IOC authority**: Who is authorized to add suppression entries
   (negative confidence IOCs)? Overly broad suppression (e.g., suppressing
   all of AWS's IP space) could create blind spots. Should there be a
   governance review process for suppression entries?

4. **Feed poisoning resistance**: If an adversary compromises a feed and
   injects false positives or false negatives, how does the system detect
   and recover? Cross-feed consistency checks (flagging IOCs reported by
   only one low-reputation feed) are a starting point, but adversary-
   controlled feeds require deeper analysis.

5. **IOC-to-pheromone deposit bridging**: Should threat intel entries actually
   produce signed pheromone deposits (requiring a "feed agent" with a signing
   key), or should they influence concentration through a separate aggregation
   path?

6. **Timestamp normalization inconsistency**: Both `pipeline.rs` and
   `network_connect.rs` contain identical `normalized_timestamp_ms` functions
   that heuristically convert seconds to milliseconds when
   `timestamp.abs() < 100_000_000_000`. This heuristic can produce incorrect
   results for edge-case timestamps. Since the decay model (Section 4.3)
   requires precise elapsed-time computation, inconsistent normalization would
   produce incorrect decay curves. The function should be centralized in
   `swarm-core` with explicit validation rejecting timestamps outside a
   reasonable range (e.g., 2000-2100).

7. **Substrate backend scalability**: The current `BTreeMap`-based storage
   performs O(log n) lookup by exact key. With millions of entries and CIDR
   range queries, should the system adopt an embedded database (e.g., `redb`,
   `sled`) or maintain the current approach with a specialized index overlay?

### 13.2 Future Work

- **Automated reputation calibration**: Adjust per-feed reputation scores
  based on operator feedback (confirmed vs. dismissed findings).
- **YARA rule integration**: Store YARA rules as an indicator type; evaluate
  against `FilePersistence` event content.
- **Graph-based correlation**: IOC relationship graph enabling indirect
  correlation discovery (IP hosts domain, domain delivers malware).
- **Federated sharing**: TAXII server mode for cooperative defense between
  STS deployments.
- **ML-based decay**: Learned decay curves replacing fixed half-lives, based
  on historical true-positive rates per indicator type and source.
- **Fuzzy matching**: ssdeep/TLSH for polymorphic file hash variants;
  homoglyph and DGA detection for domains.

---

## 14. Enrichment Quality Metrics

Operators need quantitative feedback on whether threat-intel enrichment is
contributing to detection quality. Without metrics, enrichment is a black
box that consumes resources with unmeasured benefit.

### 14.1 Core Enrichment Metrics

The following metrics should be exposed via the existing Prometheus pipeline
(`CriticalPathMetrics`):

| Metric | Type | Description |
|--------|------|-------------|
| `enrichment_hit_rate` | Gauge (0.0-1.0) | Fraction of processed events that matched at least one IOC in the last measurement window (1 minute). |
| `enrichment_boost_mean` | Gauge | Mean confidence increase from enrichment across all enriched findings in the window. |
| `enrichment_boost_p99` | Histogram | 99th percentile confidence boost, to detect outlier enrichment events. |
| `enrichment_age_p50_seconds` | Gauge | Median age (in seconds since ingestion) of IOCs that produced matches. High values indicate stale cache. |
| `enrichment_latency_us` | Histogram | Per-event enrichment latency in microseconds, bucketed at [1, 5, 10, 25, 50, 100, 500]. |
| `feed_hit_rate_by_id` | Gauge (per feed label) | Fraction of enrichment hits attributable to each feed. Identifies which feeds deliver value. |
| `feed_exclusive_hit_rate` | Gauge (per feed label) | Fraction of hits attributable to *only* this feed (no other feed corroborates). High values may indicate either unique coverage or false-positive noise. |
| `enrichment_match_count` | Counter | Total IOC matches since startup, partitioned by `indicator_type`. |
| `enrichment_miss_count` | Counter | Total enrichment queries that returned no match, partitioned by `indicator_type`. |

### 14.2 Operational Dashboards

These metrics enable three operator-facing views:

1. **Feed value assessment:** Compare `feed_hit_rate_by_id` across feeds.
   Feeds with near-zero hit rates after 30 days of operation should be
   reviewed for relevance to the deployment's threat profile. Feeds with
   high exclusive hit rates but low overall confidence boosts may be
   producing noise.

2. **Enrichment health:** Monitor `enrichment_latency_us` against the
   budget defined in Section 6.5. Alert if p99 enrichment latency exceeds
   25us (fast-path) or if `enrichment_hit_rate` drops below a configured
   floor (suggesting feed failure or cache expiration).

3. **Cache freshness:** Track `enrichment_age_p50_seconds` over time. A
   rising trend indicates feeds are not refreshing frequently enough or
   the decay model is retaining stale entries too long.

---

## 15. Deployment Profiles

Threat-intel cache sizing, feed polling strategy, and enrichment mode
must adapt to the deployment target. This section defines three profiles
that operators can select via `deployment_profile` in the runtime
configuration.

### 15.1 Edge Profile (Raspberry Pi 4 / ARM64, 256MB memory)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `threat_intel_max_entries` | 10,000 | 10K entries at ~300 bytes each = ~3MB, fitting within the 256MB budget |
| `feed_polling` | Disabled | Edge nodes should not poll feeds directly. IOC snapshots are pushed from a central coordinator via the operator API. |
| `enrichment_mode` | Inline only (Mode 1) | No batch enrichment, no external queries. Minimize background CPU/memory. |
| `enrichment_inline_max_queries` | 2 | Cap at IP + domain lookups. No URL/hash/email enrichment. |
| `gc_threat_intel_interval_ms` | 60,000 | GC every 60 seconds (vs. default 10 seconds). Reduce GC CPU overhead. |
| `l1_hot_cache_entries` | 1,000 | Small LRU cache for repeated beaconing patterns. |

Edge nodes receive a pre-filtered IOC snapshot containing only high-
confidence (>0.7) indicators relevant to their monitored network segment.
The central coordinator runs the full feed pipeline and distributes
snapshots on a configurable schedule (default: every 4 hours).

### 15.2 Standard Profile (4-8 core server, 2GB memory)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `threat_intel_max_entries` | 100,000 | ~30MB, well within budget |
| `feed_polling` | Tier 1 + Tier 2 feeds | Open-source and community feeds |
| `enrichment_mode` | Inline + Batch (Modes 1-2) | Batch enrichment for retroactive coverage |
| `enrichment_inline_max_queries` | 5 | Full indicator extraction for common event types |
| `gc_threat_intel_interval_ms` | 10,000 | Default 10-second GC interval |
| `l1_hot_cache_entries` | 10,000 | Moderate LRU cache |

### 15.3 Enterprise Profile (16+ core, 4GB+ memory)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `threat_intel_max_entries` | 1,000,000 | ~300MB, acceptable with 4GB+ budget |
| `feed_polling` | All tiers including commercial | Full feed portfolio |
| `enrichment_mode` | Inline + Batch + External (Modes 1-3) | Complete enrichment pipeline |
| `enrichment_inline_max_queries` | 10 | All indicator types including CIDR and parent-domain expansion |
| `gc_threat_intel_interval_ms` | 5,000 | Aggressive 5-second GC to keep cache lean |
| `l1_hot_cache_entries` | 100,000 | Large LRU cache for high-throughput environments |
| `external_enrichment_enabled` | true | External API queries for cache misses |

### 15.4 Air-Gapped Environments

Air-gapped deployments cannot poll external feeds. The operating model:

- **IOC import via operator API.** Threat-intel analysts prepare IOC
  bundles (STIX JSON or CSV) on an internet-connected workstation, review
  them, and import via the `POST /v1/operator/threat-intel/entries`
  endpoint (or a future bulk-import endpoint).
- **Sneakernet feed refresh.** Periodic manual transfer of IOC snapshots
  via removable media. The system should support a `POST /v1/operator/
  threat-intel/import-bundle` endpoint that accepts a STIX 2.1 Bundle
  JSON file.
- **Extended TTLs.** IOC half-lives should be increased 2-4x in
  air-gapped environments to account for infrequent refresh. A C2 IP
  with a 4-day half-life in connected environments should use a 16-day
  half-life in air-gapped deployments.
- **No external enrichment (Mode 3 disabled).** L3 cache is permanently
  unavailable.

---

## 16. Cross-References

| Document | Relevance |
|----------|-----------|
| **02 -- ATT&CK Coverage Analysis** | Threat intel entries should be tagged with MITRE ATT&CK technique IDs. The coverage analysis identifies detection gaps that threat intel can partially compensate for -- if we lack a detector for T1071.001 (Application Layer Protocol: Web), high-confidence domain IOCs tagged with that technique provide a fallback signal. |
| **04 -- Performance Characterization Under Load** | Enrichment pipeline latency is a critical performance metric. Doc 04 Section 4.2 allocates 3us (p50) / 10us (p99) for threat-intel enrichment, which reflects the current 0-3 query exact-match model. The expanded enrichment proposed here (Section 6.5) pushes inline enrichment to 15-50us. This is reconciled by the tiered enrichment strategy: the fast-path inline tier stays within Doc 04's 10us budget by limiting to the primary indicator query; supplementary enrichment (CIDR, parent-domain expansion, noisy-OR scoring) runs asynchronously and does not appear in Doc 04's critical-path latency budget. The L3 external enrichment mode (10-500ms per lookup) is explicitly excluded from the detection hot path via the supplementary deposit mechanism (Section 6.2). See also Doc 04 Section 5.3a for enrichment read-lock vs. GC write-lock contention modeling and Section 5.7 for threat-intel entry memory pressure analysis. |
| **05 -- Kill Chain Integration** | IOC types map to kill chain stages: phishing email addresses to Initial Access, C2 IPs/domains to Command and Control, exfiltration domains to Actions on Objectives. The kill chain document should reference the IOC taxonomy defined here for stage-specific enrichment strategies. |
| **06 -- Behavioral Baseline and Anomaly Detection** | The IOC-as-pheromone mapping proposed in Section 9 extends the stigmergic model underlying behavioral baselines. Threat intel concentration contributes to the swarm's collective awareness, priming anomaly detectors to lower thresholds when external intelligence indicates heightened risk for a threat class. |
| **07 -- Secure Update and Self-Protection** | Feed ingestion must be resilient to network partitions and feed compromise. During partition, the system operates on cached intel only; upon reconnection, it performs catch-up polling using `added_after` timestamps. Feed authentication and integrity verification align with the secure-update patterns analyzed in that document. |

---

## 17. References

[1] Mandiant, "M-Trends 2024: Special Report," Mandiant/Google Cloud, 2024.
Accessed: Apr. 2026. Available: https://www.mandiant.com/m-trends

[2] GreyNoise Intelligence, "2024 Internet Noise Report: Mass Exploitation
and Scanner Behavior," GreyNoise, 2024. Accessed: Apr. 2026.

[3] Google, "Google Safe Browsing Transparency Report," Google, 2025.
Accessed: Apr. 2026.
Available: https://transparencyreport.google.com/safe-browsing/overview

[4] OASIS, "STIX Version 2.1, OASIS Standard," OASIS Open, Jun. 2021.
Available: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

[5] J. Pearl, *Probabilistic Reasoning in Intelligent Systems: Networks of
Plausible Inference*, Morgan Kaufmann, 1988. (Noisy-OR model, Chapter 10)

[6] T. Bromander, A. Jorgensen, and M. Skjotskift, "An Empirical Study of
STIX Pattern Usage in Threat Intelligence Platforms," in *Proc. IEEE Symp.
Security and Privacy Workshops (SPW)*, 2023, pp. 112--120.

[7] MITRE, "MITRE ATT&CK," MITRE Corporation. Available:
https://attack.mitre.org/

[8] OASIS, "TAXII Version 2.1, OASIS Standard," OASIS Open, Jun. 2021.
Available: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html

[9] MISP Project, "MISP - Open Source Threat Intelligence and Sharing
Platform." Available: https://www.misp-project.org/

[10] A. Mohaisen, O. Alrawi, and M. Mohaisen, "AMAL: High-Fidelity,
Behavior-Based Automated Malware Analysis and Classification," *Computers &
Security*, vol. 52, pp. 251--266, 2015.

[11] European Union, "Regulation (EU) 2016/679 (General Data Protection
Regulation)," *Official Journal of the European Union*, L 119, 2016.

[12] Court of Justice of the European Union, "Patrick Breyer v.
Bundesrepublik Deutschland," Case C-582/14, Oct. 2016.
