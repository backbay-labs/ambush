---
phase: 103-threat-intel-enrichment-and-escalation-proof
type: context
created_at: 2026-04-07
depends_on: [102]
---

# Phase 103 Context

## Goal

Use the substrate-backed threat-intel cache during live detection so matched telemetry boosts finding confidence deterministically, then prove that a DNS threat-intel match can trigger alert escalation end to end.

## Why This Phase Exists

Phase 102 made threat intel durable and operator-manageable, but the live detection lane still ignores that cache entirely. Until the fast path consults substrate-owned intelligence, operator-seeded indicators cannot influence live confidence, pheromone strength, or swarm-mode escalation. This phase closes that gap and finishes the milestone by showing one real enriched detection path from seeded intel to alert mode.

## What Is Already True

- `detect_and_deposit` is the shared live detection seam used by both service-driven runtime processing and `WhiskerAgent`.
- The substrate can now persist exact-match `ThreatIntelEntry` records with TTL-aware lookup across in-memory, local-journal, and JetStream backends.
- `DnsExfiltrationDetector` already emits medium-confidence findings for high-entropy domains and higher confidence for stronger tunnel indicators.
- `ConcentrationMonitor` already records alert escalations when a deposit crosses the configured strength and source-diversity gates.

## Constraints

- Keep `DetectionStrategy` synchronous and side-effect free; adding async substrate lookups directly to the trait would ripple through offline replay and control code.
- Reuse the existing live detection pipeline rather than creating a detector-specific enrichment path.
- Threat-intel confidence shaping must be deterministic and capped at `1.0`.
- Preserve phase 102 exact-match semantics; enrichment can derive candidate indicators from telemetry, but substrate lookup remains exact and TTL-aware.

## Decisions

- Threat-intel enrichment will happen in `detect_and_deposit` after detector evaluation and before pheromone deposits are materialized.
- DNS enrichment should check the normalized full query name plus parent domains, so operators can seed a malicious domain and still match suspicious subdomains.
- Network-connect enrichment should check exact destination IP matches now; process-hash enrichment remains blocked on the current telemetry schema and should not widen this phase.
- Matching threat intel should annotate finding evidence with the matched indicator records so operators can see why confidence changed.

## Phase Direction

- First add shared live-pipeline enrichment that resolves active threat-intel matches and boosts finding confidence deterministically.
- Then add an end-to-end DNS integration proof showing seeded threat intel raises confidence above the configured alert threshold and records an alert escalation.
