---
phase: 108-canonical-siem-forward-adapter
type: context
created_at: 2026-04-07
depends_on: [107]
---

# Phase 108 Context

## Goal

Add a canonical `swarm_finding` delivery contract and a resilient `SiemForwardAdapter` that can forward findings to Splunk HEC, ELK bulk ingest, or Chronicle without changing the existing live-response execution substrate.

## Why This Phase Exists

The runtime can already detect, enrich, persist, and respond, but there is still no first-class outbound delivery path for findings into external SOC tooling. The next production milestone needs an adapter-level contract that reuses the existing retry, circuit-breaker, and dead-letter behavior instead of inventing a parallel outbound stack.

## What Is Already True

- `swarm-response` already owns `ResponseExecutor`, `ResilientExecutor`, and `DeadLetterJournal`, and both HTTP EDR and webhook adapters already execute behind that resilience layer.
- `DetectionFinding` is already a stable serializable record with `finding_id`, `event_id`, `strategy_id`, `threat_class`, `severity`, `confidence`, and structured evidence.
- `RuntimeService::process_event` already centralizes the fast detection lane, so outbound finding delivery can be inserted once instead of per ingest or per agent path.
- Config parsing, validation, and `@secret:` resolution already exist in `swarm-core` and `swarm-runtime` for outbound auth-bearing components.

## Constraints

- Preserve the existing response-adapter path for live actions; SIEM forwarding is additive and must not regress deterministic response execution.
- Reuse `ResilientExecutor` and `CircuitBreakerState` semantics instead of building a second retry implementation.
- Keep the finding schema canonical across Splunk, ELK, and Chronicle variants even if the outer transport envelope differs.
- Forwarding failures should degrade visibly and durably without breaking hot-path replay persistence.

## Decisions

- The canonical outbound payload will be named `swarm_finding` and carry a stable schema marker plus the full structured finding record.
- `SiemForwardAdapter` will implement `ResponseExecutor`, but the runtime will invoke it through finding-specific synthetic requests so the hot path can forward detections even when no response action is proposed.
- Transport-specific variants should differ only in outer request shape and auth header conventions, not in the underlying finding schema.
- SIEM config belongs in `SwarmConfig` as a top-level optional feature so runtime activation is explicit and repo-owned.

## Phase Direction

- Split the work into config and adapter shape first, then runtime integration and proof.
- Keep the canonical schema in reusable response-layer code so notification routing can reuse the same normalized finding representation later in the milestone.
- Prefer focused adapter tests over end-to-end runtime proof in this phase; the runtime integration proof lands after the adapter exists.
