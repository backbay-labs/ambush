---
phase: 109-finding-enrichment-and-delivery-metadata
type: context
created_at: 2026-04-07
depends_on: [108]
---

# Phase 109 Context

## Goal

Decorate each `DetectionFinding` with delivery-grade context such as ancestry, host metadata, and time-to-detect before external SIEM forwarding or notification routing consumes it.

## Why This Phase Exists

The detectors already emit structured evidence, but outbound tooling still lacks consistent host and ancestry context. If finding delivery leaves that enrichment to downstream systems, the repo loses portability and operators get inconsistent payload quality across transports.

## What Is Already True

- `TelemetryEvent` already carries `source`, `event_id`, `timestamp`, `host_id`, and typed payload variants with process or network context.
- Most detector evidence already includes process names, users, and host IDs, but the shape is detector-specific rather than delivery-specific.
- `RuntimeService::process_event` is the one place where detections become replay bundles and can be enriched once before any external sink sees them.
- Threat-intel enrichment already mutates `DetectionFinding.evidence` in the detection lane, so there is an established precedent for repo-owned evidence decoration.

## Constraints

- Keep enrichment deterministic and bounded; no external lookups or async inventory calls in the hot path.
- Preserve existing detector evidence fields while adding new normalized keys.
- Avoid changing detector-specific logic unless required for stable enrichment metadata.
- Use one shared enrichment service so SIEM forwarding and notification routing stay aligned.

## Decisions

- `FindingEnrichmentService` should operate on `DetectionFinding` plus the originating `TelemetryEvent`, returning enriched findings before replay persistence and outbound delivery.
- `parent_process_ancestry` will be a normalized array derived from available process context instead of a best-effort graph lookup.
- `host_metadata` will expose stable source, host, and event identity fields so downstream sinks get consistent addressing.
- `time_to_detect_ms` should be computed from the event timestamp and the runtime clock at evaluation time.

## Phase Direction

- Land the enrichment service first, then wire it into the shared runtime path and prove the added evidence appears in replay bundles and delivery payloads.
- Keep the enrichment output schema intentionally small and transport-agnostic so later sinks can reuse it unchanged.
