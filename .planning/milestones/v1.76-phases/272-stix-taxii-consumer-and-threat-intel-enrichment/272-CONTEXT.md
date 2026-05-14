# Phase 272 Context

## Goal

The runtime can consume external STIX/TAXII 2.1 threat intelligence feeds and enrich behavioral detection findings with matched IOC context.

## Repo State

- `v1.75` closed the operator-packaging loop with validated signed defaults, deployment docs, adversary-emulation coverage proof, and a packaged `swarmctl quickstart` path.
- The runtime already carries threat-intel-adjacent seams through `ThreatIntelEntry`, signed finding envelopes, and the shared health and status surfaces.
- External feed ingestion is not yet shipped; `v1.76` begins the move beyond host-only telemetry.

## Phase Focus

- Add one bounded STIX/TAXII 2.1 consumer path without widening the runtime into a generic feed orchestration system.
- Normalize indicator objects into the existing threat-intel substrate with source attribution, confidence, TTL, and deduplication.
- Reuse the existing finding and status surfaces so matched IOC context becomes visible without inventing a separate operator workflow.

## Verification Target

- Repo-owned tests proving bounded polling, indicator normalization, and deduplicating re-observation behavior for IPv4, domain, file-hash, and URL indicators.
- Runtime proof that matched behavioral findings carry IOC value, feed source, STIX indicator ID, and confidence boost in the existing signed finding surface.
- Health-surface proof that feed poll time, ingest counts, and error counts are visible on the shipped runtime status path.
