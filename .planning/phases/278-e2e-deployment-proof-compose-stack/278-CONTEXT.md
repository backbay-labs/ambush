# Phase 278 Context

## Goal

The repo ships one Docker Compose proof stack that demonstrates the full detect -> respond -> deliver loop with mocked CrowdStrike RTR and Splunk HEC dependencies.

## Repo State

- The runtime already has packaged operator flows, replay proof surfaces, and a growing integration-friendly API contract.
- Phases 276 and 277 are intended to put one real EDR adapter and one real SIEM adapter behind those existing seams.
- The milestone closes only if the adapters compose together in a reproducible deployment path.

## Phase Focus

- Reuse the packaged runtime entry points and repo-owned config surfaces instead of inventing a bespoke demo harness.
- Keep the Compose stack bounded to one telemetry source, one RTR adapter, and one HEC adapter so proof remains deterministic.
- Make the proof observable through finding delivery, response receipts, and adapter outputs, not just container exit codes.

## Verification Target

- A scripted Compose-backed scenario that injects attack telemetry, triggers detection, exercises one RTR response action, and proves finding delivery into the mocked HEC sink with the expected mapped fields.
