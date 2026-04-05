# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.26) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-83 shipped across milestones v1.0 through v1.26. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

### v1.27 Live Response Adapters And Deployment (In Progress)

**Milestone Goal:** Implement real response adapters that execute actual side effects (EDR block/isolate, webhook notifications), containerize the detection service, and add runtime policy reload.

## Phases

- [ ] **Phase 84: Real Response Adapters** - HTTP EDR and webhook adapters behind ResponseExecutor, gated by guards and policy
- [ ] **Phase 85: Container And Deployment Infrastructure** - Dockerfile, docker-compose, health checks, graceful shutdown, runtime policy reload

## Phase Details

### Phase 84: Real Response Adapters
**Goal**: Response actions produce real side effects through HTTP-based adapters gated by the existing guard pipeline and policy
**Depends on**: v1.26 (telemetry ingest and detection breadth must exist for end-to-end response testing)
**Requirements**: RESP-01, RESP-02
**Success Criteria** (what must be TRUE):
  1. An HTTP EDR adapter sends block or isolate requests to a configurable endpoint with authorization headers and parses confirmation or error responses
  2. A webhook adapter sends escalation notifications as Slack/PagerDuty-compatible JSON payloads to a configurable URL
  3. Both adapters only fire after the guard pipeline approves the action and the policy gate returns an allow verdict
  4. Each adapter execution produces a signed receipt that records adapter type, target, result status (success, failure, timeout), and elapsed time
  5. HTTP client handles configurable timeouts and returns structured errors instead of panicking on network failures
**Plans:** 2 plans

Plans:
- [ ] 84-01-PLAN.md -- Add reqwest dependency, adapter config types, HttpEdrAdapter and WebhookAdapter implementations
- [ ] 84-02-PLAN.md -- DispatchingExecutor, config-driven adapter selection, runtime wiring and integration tests

### Phase 85: Container And Deployment Infrastructure
**Goal**: The detection service is containerized and deployable with health monitoring, graceful lifecycle, and hot policy reload
**Depends on**: Phase 84
**Requirements**: DEPLOY-01, DEPLOY-02, DEPLOY-03, DEPLOY-04
**Success Criteria** (what must be TRUE):
  1. A multi-stage Dockerfile produces minimal images containing swarm-detect and swarmctl binaries without build toolchain or source
  2. docker-compose brings up the detection service and an optional NATS sidecar with one command
  3. A /healthz endpoint returns service readiness including detection pipeline and substrate status
  4. SIGTERM triggers graceful shutdown that drains in-flight events and flushes state before exit
  5. Policy file changes are detected and applied at runtime without restarting the binary (file-watch or SIGHUP)
**Plans**: TBD

Plans:
- [ ] 85-01: TBD
- [ ] 85-02: TBD

## Next Up

- `v1.28 Durable Substrate And Multi-Instance Coordination`

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 84. Real Response Adapters | v1.27 | 0/2 | Planned | - |
| 85. Container And Deployment Infrastructure | v1.27 | 0/? | Not started | - |

---
*Last shipped milestone: v1.26 Detection Breadth And Telemetry Ingestion on 2026-04-05*
*Last updated: 2026-04-05 after Phase 84 planning*
