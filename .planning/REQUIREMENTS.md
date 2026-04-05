# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.27 Requirements

### Response Adapters

- [ ] **RESP-01**: At least two real response adapters exist behind the ResponseExecutor trait (HTTP-based EDR block/isolate, webhook-based escalation notification)
- [ ] **RESP-02**: Response adapters fire only after guard pipeline and policy gate approval with signed receipt

### Deployment Infrastructure

- [ ] **DEPLOY-01**: Dockerfile exists with multi-stage build for swarm-detect and swarmctl binaries
- [ ] **DEPLOY-02**: docker-compose exists for local development (runtime + optional NATS)
- [ ] **DEPLOY-03**: Health check endpoint and graceful shutdown are implemented
- [ ] **DEPLOY-04**: Policy can be reloaded at runtime without binary restart

## Future Requirements

### Durable Substrate And Multi-Instance (v1.28)

- **SUB-01**: NATS JetStream pheromone substrate backend persists deposits across restarts
- **SUB-02**: Multiple swarm-detect instances contribute deposits to shared substrate with correct concentration aggregation
- **SUB-03**: min_sources_for_escalation enforcement works correctly across multiple instances
- **CLEAN-01**: swarm-bridge (dead PyO3 shim) and kernel/ Python stubs are removed or archived

## Out of Scope

| Feature | Reason |
|---------|--------|
| Real EDR vendor SDK integration (CrowdStrike Falcon, Defender, etc.) | HTTP adapter is generic; vendor-specific SDKs are future work |
| Kubernetes manifests or Helm charts | Dockerfile + docker-compose is sufficient for v1.27; k8s is future |
| TLS certificate management | Use reverse proxy for TLS termination; not in-binary |
| Multi-region or HA deployment | Single-node deployment first; HA comes with v1.28 multi-instance |
| Automatic scaling or load balancing | Manual deployment; orchestration is future work |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| RESP-01 | — | Pending |
| RESP-02 | — | Pending |
| DEPLOY-01 | — | Pending |
| DEPLOY-02 | — | Pending |
| DEPLOY-03 | — | Pending |
| DEPLOY-04 | — | Pending |

**Coverage:**
- v1.27 requirements: 6 total
- Mapped to phases: 0
- Unmapped: 6

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after milestone v1.27 definition*
