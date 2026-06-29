# Ambush Engine Disaster Recovery Runbook

> Operational recovery procedures for the supported `v1.53` production profile
> and the hardened serve-mode runtime.  
> Last updated: 2026-04-11

## Scope

This runbook covers:

- the supported `v1.53` recovery baseline for the Helm production profile
- repeatable backup, restore, upgrade, and rollback drills across the supported
  durable state roots
- the existing hardened-runtime failure modes carried forward from earlier
  milestones:
  - degraded or partitioned governance state
  - NATS JetStream connection loss
  - dead-letter journal disk full
  - `CircuitBreakerState` stuck open
  - `PolicyVerdict::Deny` blocking all response actions

The Phase 180 production profile defines two durable boundaries:

- runtime PVC mounted at `/var/lib/swarm`
- optional NATS JetStream PVC mounted at `/data`

Object names in the examples below assume the default chart naming contract:

- runtime Deployment: `${RELEASE}-ambush-engine`
- runtime PVC: `${RELEASE}-ambush-engine`
- NATS StatefulSet: `${RELEASE}-nats`
- NATS PVC: `data-${RELEASE}-nats-0`

If `fullnameOverride` is set, substitute the actual names consistently.

Use the same repo-owned packaging and runtime surfaces for every drill:

```bash
export RELEASE=ambush-engine
export NAMESPACE=swarm-system
export CHART=deploy/helm/ambush-engine
export VALUES=deploy/helm/ambush-engine/values-production.yaml
export RENDERED=/tmp/ambush-engine-values-production-rendered.yaml

helm template "$RELEASE" "$CHART" -f "$VALUES" --show-only templates/configmap.yaml \
  | sed -n '/^  config.yaml: |$/,$p' \
  | sed '1d;s/^    //' > "$RENDERED"

cargo run -p swarm-runtime --bin swarmctl -- validate --config "$RENDERED" --json

kubectl -n "$NAMESPACE" get deploy,sts,pvc
kubectl -n "$NAMESPACE" port-forward deploy/"$RELEASE"-ambush-engine 9090:9090
```

## 1. Supported Durability Inventory

| Boundary | Backing store | Must be backed up | Restore notes |
| --- | --- | --- | --- |
| Repo-owned chart and `values-production.yaml` | Git plus Helm history | Yes | Re-render and reapply; do not treat the pod filesystem as the source of truth |
| Runtime Secrets and TLS material | Kubernetes Secret objects | Yes | Restore Secret objects before starting the runtime pod |
| `/var/lib/swarm` runtime state root | Runtime PVC | Yes | Contains replay, investigations, incidents, runtime identities, and local-journal pheromones when JetStream is disabled |
| `/data` JetStream store | NATS PVC | Yes when `nats.enabled=true` | Restore independently from the runtime PVC |
| `/tmp` scratch | `emptyDir` | No | Recreated automatically |

Topology guidance:

- Bootstrap `local_journal` deployment: one durable boundary, the runtime PVC.
- Supported production `jet_stream` deployment: two durable boundaries, the runtime PVC and the NATS PVC.

## 2. Recovery Evidence Packet

For every backup, restore, upgrade, or rollback drill, retain:

- timestamp and operator
- Git commit or release artifact used for the chart and values
- Helm release revision before and after the drill
- rendered-config validation JSON from `swarmctl validate`
- runtime PVC snapshot identifier
- NATS PVC snapshot identifier when JetStream is enabled
- post-drill `/startupz`, `/readyz`, and `/healthz` output

This is the minimum durable evidence set for later recovery and capacity phases.

## 3. Runtime PVC Backup Drill

1. Render and validate the active production config with the commands above.
2. Start a local port-forward to the runtime Deployment and request a controlled drain:

```bash
curl -sf http://127.0.0.1:9090/prestop | jq .
kubectl -n "$NAMESPACE" scale deploy/"$RELEASE"-ambush-engine --replicas=0
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE"-ambush-engine
```

3. Take a storage-level snapshot of the runtime PVC mounted at `/var/lib/swarm`.
4. Record the snapshot identifier and the validated rendered-config artifact in the recovery evidence packet.

Verification:

```bash
kubectl -n "$NAMESPACE" get pvc
test -s "$RENDERED"
```

## 4. Runtime PVC Restore Drill

1. Keep the runtime Deployment scaled to zero.
2. Restore the runtime PVC snapshot in place or restore it to the claim that will be mounted at `/var/lib/swarm`.
3. Re-apply the release from the same chart and values if the Deployment or ConfigMap was recreated:

```bash
helm upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$VALUES"
kubectl -n "$NAMESPACE" scale deploy/"$RELEASE"-ambush-engine --replicas=1
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE"-ambush-engine
```

4. Re-establish the port-forward and verify readiness:

```bash
curl -sf http://127.0.0.1:9090/startupz | jq .
curl -sf http://127.0.0.1:9090/readyz | jq .
curl -sf http://127.0.0.1:9090/healthz | jq .
```

Success condition: the runtime returns to ready state without changing the rendered config or rewriting the declared state-root contract.

## 5. Helm Upgrade And Rollback Drill

Upgrade drill:

1. Render the candidate chart and validate the rendered config before touching the cluster.
2. Capture runtime PVC and JetStream PVC snapshot identifiers.
3. Apply the upgrade:

```bash
helm upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$VALUES"
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE"-ambush-engine
kubectl -n "$NAMESPACE" rollout status sts/"$RELEASE"-nats
```

4. Verify `startupz`, `readyz`, and `healthz` through the port-forward and record the new Helm revision.

Rollback drill:

1. Roll back to the previous Helm revision:

```bash
helm history "$RELEASE" -n "$NAMESPACE"
helm rollback "$RELEASE" REVISION -n "$NAMESPACE"
```

2. If the failure involved corrupted runtime or JetStream state, restore the pre-upgrade snapshots before scaling the workloads back up.
3. Re-run the readiness verification and keep both the failed and restored revision numbers in the evidence packet.

## 6. JetStream Durability Drill

When `nats.enabled=false`, skip this section; the runtime PVC backup already covers local-journal pheromone state.

When `nats.enabled=true`:

1. Drain and scale the runtime Deployment to zero so no new pheromone writes are issued.
2. Scale the NATS StatefulSet to zero and snapshot the JetStream PVC:

```bash
kubectl -n "$NAMESPACE" scale sts/"$RELEASE"-nats --replicas=0
kubectl -n "$NAMESPACE" rollout status sts/"$RELEASE"-nats
```

3. Restore the JetStream PVC from snapshot if testing restore behavior.
4. Scale NATS back to one replica, then start the runtime Deployment again:

```bash
kubectl -n "$NAMESPACE" scale sts/"$RELEASE"-nats --replicas=1
kubectl -n "$NAMESPACE" rollout status sts/"$RELEASE"-nats
kubectl -n "$NAMESPACE" scale deploy/"$RELEASE"-ambush-engine --replicas=1
kubectl -n "$NAMESPACE" rollout status deploy/"$RELEASE"-ambush-engine
```

5. Verify the substrate is healthy:

```bash
curl -sf http://127.0.0.1:9090/healthz | jq .
curl -sf http://127.0.0.1:9090/readyz | jq .
```

Success condition: JetStream-backed pheromone state returns without changing the runtime PVC boundary or the rendered config contract.

## 7. Failure-Mode Playbooks

### 7.1 Governance Degraded Or Partitioned

#### Detection Signals

- `/healthz` and `/readyz` show a `governance` component with
  `partition_state` set to `degraded`, `partitioned`, or `healing`.
- The governance component reports reduced healthy-governor counts,
  non-zero `active_contingency_leases`, or a populated reconciliation report
  marker.
- Runtime events include partition transition or reconciliation entries.
- Destructive response attempts are vetoed or denied with governance or
  partition-authorization reasons.

#### Operator Remediation

1. Confirm whether the issue is ordinary agent health degradation or actual
   quorum loss.
2. If the state is `degraded`, restore the unhealthy governors before the
   system crosses into `partitioned`.
3. If the state is `partitioned`, do not expect destructive response to proceed
   unless a staged contingency lease already authorizes the exact action.
4. Restore the missing governors or network path, then wait for the runtime to
   enter `healing` and emit a reconciliation report.
5. Review authorized versus unauthorized partition-era actions before treating
   the system as fully recovered.

#### Verification Commands

```bash
curl -sf http://127.0.0.1:9090/healthz | jq '.components.governance'
curl -sf http://127.0.0.1:9090/readyz | jq '.components.governance'
```

#### Recovery Notes

- destructive action should fail closed during partition
- observability should remain available
- contingency leases are emergency exceptions, not routine recovery tooling
- reconciliation reports are part of the audit trail and should be retained

### 7.2 JetStream Connection Loss

#### Detection Signals

- `/healthz` shows substrate `ready: false` or backend details mentioning JetStream unavailability.
- `/startupz` or `/readyz` stays HTTP 503 when live response requires a durable substrate.
- Logs include JetStream connect, KV, or health-check failures from `swarm-pheromone`.

#### Operator Remediation

1. Confirm whether the NATS cluster or the projected network path is down.
2. Restore JetStream reachability before restarting the runtime if `runtime.require_durable_live_response` is true.
3. If the outage is prolonged and live response must remain disabled, temporarily switch the runtime to `detect_only` or relax durability requirements through repo-owned config, then reload or restart intentionally.
4. After the backend recovers, allow the runtime to reconnect and re-check readiness.

#### Verification Commands

```bash
curl -sf http://127.0.0.1:9090/healthz | jq .
curl -sf http://127.0.0.1:9090/readyz | jq .
kubectl -n "$NAMESPACE" logs sts/"$RELEASE"-nats --tail=100
```

### 7.3 Dead-Letter Journal Disk Full

#### Detection Signals

- Response adapter logs report `failed to write dead-letter entry`.
- The response path starts surfacing final adapter failures without durable dead-letter persistence.
- Host metrics show the filesystem containing `dead_letter_path` at or near capacity.

#### Operator Remediation

1. Identify the configured `response_adapter.dead_letter_path`.
2. Free disk space on that filesystem or move the journal path to a healthier volume through config.
3. Preserve the existing JSONL file before truncating or rotating it if the contents are needed for replay.
4. Reload or restart the runtime only after the destination path is writable again.

#### Verification Commands

```bash
kubectl -n "$NAMESPACE" exec deploy/"$RELEASE"-ambush-engine -- df -h /var/lib/swarm
curl -sf http://127.0.0.1:9090/healthz | jq .
```

### 7.4 Circuit Breaker Stuck Open

#### Detection Signals

- Adapter receipts or logs repeatedly report `circuit breaker open`.
- Response actions fail fast even when the downstream endpoint is healthy again.
- The dead-letter journal keeps recording the same adapter with no successful reset.

#### Operator Remediation

1. Verify the downstream HTTP EDR or webhook endpoint is healthy independently.
2. Wait for the configured `response_adapter.circuit_breaker.cooldown_ms` window to expire.
3. If failures continue after downstream recovery, restart the runtime to reset in-memory circuit state.
4. Investigate whether retry/backoff thresholds are too aggressive for the downstream system and adjust config deliberately.

#### Verification Commands

```bash
curl -sf http://127.0.0.1:9090/metrics | rg "adapter_outcomes|response_latency"
curl -sf http://127.0.0.1:9090/healthz | jq .
```

### 7.5 PolicyVerdict::Deny Blocking All Response Actions

#### Detection Signals

- Audit trails show `PolicyVerdict::Deny` for all candidate actions.
- Operators observe detections with no executed or simulated response despite healthy adapters.
- Logs indicate policy evaluation succeeded but denied each action.

#### Operator Remediation

1. Confirm the denial is intentional and tied to the current response action or severity.
2. Review `policy.human_gate_severity`, lease TTL, and any surrounding rollout mode assumptions in the active config.
3. If the deny behavior is incorrect, update the repo-owned policy config and reload or restart intentionally.
4. If the deny is expected, escalate operationally instead of forcing execution outside the policy lane.

#### Verification Commands

```bash
cargo run -p swarm-runtime --bin swarmctl -- validate --config "$RENDERED" --json
curl -sf http://127.0.0.1:9090/healthz | jq .
```

## 8. Controlled Drain Before Restart

Before planned restarts or pod termination, call the PreStop hook and wait for it to complete:

```bash
curl -sf http://127.0.0.1:9090/prestop | jq .
```

Expected behavior:

- new `/v1/ingest/events` requests are rejected
- accepted in-flight work drains for up to `runtime.drain_timeout_ms`
- the runtime then requests clean shutdown

## 9. Post-Recovery Checklist

After remediation:

1. `GET /startupz` returns HTTP 200.
2. `GET /readyz` returns HTTP 200.
3. `GET /metrics` includes current `swarm_heap_bytes` and `swarm_heap_pressure_ratio`.
4. `GET /healthz` shows the substrate ready for the selected topology.
5. The rendered config still validates against the repo-owned contract.
6. The dead-letter journal path is writable if live response adapters are enabled.
