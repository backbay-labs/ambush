# Swarm Team Six Disaster Recovery Runbook

> Operational recovery procedures for the hardened serve-mode runtime.  
> Last updated: 2026-04-07

## Scope

This runbook covers the required `v1.35` production failure modes:

- NATS JetStream connection loss
- dead-letter journal disk full
- `CircuitBreakerState` stuck open
- `PolicyVerdict::Deny` blocking all response actions

Use the same repo-owned runtime surfaces for detection and verification:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /v1/operator/status`
- `cargo run -p swarm-runtime --bin swarmctl -- status --config rulesets/default.yaml`

## 1. JetStream Connection Loss

### Detection Signals

- `/healthz` shows substrate `ready: false` or backend details mentioning JetStream unavailability.
- `/startupz` or `/readyz` stays HTTP 503 when live response requires a durable substrate.
- Logs include JetStream connect, KV, or health-check failures from `swarm-pheromone`.

### Operator Remediation

1. Confirm whether the NATS cluster or the projected network path is down.
2. Restore JetStream reachability before restarting the runtime if `runtime.require_durable_live_response` is true.
3. If the outage is prolonged and live response must remain disabled, temporarily switch the runtime to `detect_only` or relax durability requirements through repo-owned config, then reload or restart intentionally.
4. After the backend recovers, allow the runtime to reconnect and re-check readiness.

### Verification Commands

```bash
curl -sf http://127.0.0.1:9090/healthz | jq .
curl -sf http://127.0.0.1:9090/readyz | jq .
cargo run -p swarm-runtime --bin swarmctl -- status --config rulesets/default.yaml
```

## 2. Dead-Letter Journal Disk Full

### Detection Signals

- Response adapter logs report `failed to write dead-letter entry`.
- The response path starts surfacing final adapter failures without durable dead-letter persistence.
- Host metrics show the filesystem containing `dead_letter_path` at or near capacity.

### Operator Remediation

1. Identify the configured `response_adapter.dead_letter_path`.
2. Free disk space on that filesystem or move the journal path to a healthier volume through config.
3. Preserve the existing JSONL file before truncating or rotating it if the contents are needed for replay.
4. Reload or restart the runtime only after the destination path is writable again.

### Verification Commands

```bash
df -h .
ls -lh ./dead-letter.jsonl
curl -sf http://127.0.0.1:9090/healthz | jq .
```

## 3. Circuit Breaker Stuck Open

### Detection Signals

- Adapter receipts or logs repeatedly report `circuit breaker open`.
- Response actions fail fast even when the downstream endpoint is healthy again.
- The dead-letter journal keeps recording the same adapter with no successful reset.

### Operator Remediation

1. Verify the downstream HTTP EDR or webhook endpoint is healthy independently.
2. Wait for the configured `response_adapter.circuit_breaker.cooldown_ms` window to expire.
3. If failures continue after downstream recovery, restart the runtime to reset in-memory circuit state.
4. Investigate whether retry/backoff thresholds are too aggressive for the downstream system and adjust config deliberately.

### Verification Commands

```bash
curl -sf http://127.0.0.1:9090/metrics | rg "adapter_outcomes|response_latency"
curl -sf http://127.0.0.1:9090/healthz | jq .
```

## 4. PolicyVerdict::Deny Blocking All Response Actions

### Detection Signals

- Audit trails show `PolicyVerdict::Deny` for all candidate actions.
- Operators observe detections with no executed or simulated response despite healthy adapters.
- Logs indicate policy evaluation succeeded but denied each action.

### Operator Remediation

1. Confirm the denial is intentional and tied to the current response action or severity.
2. Review `policy.human_gate_severity`, lease TTL, and any surrounding rollout mode assumptions in the active config.
3. If the deny behavior is incorrect, update the repo-owned policy config and reload or restart intentionally.
4. If the deny is expected, escalate operationally instead of forcing execution outside the policy lane.

### Verification Commands

```bash
cargo run -p swarm-runtime --bin swarmctl -- status --config rulesets/default.yaml
curl -sf http://127.0.0.1:9090/healthz | jq .
```

## Controlled Drain Before Restart

Before planned restarts or pod termination, call the PreStop hook and wait for it to complete:

```bash
curl -sf http://127.0.0.1:9090/prestop | jq .
```

Expected behavior:

- new `/v1/ingest/events` requests are rejected
- accepted in-flight work drains for up to `runtime.drain_timeout_ms`
- the runtime then requests clean shutdown

## Post-Recovery Checklist

After remediation:

1. `GET /startupz` returns HTTP 200.
2. `GET /readyz` returns HTTP 200.
3. `GET /metrics` includes current `swarm_heap_bytes` and `swarm_heap_pressure_ratio`.
4. Operator status shows the substrate and replay store healthy.
5. The dead-letter journal path is writable if live response adapters are enabled.
