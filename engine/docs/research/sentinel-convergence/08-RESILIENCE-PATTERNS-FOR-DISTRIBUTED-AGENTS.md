---
title: "08 -- Resilience Patterns for Distributed Agent Systems"
series: Sentinel Convergence (8 of 8)
version: "0.2"
date: 2026-04-07
status: Draft
authors: Swarm Team Six Research
---

# 08 -- Resilience Patterns for Distributed Agent Systems

> Cross-project analysis: Sentinel (Go, edge Kubernetes) and Swarm Team Six (Rust, EDR/detection).
> Audience: systems engineers building fault-tolerant autonomous agent pipelines.

> **Series Note**
> - This is the most near-term actionable document in the series.
> - Items like jitter, deadline propagation, and composite health aggregation can
>   land independently of Phase 6 governance work.
> - See [00-OVERVIEW.md](00-OVERVIEW.md) for current series posture.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Taxonomy of Failure Modes](#2-taxonomy-of-failure-modes)
3. [Circuit Breaker Pattern](#3-circuit-breaker-pattern)
4. [Rate Limiting Strategies](#4-rate-limiting-strategies)
5. [Exponential Backoff with Jitter](#5-exponential-backoff-with-jitter)
6. [Graceful Degradation Hierarchy](#6-graceful-degradation-hierarchy)
7. [Bulkhead Pattern](#7-bulkhead-pattern)
8. [Timeout and Deadline Propagation](#8-timeout-and-deadline-propagation)
9. [Health Checking Patterns](#9-health-checking-patterns)
10. [Chaos Engineering for Agent Swarms](#10-chaos-engineering-for-agent-swarms)
11. [Self-Healing Patterns](#11-self-healing-patterns)
12. [Comparison with Resilience Libraries](#12-comparison-with-resilience-libraries)
13. [Fail-Closed vs Fail-Open Semantics](#13-fail-closed-vs-fail-open-semantics)
14. [Reference Resilience Architecture](#14-reference-resilience-architecture)
15. [Appendix: Source Cross-Reference](#appendix-source-cross-reference)
16. [Cross-References](#cross-references)

---

## 1. Introduction

Distributed agent systems combine the operational complexity of distributed systems with
the autonomy challenges of multi-agent coordination. A detection swarm that misses events
during a transient failure is an availability problem; a response swarm that executes a
host-isolation action twice during a retry storm is a safety problem. Resilience patterns
must therefore satisfy dual constraints that traditional web services never face:
**liveness** (the swarm must keep detecting) and **safety** (the swarm must never act
beyond its authorization boundary, even under failure).

This document analyzes concrete implementations from two codebases:

- **Sentinel** (`playground/sentinel`): A Go service managing Kubernetes edge nodes with
  circuit breakers, token-bucket rate limiting, Raft-lite consensus, exponential backoff,
  and three-tier health probes. Designed for small clusters (3--10 nodes) that must
  survive network partitions from the control plane.

- **Swarm Team Six** (`standalone/swarm-team-six`): A Rust-first EDR runtime with a
  guard pipeline, deterministic policy gate, capability-scoped leases, resilient response
  adapters (retry + circuit breaker + dead-letter journal), and dual execution modes
  (`DryRun` vs `Enforced`). Designed to detect threats and optionally execute live response
  actions with full auditability.

Where the two systems converge, we extract generalizable patterns. Where they diverge, we
identify which failure mode each approach is optimized for.

---

## 2. Taxonomy of Failure Modes

Distributed agent systems experience four classical failure categories, each with
agent-specific manifestations:

### 2.1 Crash Failures

The simplest model: a process stops executing and never resumes.

| System | Manifestation | Mitigation |
|--------|---------------|------------|
| Sentinel | Edge node kubelet dies; `peerConn.healthy` goes false | Raft-lite leader re-election; partition detector triggers autonomous decisions |
| Swarm | Whisker agent process exits mid-tick | `agent_tick_timeout_ms` watchdog; dispatcher marks `AgentHealth::Failed` |
| Swarm | NATS JetStream backend crashes | `/healthz` reports substrate `ready: false`; runtime refuses live-response mode |

In both systems, crash failures are the easiest to handle because they are detectable
through absence of heartbeats or health responses.

### 2.2 Omission Failures

A process is alive but drops messages -- either on send or receive.

| System | Manifestation | Mitigation |
|--------|---------------|------------|
| Sentinel | API server request dropped by overloaded network | Circuit breaker opens after `FailureThreshold` (default 5) consecutive failures |
| Sentinel | Consensus message dropped by rate limiter | `tokenBucket.Allow()` returns false; `rateLimitDropped` counter increments |
| Swarm | HTTP EDR adapter receives no response | `ResponseStatus::Timeout` triggers retry with backoff; dead-letter after exhaustion |
| Swarm | Webhook notification silently lost | Notification router tracks delivery; dead-letter journal preserves failed payloads |

Omission failures are particularly dangerous for security systems because a dropped
detection event can mean a missed threat. Sentinel's partition detector (`partitionDetector`
goroutine) specifically watches for omission patterns: a peer is considered healthy only if
`time.Since(peer.lastSeen) < 5s`. When `healthyPeers < quorum` (where `quorum = len(peers)/2`),
the node declares itself partitioned and begins autonomous operation.

### 2.3 Timing Failures

A process responds, but outside the expected time bound.

| System | Manifestation | Mitigation |
|--------|---------------|------------|
| Sentinel | API server responds after 10s timeout (edge network latency) | `config.Timeout = 10 * time.Second` on Kubernetes client; circuit breaker records as failure |
| Sentinel | Election timeout variance | Randomized timeout `[ElectionTimeout, 2*ElectionTimeout]` prevents synchronized elections |
| Swarm | EDR endpoint responds after `timeout_ms` | `reqwest::Client` timeout; receipt marked `ResponseStatus::Timeout`; retryable |
| Swarm | Agent tick exceeds `agent_tick_timeout_ms` | Dispatcher skips cycle; agent marked `AgentHealth::Degraded` |

Timing failures sit between omission and correct behavior. Both systems treat timeouts as
retriable failures rather than terminal errors, which is critical for agents operating over
unreliable networks.

### 2.4 Byzantine Failures

A process behaves arbitrarily -- producing incorrect results, lying about state, or acting
maliciously.

| System | Manifestation | Mitigation |
|--------|---------------|------------|
| Sentinel | Compromised node sends false votes in Raft-lite | Term-based vote validation; quorum requirement prevents single-node takeover |
| Swarm | Malicious agent forges a `ResponseAction::IsolateHost` | Guard pipeline fail-closed; policy gate requires `CapabilityLease` with short TTL |
| Swarm | Compromised whisker deposits false pheromones | BFT consensus (Tendermint-style, `2f+1` agreement) required for response actions |
| Swarm | Tampered audit trail | Cryptographic envelope signing (`ed25519-dalek`); chain verification via `swarm-spine` |

Byzantine tolerance is where the two systems diverge most sharply. Sentinel's Raft-lite
tolerates crash faults only (requires simple majority). Swarm Team Six's consensus design
(documented in `swarm-consensus/src/lib.rs`) targets full BFT with `2f+1` agreement out of
`3f+1` voters, though the implementation is still in progress.

### 2.5 Failure Mode Decision Matrix

```
              Crash    Omission    Timing    Byzantine
             ------   ---------   -------   ----------
Detection      low     CRITICAL    medium    CRITICAL
Response      medium    medium      high     CRITICAL
Audit          low      high       medium    CRITICAL
Consensus     medium    medium     medium    CRITICAL
```

The matrix reveals why security agent systems must treat omission and Byzantine failures in
the detection path as critical: a missed detection is indistinguishable from a successful
attack evasion.

---

## 3. Circuit Breaker Pattern

### 3.1 State Machine

Both projects implement the circuit breaker pattern, but with different state management
strategies.

```
             +---------+    failure >= threshold    +--------+
             |         |-------------------------->|        |
  Request -->| CLOSED  |                           |  OPEN  |---> Reject (fast-fail)
             |         |<--.                       |        |
             +---------+   |                       +--------+
                 ^         |                           |
                 |    success >= threshold             | timeout elapsed
                 |         |                           v
                 |     +----------+                    |
                 |     |          |<--------------------+
                 +-----| HALF-OPEN|
                       |          |---> failure --> OPEN
                       +----------+
```

### 3.2 Sentinel Implementation (Go)

Sentinel's circuit breaker (`pkg/k8s/circuit_breaker.go`) is a standalone, mutex-protected
state machine with three explicit states:

```go
type CircuitBreaker struct {
    config *CircuitBreakerConfig
    mu                  sync.RWMutex
    state               CircuitState     // Closed | Open | HalfOpen
    failures            int
    successes           int
    lastFailureTime     time.Time
    lastStateChangeTime time.Time
}
```

Key design decisions:

1. **Explicit half-open with success threshold.** The `SuccessThreshold` (default 2)
   requires multiple successful probe requests before re-closing the circuit. This
   prevents a single lucky success from re-enabling a still-degraded dependency.

2. **Asynchronous state-change callback.** The `OnStateChange` callback fires in a
   separate goroutine (`go cb.config.OnStateChange(oldState, newState)`), preventing
   callback latency from blocking the request path. This is critical for edge nodes where
   the callback might trigger a Kubernetes API call.

3. **Counter reset on transition.** Every `transitionTo` call resets both `failures` and
   `successes` to zero. This ensures clean accounting in each state phase.

4. **Immediate re-open on half-open failure.** A single failure in half-open state
   transitions directly back to open. This is conservative -- appropriate for Kubernetes
   API calls where a failure indicates the control plane is still unreachable.

Usage in the K8s client:

```go
func (c *Client) GetNode(ctx context.Context) (*corev1.Node, error) {
    if !c.circuitBreaker.Allow() {
        return nil, ErrCircuitOpen
    }
    node, err := c.clientset.CoreV1().Nodes().Get(ctx, c.nodeName, metav1.GetOptions{})
    if err != nil {
        c.circuitBreaker.RecordFailure()
        return nil, err
    }
    c.circuitBreaker.RecordSuccess()
    return node, nil
}
```

### 3.3 Swarm Team Six Implementation (Rust)

Swarm's circuit breaker (`crates/swarm-response/src/resilience.rs`) is integrated into a
`ResilientExecutor<E>` wrapper that decorates any `ResponseExecutor` with retry and
circuit-breaking behavior:

```rust
pub struct CircuitBreakerState {
    consecutive_failures: AtomicU32,
    last_failure_time: Mutex<Option<Instant>>,
}
```

Key design decisions:

1. **Threshold + cooldown model** instead of explicit half-open state. The circuit is
   considered "open" when `consecutive_failures >= threshold` AND the time since last
   failure is less than `cooldown_ms`. Once `cooldown_ms` expires, the next request
   is allowed through implicitly (equivalent to half-open) -- if it succeeds,
   `reset_after_success` zeroes the failure counter.

2. **Atomic counters for lock-free reads.** The failure count uses `AtomicU32` with
   `SeqCst` ordering, minimizing contention on the hot path. Only the failure timestamp
   requires a mutex.

3. **Integration with retry loop.** The circuit check happens inside the retry loop:
   ```rust
   for attempt in 0..total_attempts {
       if self.circuit_is_open() {
           return Ok(self.circuit_open_receipt(request, mode));
       }
       // ... execute and potentially retry
   }
   ```
   This means a circuit can open mid-retry, causing remaining retries to fast-fail.

4. **Dead-letter journal on final failure.** When all retries exhaust AND the circuit
   opens, the failed action is serialized to a JSONL dead-letter file for later replay
   or forensic analysis.

5. **DryRun bypass.** Dry-run executions skip the entire resilience layer:
   ```rust
   if mode == ExecutionMode::DryRun {
       return self.inner.execute(request, lease, mode).await;
   }
   ```

### 3.4 Comparison

| Aspect | Sentinel (Go) | Swarm (Rust) |
|--------|---------------|--------------|
| State representation | Explicit enum (Closed/Open/HalfOpen) | Implicit via threshold + cooldown |
| Half-open behavior | Requires N successes to close | Single success resets counter |
| Lock strategy | RWMutex on entire struct | Atomic counter + Mutex only for timestamp |
| Failure granularity | Per-dependency instance | Per-adapter instance |
| Recovery signal | Explicit `RecordSuccess()` | Success in retry loop triggers `reset_after_success()` |
| Integration | Standalone; caller wraps calls | Decorator pattern wraps `ResponseExecutor` trait |
| Dead-letter | Not implemented | JSONL journal with rotation |

### 3.5 Applicability to EDR Adapters

Sentinel's explicit three-state model is better suited for long-lived connections (like
Kubernetes API sessions) where the transition semantics must be visible to operators. For
Swarm's EDR adapters, the threshold+cooldown model is more pragmatic because:

- EDR endpoints are stateless HTTP -- there is no connection to "re-establish"
- The cooldown timer provides natural backoff without an explicit half-open state
- Multiple adapter instances (http_edr, webhook, siem) each need independent circuits

The DR Runbook (`docs/DR-RUNBOOK.md`) documents the operational recovery procedure for a
stuck-open circuit breaker:

> 1. Verify the downstream HTTP EDR or webhook endpoint is healthy independently.
> 2. Wait for the configured `response_adapter.circuit_breaker.cooldown_ms` window to expire.
> 3. If failures continue after downstream recovery, restart the runtime to reset in-memory
>    circuit state.

This "restart to reset" approach is a known limitation of the implicit-state model. An
explicit half-open state with manual reset capability (as in Sentinel) would provide finer
operator control.

---

## 4. Rate Limiting Strategies

### 4.1 Token Bucket (Sentinel)

Sentinel implements a classic token bucket in `pkg/consensus/raft_lite.go`:

```go
type tokenBucket struct {
    mu         sync.Mutex
    tokens     int
    maxTokens  int        // Burst capacity
    refillRate int        // Tokens per second
    lastRefill time.Time
}

func (tb *tokenBucket) Allow() bool {
    tb.mu.Lock()
    defer tb.mu.Unlock()
    now := time.Now()
    elapsed := now.Sub(tb.lastRefill)
    tokensToAdd := int(elapsed.Seconds() * float64(tb.refillRate))
    if tokensToAdd > 0 {
        tb.tokens = min(tb.tokens+tokensToAdd, tb.maxTokens)
        tb.lastRefill = now
    }
    if tb.tokens > 0 {
        tb.tokens--
        return true
    }
    return false
}
```

Configuration defaults:
- `MaxMessagesPerSecond`: 100 (refill rate)
- `BurstSize`: 20 (max tokens / bucket capacity)

The token bucket is applied per-peer for incoming consensus messages. The
`getOrCreateLimiter` method uses a double-checked locking pattern for thread-safe lazy
initialization:

```go
func (n *Node) getOrCreateLimiter(addr string) *tokenBucket {
    n.incomingLimitersMu.RLock()
    limiter, exists := n.incomingLimiters[addr]
    n.incomingLimitersMu.RUnlock()
    if exists { return limiter }

    n.incomingLimitersMu.Lock()
    defer n.incomingLimitersMu.Unlock()
    // Double-check after acquiring write lock
    if limiter, exists = n.incomingLimiters[addr]; exists {
        return limiter
    }
    limiter = newTokenBucket(n.config.RateLimit.BurstSize, n.config.RateLimit.MaxMessagesPerSecond)
    n.incomingLimiters[addr] = limiter
    return limiter
}
```

Rate-limited messages are silently dropped -- no error response is sent. This is
intentional: responding to rate-limited messages would itself consume resources, and in a
Byzantine scenario, an attacker flooding consensus messages should receive no feedback.

### 4.2 Alternative Algorithms

| Algorithm | Burst Behavior | Memory | Fairness | Best For |
|-----------|---------------|--------|----------|----------|
| Token Bucket | Allows bursts up to bucket size | O(1) per limiter | Time-averaged | Consensus messages, API calls |
| Sliding Window | Smoothed; no burst spikes | O(sub-windows) | Uniform over window | External API rate limits |
| Leaky Bucket | No bursts; constant rate | O(queue size) | Perfect smoothness | Serialized execution pipelines |

### 4.3 Applicability to Swarm Agents

Token bucket is the right default for swarm agent communication: burst tolerance is needed
during threat escalation (all agents emit pheromones simultaneously), per-agent isolation
prevents misbehaving agents from exhausting the global budget, and silent dropping is
acceptable because pheromone deposits are idempotent.

For response adapter rate limiting, a leaky bucket would be more appropriate. Swarm's
`max_in_flight_actions` config serves a similar purpose by capping concurrent executions.

---

## 5. Exponential Backoff with Jitter

### 5.1 The Thundering Herd Problem

When N agents simultaneously detect a dependency failure and all retry at the same
interval, the dependency receives N simultaneous retry requests at each retry tick. This
"thundering herd" can prevent recovery even when the dependency is ready to serve
individual requests.

### 5.2 Sentinel Implementation

Sentinel's backoff calculation (`pkg/consensus/raft_lite.go`):

```go
var defaultBackoff = backoffConfig{
    initialDelay: 100 * time.Millisecond,
    maxDelay:     30 * time.Second,
    multiplier:   2.0,
}

func calculateBackoff(failures int, cfg backoffConfig) time.Duration {
    if failures <= 0 {
        return cfg.initialDelay
    }
    delay := cfg.initialDelay
    for i := 0; i < failures && delay < cfg.maxDelay; i++ {
        delay = time.Duration(float64(delay) * cfg.multiplier)
    }
    if delay > cfg.maxDelay {
        delay = cfg.maxDelay
    }
    // Add jitter (10% of delay)
    jitter := time.Duration(mathrand.Int63n(int64(delay / 10)))
    return delay + jitter
}
```

Progression: 100ms -> 200ms -> 400ms -> 800ms -> 1.6s -> 3.2s -> 6.4s -> 12.8s -> 25.6s -> 30s (capped)

Jitter range at each step (10% of delay):
- Step 1: +0 to 20ms
- Step 5: +0 to 320ms
- Step 9: +0 to 3s

**Design note:** Sentinel uses additive jitter (delay + random(0, delay/10)). This means
the jitter is proportional to the backoff duration, providing wider spread at longer
delays where thundering herd is most damaging.

### 5.3 Swarm Implementation

Swarm's backoff in `ResilientExecutor`:

```rust
fn backoff_for_retry(&self, retry_index: u32) -> Duration {
    let millis = (self.retry.initial_backoff_ms as f64)
        * self.retry.backoff_multiplier.powi(retry_index as i32);
    Duration::from_millis(millis.min(30_000.0).round() as u64)
}
```

Default configuration:
- `initial_backoff_ms`: 200 (from `RetryConfig` defaults)
- `backoff_multiplier`: 2.0
- `max_retries`: 3

**Notable absence:** Swarm's backoff does NOT include jitter. This is a confirmed gap
(see `crates/swarm-response/src/resilience.rs`, lines 101--104). When multiple swarm agents
fail against the same EDR endpoint simultaneously, their retry patterns will synchronize.
The fix is straightforward (requires adding `rand` to `swarm-response/Cargo.toml`):

```rust
// Proposed jitter addition
fn backoff_for_retry(&self, retry_index: u32) -> Duration {
    let base_millis = (self.retry.initial_backoff_ms as f64)
        * self.retry.backoff_multiplier.powi(retry_index as i32);
    let jitter = rand::thread_rng().gen_range(0.0..base_millis * 0.1);
    Duration::from_millis((base_millis + jitter).min(30_000.0).round() as u64)
}
```

### 5.4 Jitter Strategies

| Strategy | Formula | Spread | Use Case |
|----------|---------|--------|----------|
| Full jitter | `random(0, delay)` | Maximum | Many independent clients |
| Equal jitter | `delay/2 + random(0, delay/2)` | Medium | Moderate client count |
| Decorrelated jitter | `min(cap, random(base, prev * 3))` | High, uncorrelated | Best general-purpose |
| Additive jitter (Sentinel) | `delay + random(0, delay/10)` | Low | Conservative; peers roughly aligned |

For agent swarms, **full jitter** is generally optimal. Sentinel's conservative 10% jitter
suits its 3--10 node clusters, but a 50+ agent swarm needs wider spread.

### 5.5 Backoff in Peer Reconnection

Sentinel applies backoff to peer reconnection, not just request retries. The `peerConnector`
goroutine skips peers whose `nextRetryTime` has not elapsed, computes backoff via
`calculateBackoff(consecutiveFailures, defaultBackoff)`, and resets on successful dial.
This pattern is directly applicable to swarm substrate (NATS JetStream) reconnection.

---

## 6. Graceful Degradation Hierarchy

### 6.1 Four-Level Hierarchy

Both systems implement graceful degradation, though they formalize it differently. The
combined hierarchy for a security agent system:

```
Level 0: FULL OPERATION
  - All agents running, all adapters connected
  - Live response mode, full audit trail
  - SwarmMode::Normal or ::Alert

Level 1: DEGRADED DETECTION
  - Some agents failed or timed out
  - Detection continues with reduced coverage
  - Response adapters may be circuit-broken
  - Sentinel: CircuitHalfOpen, probing recovery
  - Swarm: AgentHealth::Degraded, tick skipped

Level 2: MINIMAL ALERTING
  - Detection pipeline impaired
  - Only high-confidence, high-severity findings processed
  - Notifications via degraded channel (e.g., dead-letter instead of webhook)
  - Sentinel: CircuitOpen, partitioned from control plane
  - Swarm: RuntimeMode::DetectOnly forced, live response disabled

Level 3: SILENT RECORDING
  - No real-time detection or response
  - Raw telemetry persisted to durable storage for later replay
  - Dead-letter journal accumulating all failed actions
  - Sentinel: fully partitioned, autonomous decisions logged for reconciliation
  - Swarm: All adapters circuit-broken, dead-letter journal only
```

### 6.2 Sentinel's Degradation Path

Sentinel implements degradation through health status composition
(`StatusHealthy`/`StatusDegraded`/`StatusUnhealthy`). The health checker aggregates using
worst-status-wins semantics. Specific triggers: `ConsensusCheck` returns `Degraded` when
partitioned, `CollectorCheck` returns `Unhealthy` when metrics are stale, and
`PredictorCheck` returns `Degraded` when prediction history is insufficient.

### 6.3 Swarm's Degradation Path

Swarm implements degradation through multiple independent mechanisms:

1. **Runtime mode demotion.** The DR Runbook prescribes switching to `detect_only` mode
   when live response infrastructure is unavailable:
   > "If the outage is prolonged and live response must remain disabled, temporarily switch
   > the runtime to `detect_only`."

2. **Circuit breaker cascading.** When an EDR adapter circuit opens, the `ResilientExecutor`
   returns a `circuit_open_receipt` rather than attempting execution. The audit trail
   records this as `AuditResponseRecord::Failure`.

3. **Dead-letter accumulation.** Failed response actions are written to the dead-letter
   journal for later replay. This provides Level 3 (silent recording) automatically.

4. **Guard rejection as degradation signal.** If a guard panics during evaluation,
   `catch_unwind` converts the panic into a `GuardResult::block` with `Severity::Critical`.
   A guard panic is a degradation signal: the system cannot verify action safety, so it
   refuses to act.

### 6.4 Controlled Drain

Swarm implements a PreStop hook (`GET /prestop`) for planned shutdowns: new ingest requests
are rejected, in-flight work drains for up to `drain_timeout_ms`, then the runtime shuts
down cleanly. Sentinel achieves the same via `cancel()` + `wg.Wait()`, but without a drain
timeout.

---

## 7. Bulkhead Pattern

### 7.1 Concept

The bulkhead pattern isolates subsystems so that a failure in one does not cascade to
others. Named after ship bulkheads, the pattern ensures that a flooded compartment does
not sink the entire vessel.

### 7.2 Natural Bulkheads in Swarm Architecture

Swarm Team Six implements structural bulkheads through crate boundaries:

```
Detection Bulkhead       Response Bulkhead       Audit Bulkhead
+------------------+    +------------------+    +------------------+
| swarm-whisker    |    | swarm-response   |    | swarm-spine      |
| swarm-ingest-*   |    | swarm-policy     |    | (chain, store,   |
| swarm-pheromone  |    | swarm-guard      |    |  checkpoint)     |
+------------------+    +------------------+    +------------------+
       |                       |                       |
       v                       v                       v
   Telemetry events     Response execution      Audit persistence
```

This separation means:
- A panic in `swarm-guard` (detection guard) blocks the response pipeline but does not
  affect audit recording
- A dead-letter journal disk full (response bulkhead) does not prevent detection from
  continuing
- An audit store failure does not prevent response execution (responses are
  fire-and-record, not fire-after-record)

### 7.3 Sentinel's Bulkheads

Sentinel uses goroutine-based bulkheads:

```
Consensus Bulkhead       Health Bulkhead        Collection Bulkhead
+------------------+    +------------------+    +------------------+
| electionLoop()   |    | HTTP handlers    |    | collector.go     |
| peerConnector()  |    | (liveness,       |    | predictor.go     |
| leaderLoop()     |    |  readiness,      |    | metrics export   |
| partitionDetect()|    |  health detail)  |    |                  |
+------------------+    +------------------+    +------------------+
```

Each goroutine is independently cancellable via `context.Context`. A hung peer connector
does not block the election loop. A slow health check handler does not block consensus.

### 7.4 Adapter-Level Bulkheads

Swarm's `DispatchingExecutor` creates independent circuit breaker state per adapter:

```rust
enum AdapterInner {
    Sandbox(SandboxExecutor),
    HttpEdr(ResilientExecutor<HttpEdrAdapter>),
    Webhook(ResilientExecutor<WebhookAdapter>),
}
```

Each `ResilientExecutor<E>` maintains its own `CircuitBreakerState`. A failing HTTP EDR
endpoint does not affect the webhook adapter's circuit. This is adapter-level bulkheading.

---

## 8. Timeout and Deadline Propagation

### 8.1 The Problem

In async agent pipelines, a top-level operation (e.g., "detect and respond to this event")
spans multiple stages. If each stage has its own independent timeout, the total operation
time is unbounded: stage 1 might use 4.9s of a 5s timeout, leaving only 100ms for
stages 2--4.

### 8.2 Sentinel's Approach: Context Propagation

Sentinel uses Go's `context.Context` for deadline propagation:

```go
// Health handler creates a bounded context
func (c *Checker) ReadinessHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()
        resp := c.Check(ctx)  // All sub-checks share this deadline
        // ...
    }
}
```

The 5-second timeout is shared across all registered health checks. If the consensus check
takes 4 seconds, the collector check gets at most 1 second.

For Kubernetes API calls, the client config sets a 10-second global timeout:

```go
config.Timeout = 10 * time.Second
```

### 8.3 Swarm's Approach: Stage-Level Timeouts

Swarm uses per-adapter timeouts configured independently:

```rust
// HttpEdrAdapter
let client = Client::builder()
    .timeout(Duration::from_millis(config.timeout_ms))
    .build()?;
```

The `timeout_ms` is configurable per adapter (default 5000ms). However, there is no
top-level deadline that encompasses the full detection-to-response pipeline. The
`audit_authorize_and_execute_instrumented` method tracks stage timings but does not
enforce an overall deadline:

```rust
let policy_started = Instant::now();
let decision = self.policy.evaluate(request, context)?;
let policy_elapsed_us = policy_started.elapsed().as_micros() as u64;
// ... no overall deadline check between stages ...
let response_started = Instant::now();
let response = self.response.execute(request, &lease, execution_mode).await;
let response_elapsed_us = response_started.elapsed().as_micros() as u64;
```

### 8.4 Recommended Deadline Propagation Pattern

Each stage should compute `remaining = deadline.saturating_duration_since(Instant::now())`
and pass it as the timeout to `tokio::time::timeout`. A 10s top-level deadline propagates
as: detection (min 5s, remaining) -> policy (min 1s, remaining) -> response (min remaining,
adapter_timeout). This prevents any single stage from consuming the entire budget.

---

## 9. Health Checking Patterns

### 9.1 Three-Tier Probes

Sentinel implements the Kubernetes probe trinity, each serving a distinct operational
purpose:

**Liveness Probe** (`/livez`):
- Answers "is the process running and not deadlocked?"
- Always returns 200 OK with `{"status": "alive"}`
- Zero dependencies -- does not check any subsystem
- Failure triggers pod restart (destructive recovery)

**Readiness Probe** (`/readyz`):
- Answers "can this instance accept new work?"
- Runs all registered health checks with 5-second timeout
- Returns 503 if ANY check is `StatusUnhealthy`
- Returns 200 even if degraded (degraded can still serve)
- Failure removes instance from load balancer (graceful shed)

**Detailed Health** (`/healthz`):
- Answers "what is the detailed subsystem status?"
- Runs all checks with 10-second timeout
- Returns individual check results with latency
- 200 for healthy or degraded, 503 for unhealthy
- Used for dashboards and operator troubleshooting

### 9.2 Swarm Health Endpoints

The runtime exposes six operational endpoints (see `swarm-runtime/src/ingest.rs`):

```
GET /healthz       - Detailed component health (substrate, adapters, journal)
GET /readyz        - Readiness gate (heap pressure, substrate connectivity)
GET /startupz      - Startup completion gate
GET /livez         - Liveness probe (process alive, not deadlocked)
GET /metrics       - Prometheus metrics (swarm_heap_bytes, adapter_outcomes)
GET /prestop       - Graceful drain trigger
```

Swarm also exposes `/livez`, mirroring Sentinel's liveness probe. The `/startupz` endpoint
is an addition Sentinel lacks. It serves the Kubernetes `startupProbe`, preventing liveness
checks from killing a slow-starting runtime:

```
Pod lifecycle:
  1. startupProbe polls /startupz every 5s for up to 120s
  2. Once /startupz returns 200, startupProbe stops
  3. livenessProbe and readinessProbe begin
```

### 9.3 Health Check Composition

Sentinel registers domain-specific checks as named functions:

```go
checker.Register("collector", CollectorCheck(lastCollectionTime, 5*time.Minute))
checker.Register("consensus", ConsensusCheck(node.IsPartitioned, node.PartitionDuration))
checker.Register("predictor", PredictorCheck(predictor.HistorySize, 10))
```

Each check returns a `CheckResult{Status, Message, Latency}`. The aggregator computes
the composite status as `max(all check statuses)` using the ordering
`Healthy < Degraded < Unhealthy`.

### 9.4 Applying Sentinel's Pattern to Swarm Agents

Individual swarm agents report `AgentHealth` (Healthy/Degraded/Failed), but there is no
composite health aggregation across agents. A `SwarmHealthChecker` that registers per-agent
health functions, per-adapter circuit state, and substrate connectivity would allow the
`/healthz` endpoint to report composite status with per-component latency -- directly
mirroring Sentinel's `Checker.Check()` aggregation pattern.

---

## 10. Chaos Engineering for Agent Swarms

### 10.1 Fault Injection Categories

| Category | Target | Expected Behavior |
|----------|--------|-------------------|
| Process kill | Individual agent | Dispatcher detects `AgentHealth::Failed`; remaining agents absorb load |
| Network partition | Between agents and substrate | Agents degrade; detection continues with local state |
| Latency injection | EDR adapter responses | Circuit breaker opens; dead-letter captures failed actions |
| Resource exhaustion | Agent memory / CPU | `max_heap_pressure` triggers readiness failure; pod rescheduled |
| Clock skew | Agent-to-agent time drift | Lease expiration miscalculated; capability scoping fails |
| Byzantine injection | False pheromone deposits | BFT consensus rejects actions without quorum agreement |

### 10.2 Network Partition Simulation

Sentinel's `partitionDetector` monitors `healthyPeers < quorum` to detect partitions.
Testing: deploy 5 nodes, use iptables to partition node 1, verify partition detection and
autonomous decision logging, heal partition, verify `GetUnreconciledDecisions()` is
non-empty.

For Swarm: kill NATS pod, verify `/healthz` reports substrate unhealthy, verify detection
continues locally, verify response actions accumulate in dead-letter journal, restore NATS,
replay dead-letter entries.

### 10.3 Resource Exhaustion Testing

Swarm's `max_heap_pressure` config provides a built-in resource exhaustion detector.
Under memory pressure, `/readyz` returns 503 (unhealthy) while `/livez` remains 200
(alive). This separation ensures the pod is removed from the load balancer but not killed
-- a graceful shed rather than a destructive restart.

### 10.4 Guard Pipeline Chaos

The guard pipeline's `catch_unwind` wrapper is itself a chaos-tolerance mechanism. Chaos
test: inject a guard that randomly panics 50% of the time, then verify panics are caught
as `GuardResult::block`, the pipeline short-circuits, the response action is NOT executed,
and the audit trail records `AuditResponseRecord::GuardRejected`.

### 10.5 Key Chaos Invariants

A chaos testing framework for agent swarms should assert these invariants:

- **SAFETY:** `never(response_executed AND NOT policy_approved)`
- **SAFETY:** `never(response_executed AND guard_rejected)`
- **SAFETY:** `never(response_executed AND lease_expired)`
- **LIVENESS:** `eventually(detection_event_processed, timeout=30s)`
- **LIVENESS:** `eventually(circuit_closed, timeout=cooldown_ms*2)`
- **ORDERING:** `always(policy_before_guard_before_response)`

---

## 11. Self-Healing Patterns

### 11.1 Automatic Recovery

Both systems implement recovery without operator intervention:

**Sentinel circuit breaker auto-recovery:**
```
CLOSED --[5 failures]--> OPEN --[30s timeout]--> HALF-OPEN --[2 successes]--> CLOSED
```

The system automatically probes recovery by transitioning to half-open after the timeout.
No operator action is required unless the underlying issue persists.

**Swarm circuit breaker auto-recovery:**
```
Normal --[threshold failures]--> Open --[cooldown_ms]--> Implicit probe --[success]--> Normal
```

Same pattern, different mechanism: the cooldown timer allows the next request through
implicitly.

### 11.2 Leader Re-Election

Sentinel's Raft-lite implements leader re-election as self-healing. When the leader
crashes, followers detect absence of heartbeats (election timeout expires). The randomized
timeout `[ElectionTimeout, 2*ElectionTimeout]` prevents synchronized elections. A new
leader emerges via `startElection()` -> majority vote -> `leaderLoop()`.

For Swarm, the analogous mechanism is the `SwarmModeState` machine with monotonic
escalation (Normal -> Alert -> Incident, never backwards). This prevents oscillation
during healing; de-escalation requires explicit operator action.

### 11.3 Substrate Failover

When the pheromone substrate (NATS JetStream) becomes unavailable, agents should continue
detection locally, buffer deposits, reconnect with exponential backoff, flush on
reconnection, and reconcile conflicting state. This mirrors Sentinel's partition recovery
via `GetUnreconciledDecisions()`.

### 11.4 Dead-Letter Replay as Self-Healing

Swarm's dead-letter journal is not just an error log -- it is a self-healing mechanism.
After failure resolution, entries can be read via `journal.read_entries()` and re-executed
with fresh leases. The rotation mechanism (`max_dead_letter_bytes`) prevents unbounded
growth while preserving recent failures for replay.

---

## 12. Comparison with Resilience Libraries

### 12.1 Netflix Hystrix (Java)

Hystrix pioneered the circuit breaker pattern in microservices. Key concepts that both
projects adopt:

| Hystrix Concept | Sentinel Equivalent | Swarm Equivalent |
|----------------|--------------------|--------------------|
| `HystrixCommand` | Direct `Allow()`/`RecordSuccess()`/`RecordFailure()` calls | `ResilientExecutor` decorator |
| Circuit breaker | `CircuitBreaker` struct | `CircuitBreakerState` in `ResilientExecutor` |
| Bulkhead (thread pool) | Goroutine isolation | Crate boundaries + `max_in_flight_actions` |
| Fallback | `ErrCircuitOpen` return | `circuit_open_receipt` with `ResponseStatus::Failed` |
| Metrics stream | `CircuitBreakerStats` | Prometheus metrics via `prometheus-client` |
| Request cache | Not implemented | Not implemented |
| Request collapsing | Not implemented | Not implemented |

Hystrix's request collapsing (batching multiple requests into one) would be valuable for
swarm pheromone deposits, where N agents may deposit the same threat class indicator
within a short window.

### 12.2 Polly (.NET)

Polly provides policy-based resilience. Its policy composition model is relevant:

```
Policy.Wrap(
    circuitBreaker,    // Outer: fail fast if circuit open
    retry,             // Middle: retry transient failures
    timeout            // Inner: bound individual attempts
)
```

Swarm's `ResilientExecutor` effectively implements this composition inline:

```rust
for attempt in 0..total_attempts {         // retry policy
    if self.circuit_is_open() { ... }      // circuit breaker policy
    match self.inner.execute(...).await {   // inner execution (with timeout via reqwest)
        Ok(receipt) if receipt.status.indicates_success() => { ... }
        Ok(receipt) => { /* retry or dead-letter */ }
        Err(error) => { /* retry or dead-letter */ }
    }
}
```

A more modular approach (like Polly's policy wrapping) would allow operators to
reconfigure the resilience stack without code changes:

```yaml
resilience:
  - type: circuit_breaker
    threshold: 5
    cooldown_ms: 30000
  - type: retry
    max_retries: 3
    backoff: exponential
    initial_ms: 100
  - type: timeout
    ms: 5000
```

### 12.3 Tower (Rust)

The `swarm-runtime` crate already depends on `tower` (see `crates/swarm-runtime/Cargo.toml`),
making Tower's composable middleware directly relevant. Key mappings:
`ConcurrencyLimit` -> `max_in_flight_actions`, `Timeout` -> `reqwest::Client::timeout`,
`Retry` -> `ResilientExecutor` retry loop, `LoadShed` -> `/readyz` returning 503.

The main blocker to Tower migration is that `ResponseExecutor` is an `async_trait` rather
than a Tower `Service`. Migration would require refactoring to implement
`Service<ActionRequest, Response = ResponseReceipt>`.

### 12.4 Alibaba Sentinel (Java)

Despite sharing a name with the Go project analyzed here, Alibaba Sentinel is a
flow-control and circuit-breaking library for Java microservices. Key differences:

| Aspect | Alibaba Sentinel | Sentinel (Go) | Swarm (Rust) |
|--------|-----------------|----------------|--------------|
| Scope | General microservice resilience | Edge K8s node management | EDR response pipeline |
| Circuit breaker | Slow request ratio, error ratio, error count | Consecutive failure count | Consecutive failure count |
| Rate limiting | QPS + thread count + adaptive | Token bucket per peer | Config-based max retries |
| Flow control | Warm up, queue, reject | Binary allow/reject | Binary allow/reject |
| Dashboard | Real-time web console | JSON health endpoints | Prometheus + operator HTTP |

Alibaba Sentinel's "slow request ratio" circuit breaker is worth noting: it opens the
circuit when the ratio of requests exceeding a latency threshold exceeds a configured
percentage. This would be valuable for EDR adapters where a responding-but-slow endpoint
is worse than a non-responding one (because it consumes resources without completing
actions).

---

## 13. Fail-Closed vs Fail-Open Semantics

### 13.1 The Security Context

In security systems, the choice between fail-closed and fail-open has direct security
implications:

```
Fail-Closed: When uncertain, DENY the action.
  - Blocks legitimate actions during failures
  - Prevents unauthorized actions during failures
  - Appropriate for: response actions, credential operations, network modifications

Fail-Open: When uncertain, ALLOW the action.
  - Permits legitimate actions during failures
  - May permit unauthorized actions during failures
  - Appropriate for: detection/logging, monitoring, telemetry collection
```

### 13.2 Swarm's Fail-Closed Guard Pipeline

The guard pipeline (`crates/swarm-guard/src/lib.rs`) is explicitly fail-closed with three
rejection paths:

1. **Guard panic** -- `catch_unwind` converts to `GuardResult::block(name, Severity::Critical, msg)`
2. **Invalid result** (empty guard name) -- converted to `GuardResult::block(name, Severity::Critical, msg)`
3. **Explicit block** from any guard -- short-circuit, remaining guards skipped

The pipeline evaluates guards in order, skipping those that do not `handle` the action
type. Any block terminates evaluation immediately.

### 13.3 Swarm's Fail-Closed Policy Gate

The `StaticApprovalGate` enforces layered fail-closed semantics: invalid requests return
`Err` (validation failure), low-severity destructive actions return a `PolicyVerdict::Deny`
decision, and high-severity destructive actions return `PolicyVerdict::RequireHuman`. In
`LiveResponse` mode, the runtime treats `RequireHuman` as a denial -- ensuring no
execution without human confirmation.

### 13.4 Detection: Permissive (Fail-Open)

Detection should be fail-open: tick failures log and continue, deposit failures cache
locally, correlation failures emit uncorrelated findings. Swarm implements this through
`AgentHealth::Degraded` -- a degraded agent still runs its tick loop.

### 13.5 Response: Restrictive (Fail-Closed)

Response must be fail-closed: guard failures block, policy failures deny, expired leases
reject, adapter failures dead-letter. Every link in the response chain defaults to "do not
act" on uncertainty.

### 13.6 Decision Matrix

| Subsystem | Fail Mode | Rationale |
|-----------|-----------|-----------|
| Telemetry ingestion | Fail-open | Missed events = missed threats |
| Detection (whisker) | Fail-open | False positives are correctable; missed detections are not |
| Pheromone deposit | Fail-open | Duplicate deposits merge; missing deposits blind the swarm |
| Correlation | Fail-open | Uncorrelated findings are still valuable |
| Policy evaluation | **Fail-closed** | Unauthorized response actions are irreversible |
| Guard pipeline | **Fail-closed** | Unverified actions may violate safety constraints |
| Response execution | **Fail-closed** | Unauthorized network/host changes are catastrophic |
| Audit recording | Fail-open | Missing audit entries are bad but not safety-critical |
| Notification | Fail-open | Missed notifications can be replayed from audit trail |

---

## 14. Reference Resilience Architecture

### 14.1 Combined Architecture Diagram

```
                        +---------------------------+
                        |     Telemetry Ingestion    |
                        |  (fail-open, rate-limited) |
                        +-------------+-------------+
                                      |
                        +-------------v-------------+
                        |     Detection Pipeline     |
                        |  (fail-open, bulkheaded)   |
                        |                            |
                        |  +--------+   +--------+   |
                        |  |Whisker |   |Whisker |   |
                        |  |Agent A |   |Agent B |   |
                        |  +---+----+   +---+----+   |
                        |      |            |        |
                        +------+-----+------+--------+
                               |     |
                        +------v-----v------+
                        |  Pheromone Layer   |
                        | (token bucket RL)  |
                        |  +health checks+   |
                        +--------+----------+
                                 |
                        +--------v----------+
                        |    Correlation     |
                        | (deadline-bounded) |
                        +--------+----------+
                                 |
                  +--------------v--------------+
                  |      Response Pipeline      |
                  |     (fail-closed chain)      |
                  |                              |
                  |  +--------+    +----------+  |
                  |  | Guard  |--->|  Policy  |  |
                  |  |Pipeline|    |   Gate   |  |
                  |  |(panic  |    |(severity |  |
                  |  | catch) |    | + lease) |  |
                  |  +---+----+    +----+-----+  |
                  |      |              |         |
                  |      v              v         |
                  |  +--------+    +----------+  |
                  |  |Bulkhead|    | Execution |  |
                  |  |(max    |    | (circuit  |  |
                  |  |inflight)|   |  breaker  |  |
                  |  +--------+    |  + retry  |  |
                  |                |  + backoff|  |
                  |                |  + jitter)|  |
                  |                +----+------+  |
                  |                     |         |
                  +---------------------+---------+
                                        |
                        +---------------v---------+
                        |      Audit Trail        |
                        |   (fail-open, durable)   |
                        |                          |
                        |  +----------+  +------+  |
                        |  | Spine    |  | Dead  |  |
                        |  | (signed  |  |Letter |  |
                        |  | envelope)|  |Journal|  |
                        |  +----------+  +------+  |
                        +--------------------------+
                                        |
                        +---------------v---------+
                        |   Health & Observability  |
                        |                          |
                        |  /healthz  (detailed)    |
                        |  /readyz   (traffic)     |
                        |  /startupz (boot)        |
                        |  /metrics  (prometheus)   |
                        +--------------------------+
```

### 14.2 Resilience Pattern Placement

| Layer | Pattern | Configuration |
|-------|---------|---------------|
| Ingestion | Rate limiting (token bucket) | `MaxMessagesPerSecond: 100`, `BurstSize: 20` |
| Ingestion | Backpressure (load shed) | Reject when readiness probe fails |
| Detection | Bulkhead (agent isolation) | Per-agent tick timeout, independent failure tracking |
| Detection | Health monitoring | Per-agent `AgentHealth` status |
| Pheromone | Rate limiting | Per-agent deposit rate |
| Pheromone | Substrate failover | Local cache + reconnect with backoff |
| Correlation | Deadline propagation | Top-level deadline shared across stages |
| Guard | Fail-closed | Panic catch, invalid-result catch, short-circuit |
| Policy | Fail-closed | Severity-gated, lease-scoped, human-gate |
| Execution | Circuit breaker | Threshold: 5, Cooldown: 30s (configurable) |
| Execution | Retry with backoff | Max retries: 3, initial: 100ms, multiplier: 2x |
| Execution | Jitter | 10% additive (add full jitter for swarms) |
| Execution | Dead-letter | JSONL journal with rotation at `max_dead_letter_bytes` |
| Execution | Bulkhead | `max_in_flight_actions` cap |
| Audit | Fail-open | Write failures logged but do not block response |
| Audit | Cryptographic integrity | ed25519 envelope signing, chain verification |
| Health | Three-tier probes | Liveness (always OK), Readiness (subsystem check), Detailed (latency) |
| Ops | Controlled drain | PreStop hook with `drain_timeout_ms` |

### 14.3 Reference Configuration

| Parameter | Recommended Default | Source |
|-----------|-------------------|--------|
| `circuit_breaker.threshold` | 5 | Both projects |
| `circuit_breaker.cooldown_ms` | 30000 | Both projects |
| `retry.max_retries` | 3 | Swarm default |
| `retry.initial_backoff_ms` | 100--200 | Sentinel: 100ms, Swarm: 200ms |
| `retry.backoff_multiplier` | 2.0 | Both projects |
| `retry.jitter` | full | Upgrade from Sentinel's 10% additive |
| `rate_limit.max_per_second` | 100 | Sentinel default |
| `rate_limit.burst_size` | 20 | Sentinel default |
| `bulkhead.response_pool` | 4 | Swarm `max_in_flight_actions` (current default) |
| `timeout.overall_pipeline_ms` | 10000 | Recommended addition |
| `timeout.adapter_execution_ms` | 5000 | Swarm default |
| `health.readiness_timeout_ms` | 5000 | Sentinel default |

### 14.4 Implementation Priorities

For Swarm Team Six, the following enhancements are ordered by impact:

Items 1-4 below are compatible with the current single-node roadmap and do not
depend on distributed consensus landing first.

1. **Add jitter to `ResilientExecutor::backoff_for_retry`** -- Low effort, high impact.
   Prevents thundering herd across concurrent agent response attempts.

2. **Implement top-level deadline propagation** -- Medium effort. Wrap the
   `authorize_and_execute` path in a shared deadline that decrements through stages.

3. **Composite health aggregation** -- Medium effort. Aggregate per-agent, per-adapter,
   and substrate health into a single `/healthz` response.

4. **Explicit half-open state in circuit breaker** -- Low effort. Add a success threshold
   (like Sentinel's `SuccessThreshold: 2`) to prevent premature circuit closure after a
   single lucky success.

5. **Tower middleware migration** -- High effort. Refactor `ResponseExecutor` to implement
   Tower's `Service` trait, enabling composable middleware stacking.

6. **Substrate failover with local cache** -- High effort. Buffer pheromone deposits
   locally during NATS outages and flush on reconnection.

---

## Appendix: Source Cross-Reference

### Sentinel Files

| File | Key Constructs |
|------|----------------|
| `pkg/k8s/circuit_breaker.go` | `CircuitBreaker`, `CircuitState`, `CircuitBreakerConfig`, `Allow()`, `RecordSuccess()`, `RecordFailure()`, `transitionTo()` |
| `pkg/consensus/raft_lite.go` | `tokenBucket`, `calculateBackoff`, `backoffConfig`, `RateLimitConfig`, `peerConn` (backoff fields), `partitionDetector()`, `startElection()` |
| `pkg/health/health.go` | `Checker`, `Check`, `CheckResult`, `LivenessHandler()`, `ReadinessHandler()`, `HealthHandler()`, `CollectorCheck`, `ConsensusCheck`, `PredictorCheck` |
| `pkg/k8s/client.go` | `Client` (circuit breaker integration), `GetNode()`, `DrainNode()` |

### Swarm Team Six Files

| File | Key Constructs |
|------|----------------|
| `crates/swarm-consensus/src/lib.rs` | BFT consensus protocol (Tendermint-style, `2f+1` agreement); currently a TODO stub |
| `crates/swarm-guard/src/lib.rs` | `GuardPipeline`, `Guard` trait, `GuardResult`, `evaluate()` (fail-closed with `catch_unwind`) |
| `crates/swarm-policy/src/lib.rs` | `ApprovalGate` trait, `PolicyDecision`, `PolicyVerdict`, `CapabilityLease`, `ActionRequest` |
| `crates/swarm-policy/src/static_gate.rs` | `StaticApprovalGate`, severity-based gating, destructive action classification |
| `crates/swarm-response/src/lib.rs` | `ResponseExecutor` trait, `ExecutionMode`, `ResponseReceipt`, `ResponseStatus` |
| `crates/swarm-response/src/resilience.rs` | `ResilientExecutor`, `CircuitBreakerState`, retry loop, dead-letter integration |
| `crates/swarm-response/src/dead_letter.rs` | `DeadLetterJournal`, JSONL persistence, rotation |
| `crates/swarm-response/src/dispatch.rs` | `DispatchingExecutor`, per-adapter `ResilientExecutor` wiring |
| `crates/swarm-response/src/http_edr.rs` | `HttpEdrAdapter`, timeout handling, HTTP POST execution |
| `crates/swarm-runtime/src/lib.rs` | `SwarmRuntime`, `authorize_and_execute()`, `audit_authorize_and_execute_instrumented()`, guard + policy + response composition |
| `crates/swarm-runtime/src/ingest.rs` | Health endpoints (`/healthz`, `/readyz`, `/startupz`, `/livez`, `/prestop`, `/metrics`), ingest router |
| `crates/swarm-core/src/agent.rs` | `AgentHealth`, `SwarmMode`, `SwarmModeState`, tick loop |
| `crates/swarm-core/src/config.rs` | `RetryConfig`, `CircuitBreakerConfig`, default constants |
| `crates/swarm-core/src/types.rs` | `ResponseAction`, `Severity`, `AgentId` |
| `crates/swarm-spine/src/lib.rs` | `AuditTrail`, `AuditResponseRecord`, `PolicyRecord`, `ReplayBundle` |
| `docs/DR-RUNBOOK.md` | Circuit breaker recovery, JetStream loss, dead-letter disk full, PolicyVerdict::Deny blocking |

---

## Cross-References

This document is part of the Sentinel Convergence research series (8 of 8). Related
documents and their relevance to the resilience patterns discussed here:

| # | Document | Relevance |
|---|----------|-----------|
| 01 | [Distributed Consensus for Agent Swarms](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Raft-lite and BFT consensus underpin the partition detection and leader re-election self-healing patterns analyzed in Sections 2, 5.5, and 11.2. |
| 02 | [Predictive Failure as Threat Signal](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Sentinel's health-score predictor feeds the health checking patterns (Section 9) and the graceful degradation hierarchy (Section 6). |
| 03 | [Edge-Native Security Detection](03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge deployment constraints motivate the circuit breaker timeout values and the autonomous-operation mode discussed in Sections 3 and 6. |
| 04 | [Autonomous Response Under Partition](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | Directly extends the partition scenarios in Section 2.2 and the fail-closed response semantics in Section 13. |
| 05 | [Telemetry Bridge Architecture](05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | The telemetry ingestion layer in the reference architecture (Section 14) depends on the bridge design explored here. |
| 06 | [Stigmergic Coordination and Swarm Intelligence](06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Pheromone-layer rate limiting (Section 4.3) and substrate failover (Section 11.3) build on the stigmergic model. |
| 07 | [Audit Trails and Decision Reconciliation](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | The dead-letter replay pattern (Section 11.4) and cryptographic audit integrity (Section 14) connect to the reconciliation protocol. |
