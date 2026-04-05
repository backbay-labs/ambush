# Phase 84: Real Response Adapters -- Context

## User Decisions

### Locked Decisions

- Two adapters: `HttpEdrAdapter` (block/isolate to EDR endpoint) and `WebhookAdapter` (Slack/PagerDuty-compatible JSON)
- Both must implement existing `ResponseExecutor` trait
- Both must fire only after guard pipeline + policy gate approval (already enforced by `swarm-runtime`)
- Each execution produces a receipt with result status including timeout handling
- `reqwest` is the HTTP client (add to workspace dependencies)
- Config should specify adapter type, endpoint URL, auth token, timeout
- Adapters selectable via runtime config similar to detector selection

### Deferred

- Real EDR vendor SDK integration (CrowdStrike Falcon, Defender, etc.)
- TLS certificate management (use reverse proxy)
- Retry policies beyond timeout (future work)

### Claude's Discretion

- Exact config field names and structure
- Whether to add `Timeout`/`Failed` to `ResponseStatus` or keep using `ResponseError` for non-success
- Internal HTTP client construction details
- Test mock server approach

## Key Existing Contracts

### ResponseExecutor trait (swarm-response/src/lib.rs)

```rust
#[async_trait]
pub trait ResponseExecutor: Send + Sync {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError>;
}
```

### ResponseReceipt (swarm-response/src/lib.rs)

```rust
pub struct ResponseReceipt {
    pub receipt_id: String,
    pub action: String,
    pub mode: ExecutionMode,
    pub status: ResponseStatus,
    pub summary: String,
    pub details: serde_json::Value,
}
```

### ResponseStatus (swarm-response/src/lib.rs)

Currently only `Simulated` and `Executed`. May need extension.

### ResponseAction variants (swarm-core/src/types.rs)

```rust
pub enum ResponseAction {
    BlockEgress { target: String },
    IsolateHost { host_id: String },
    RevokeCredential { credential_id: String },
    DeployDecoy { decoy_type: String, target_zone: String },
    Escalate { summary: String, urgency: Severity },
}
```

### Guard + policy gating (swarm-runtime/src/lib.rs)

`authorize_and_execute` already runs policy evaluation then guard pipeline before calling `self.response.execute()`. New adapters get guard protection for free by plugging into the existing `ResponseExecutor` slot.

### SandboxExecutor pattern (swarm-response/src/adapters.rs)

Reference implementation showing receipt construction, action name extraction, and error handling patterns.
