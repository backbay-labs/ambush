# ADR 0013: Minimal Type Changes for Bounded Partition Authority

## Status

Proposed on 2026-04-07.

## Context

Doc 11 (Partition Authority Matrix) defines contingency leases, degraded
action variants, blast-radius caps, and escalation tiers for autonomous
response during network partition. None of this is expressible in the
current type system, which assumes a connected governance plane for every
destructive action. This ADR identifies the smallest type diff that makes
the doc-11 matrix representable.

---

## 1. Inventory of Touched Types

| Type | Crate / File | Expresses Today | Cannot Express |
|------|-------------|-----------------|----------------|
| `ResponseAction` | swarm-core/types.rs | 5 action variants with string targets | Soft-isolate (degraded `IsolateHost`) |
| `CapabilityLease` | swarm-policy/lib.rs | Single-use lease: id, expiry, action string, optional scope | Multi-use, blast-radius caps, issuer signature, activation condition |
| `PolicyVerdict` | swarm-policy/lib.rs | `Deny`, `Allow`, `RequireHuman` | "Allowed under contingency lease" (audit distinction) |
| `StaticApprovalGate` | swarm-policy/static_gate.rs | Severity threshold + rate limit | Partition-aware resolution of `RequireHuman`; contingency lease lookup |
| `SwarmMode` | swarm-core/agent.rs | `Normal`, `Alert`, `Incident` (threat posture) | Partition state (orthogonal to threat mode) |
| `SwarmEnvironment` | swarm-core/agent.rs | Mode, pheromones, peer findings, timestamp | Partition state, escalation tier |
| `ApprovalContext` | swarm-policy/lib.rs | `live_mode`, `receipt_chain`, `correlation_id`, `now_ms` | Partition flag for gate branching |
| `ResponseReceiptAudit` | swarm-response/lib.rs | Optional `ResponsePolicyAudit` | Contingency lease attribution |
| `GuardPipeline` | swarm-guard/lib.rs | Ordered fail-closed guard chain | **No gap.** Guard pipeline is never relaxed during partition. |

---

## 2. Alternatives Evaluated

### Option A: New `ContingencyLease` Type (Doc-11's Proposal)

Separate struct alongside `CapabilityLease`. New `ContingencyActionClass`,
`ContingencyScope`, `ContingencyLeaseStore`.

- **New types**: 5 | **Lines**: ~120 | **Existing consumer breakage**: Zero
- **Type safety**: Strong -- normal and contingency leases incompatible at compile time

### Option B: Extend `CapabilityLease` with Optional Fields

Add `max_uses`, `blast_radius`, `issuer_signature`, `activation` as `Option` fields.

- **New types**: 2 | **Lines**: ~50 | **Existing consumer breakage**: Zero
- **Type safety**: Weak -- cannot enforce all-or-nothing invariant on contingency fields

### Option C: Wrapper Enum `LeaseKind { Normal(CapabilityLease), Contingency(ContingencyLease) }`

- **New types**: 4 | **Lines**: ~100 | **Existing consumer breakage**: High -- `ResponseExecutor` trait signature changes, breaks all adapters and test doubles
- **Type safety**: Strong

### Decision: Option A

1. **Zero existing consumer breakage.** `CapabilityLease`, `ApprovalGate`,
   `ResponseExecutor`, and all tests untouched. Contingency lease is a
   parallel path for the new partition-mode gate only.
2. **Type safety without wrapping churn.** Distinct types prevent accidental
   misuse; no runtime checks needed.
3. **Smallest blast radius.** Option C breaks `SandboxExecutor`,
   `DispatchingExecutor`, `ResilientExecutor`, `HttpEdrAdapter`,
   `WebhookAdapter`, and all test doubles. Option B sacrifices type safety.
   Option A sacrifices neither.

Cost: ~20 lines of duplicated expiry-check logic, acceptable for a
security-critical boundary.

---

## 3. Proposed Minimal Diff

### 3.1 `PartitionState` + `EscalationTier` in swarm-core/src/agent.rs

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionState {
    Connected,
    Partitioned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTier {
    ContingencyAuthority, // Tier 0: leases active
    DetectionOnly,        // Tier 1: leases expired, detect + buffer
    PassiveObservation,   // Tier 2: pheromone + health, 50% sampling
    Hibernation,          // Tier 3: health beacon only
}
```

Add to `SwarmEnvironment` (both `Option` -- no existing site breaks):

```rust
pub partition: Option<PartitionState>,
pub escalation_tier: Option<EscalationTier>,
```

### 3.2 `ContingencyLease` + supporting types in swarm-policy/src/lib.rs

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContingencyActionClass {
    BlockEgress,
    IsolateHost,
    DeployDecoy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusCap {
    pub max_targets: u32,
    /// Min CIDR prefix length (e.g. 24 = /24 widest). BlockEgress only.
    pub min_cidr_prefix: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContingencyScope {
    pub allowed_targets: Vec<String>,
    pub blast_radius: BlastRadiusCap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContingencyLease {
    pub lease_id: String,
    pub action_class: ContingencyActionClass,
    pub min_severity: Severity,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub max_uses: u32,
    pub uses: u32,
    pub scope: ContingencyScope,
    pub issuer_signature: Vec<u8>,
}
```

### 3.3 `ContingencyLeaseStore` in swarm-policy/src/contingency.rs (new file)

```rust
#[derive(Debug, Default)]
pub struct ContingencyLeaseStore {
    leases: HashMap<ContingencyActionClass, Vec<ContingencyLease>>,
    episode_counters: EpisodeCounters,
}

#[derive(Debug, Default)]
pub struct EpisodeCounters {
    pub total_ips_blocked: u32,     // cap: 50
    pub total_hosts_isolated: u32,  // cap: 3
    pub total_decoys_deployed: u32, // cap: 9
    pub total_leases_consumed: u32, // cap: 20
}

impl ContingencyLeaseStore {
    /// Find valid lease matching action class, severity, and time.
    pub fn find_lease(&self, class: ContingencyActionClass,
        severity: Severity, now_ms: i64) -> Option<&ContingencyLease>;

    /// Check aggregate episode caps for action class.
    pub fn within_episode_caps(&self, class: ContingencyActionClass) -> bool;

    /// Record lease exercise. Returns false if any cap exceeded.
    pub fn record_use(&mut self, lease_id: &str,
        class: ContingencyActionClass) -> bool;

    /// Replace lease set for an action class (on renewal).
    pub fn ingest(&mut self, class: ContingencyActionClass,
        leases: Vec<ContingencyLease>);

    /// Reset episode counters on partition heal.
    pub fn reset_episode(&mut self);
}
```

### 3.4 `IsolationMode` on `ResponseAction::IsolateHost` in swarm-core/src/types.rs

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    Full, // Sever all connectivity. Requires connected governance.
    Soft, // Block egress only. Preserve monitoring/management ports.
}
impl Default for IsolationMode { fn default() -> Self { Self::Full } }
```

```rust
// before
IsolateHost { host_id: String },
// after
IsolateHost { host_id: String, #[serde(default)] isolation_mode: IsolationMode },
```

`#[serde(default)]` preserves backward compatibility for deserialization.
The partition-mode gate constructs `IsolationMode::Soft` before dispatch;
the receipt records which mode was actually executed.

**Why a mode flag, not a new variant or policy rewrite:**
- New variant `SoftIsolateHost` breaks 12+ `match` sites across 5 crates.
- Policy rewrite (silently converting to `BlockEgress`) loses audit
  fidelity: receipt says `block_egress` when operator intended `isolate_host`.
- Mode flag changes ~5 struct-literal sites, preserves intent in receipt.

### 3.5 `partitioned` flag on `ApprovalContext` in swarm-policy/src/lib.rs

```rust
// added field
#[serde(default)]
pub partitioned: bool,
```

Intentional compile-time breakage at all struct-literal sites -- every
approval call must consciously declare partition state.

### 3.6 `AllowContingency` on `PolicyVerdict` in swarm-policy/src/lib.rs

```rust
pub enum PolicyVerdict {
    Deny,
    Allow,
    RequireHuman,
    AllowContingency, // new: audit-distinguishes contingency authorization
}
```

Compiler errors at non-exhaustive `match` sites (~4) force each to decide
how to handle contingency-authorized actions.

### 3.7 `contingency_lease_id` on `ResponseReceiptAudit` in swarm-response/src/lib.rs

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub contingency_lease_id: Option<String>,
```

---

## 4. Blast Radius Cap Representation

Blast-radius caps are **runtime checks**, not compile-time constraints.
The limits ("max 10 IPs", "max 1 host") depend on the lease instance and
running aggregate counters -- unknowable at compile time.

The type system's role is to make the cap **structurally mandatory**:

- `BlastRadiusCap` is a required field on `ContingencyScope` -- you cannot
  construct a `ContingencyLease` without it.
- `EpisodeCounters` tracks aggregates with `const` caps.
- `ContingencyLeaseStore::record_use` returns `false` when any cap is hit.

Per-lease `max_targets` is checked by the partition-mode gate before
dispatching to the executor. Aggregate caps are checked by the store.

---

## 5. Degraded Action Representation

Covered in Section 3.4. Summary of the decision:

| Approach | Match-site breakage | Audit fidelity | Chosen |
|----------|-------------------|----------------|--------|
| New `SoftIsolateHost` variant | 12+ sites across 5 crates | High | No |
| Policy rewrite to `BlockEgress` | 0 sites | Low (receipt lies) | No |
| `IsolationMode` flag on existing variant | ~5 struct-literal sites | High | **Yes** |

```rust
// Partition-mode gate usage:
let degraded = ResponseAction::IsolateHost {
    host_id: original.host_id.clone(),
    isolation_mode: IsolationMode::Soft,
};
```

---

## 6. Migration Checklist

| # | File | Change | Est. Lines |
|---|------|--------|------------|
| 1 | `swarm-core/src/types.rs` | Add `IsolationMode` enum, add field to `IsolateHost` | +15 |
| 2 | `swarm-core/src/agent.rs` | Add `PartitionState`, `EscalationTier`, extend `SwarmEnvironment` | +25 |
| 3 | `swarm-policy/src/lib.rs` | Add contingency types, `AllowContingency`, `partitioned` flag, `pub mod contingency` | +55 |
| 4 | `swarm-policy/src/contingency.rs` | New file: `ContingencyLeaseStore`, `EpisodeCounters` | +90 |
| 5 | `swarm-policy/src/static_gate.rs` | Update `IsolateHost` match arms | +5 |
| 6 | `swarm-response/src/lib.rs` | Add `contingency_lease_id` to audit struct | +3 |
| 7 | `swarm-response/src/adapters/*.rs` | Update `IsolateHost` match arms | +5/adapter |
| 8 | `swarm-guard/src/lib.rs` | No changes | 0 |
| 9 | `swarm-runtime/src/lib.rs` | Fix struct literals in tests | +10 |

**Total**: ~215 production lines + ~80 test updates.

**Order**: (1) Land types (steps 1-4, compile independently) -> (2) Fix
match sites (steps 5, 7; compiler-guided) -> (3) Extend context/audit
(steps 6, 9; struct-literal errors guide you) -> (4) Partition-mode gate
impl is follow-on work, not this diff.

---

## Consequences

### Positive

- Every doc-11 concept has a named Rust type.
- `IsolationMode::Soft` makes degraded execution auditable at the type level.
- `ContingencyLease` is structurally incompatible with `CapabilityLease`.
- All new fields use `Option` or `#[serde(default)]`; existing payloads valid.
- Guard pipeline: zero changes.

### Negative

- `IsolateHost` struct-literal sites must add `isolation_mode` (~5 prod, ~8 test).
- `ApprovalContext` sites must add `partitioned: false` (~6 sites).
- `PolicyVerdict` match arms get compiler errors from `AllowContingency` (~4 sites).
- ~20 lines of duplicated expiry-check logic across lease types.

## Follow-On Work

- Implement `PartitionModeGate` (`ApprovalGate` decorator).
- Wire `ContingencyLeaseStore` into `PounceAgent` state.
- Implement escalation tier state machine.
- Add partition-mode integration tests for the full doc-11 matrix.
- Define Tom-agent lease issuance protocol (spine envelope signing).
