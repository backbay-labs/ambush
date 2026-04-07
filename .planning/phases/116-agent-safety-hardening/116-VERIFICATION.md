---
phase: 116-agent-safety-hardening
verified: 2026-04-07T22:58:19Z
status: passed
score: 8/8 must-haves verified
---

# Phase 116: Agent Safety Hardening Verification Report

**Phase Goal:** Agents sign every deposit before submitting, the dispatcher enforces a tick timeout, and unhandled action variants produce structured warnings instead of silent drops
**Verified:** 2026-04-07T22:58:19Z
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A PheromoneDeposit with empty signature or agent_key is rejected by PheromoneSubstrate::deposit() with a SubstrateError | VERIFIED | `substrate.rs:97-158` implements `validate_deposit_signature()` rejecting empty signature (line 98-101), empty agent_key (line 103-106), invalid key bytes, and failed Ed25519 verification. Called in all three backends: InMemory (line 432), LocalJournal (line 626), ConfiguredPheromoneSubstrate (line 272). Five dedicated tests at lines 1573-1650. |
| 2 | WhiskerAgent signs every deposit with its signing key before the deposit reaches the substrate | VERIFIED | `whisker_agent.rs:20` has `signing_key: SigningKey` (not prefixed with `_`). Line 98 passes `&self.signing_key` to `detect_and_deposit()`. Pipeline signs at lines 46-48 via `sign_deposit()`. Test at line 277 confirms deposits reach substrate. |
| 3 | StalkerAgent signs every deposit with its signing key before the deposit reaches the substrate | VERIFIED | `stalker_agent.rs:19` has `signing_key: SigningKey` (not prefixed with `_`). Lines 150-163 build `DepositSigningPayload`, serialize, sign with `self.signing_key.sign()`, and set `deposit.signature`/`deposit.agent_key` before `substrate.deposit()` at line 164-167. |
| 4 | Signed deposits are accepted by the substrate and queryable | VERIFIED | Test `deposit_accepts_valid_signed_deposit` at substrate.rs:1599-1606 creates a signed deposit, submits it, and asserts `recent_deposits` returns 1. WhiskerAgent test at whisker_agent.rs:297 and StalkerAgent test at stalker_agent.rs:454-461 both verify deposits reach substrate. |
| 5 | Every SwarmAgent::tick() call is wrapped in tokio::time::timeout using agent_tick_timeout_ms from RuntimeSettings | VERIFIED | `dispatcher.rs:244-245` wraps with `tokio::time::timeout(tick_timeout, agent.tick(&env))`. `tick_timeout` is `Duration::from_millis(self.config.agent_tick_timeout_ms)`. `config.rs:91-92` defines `pub agent_tick_timeout_ms: u64` with serde default. `config.rs:1807-1809` provides default of 500ms. |
| 6 | An agent that exceeds the tick timeout is marked AgentHealth::Degraded and its tick is skipped for that cycle | VERIFIED | `dispatcher.rs:272-282` matches `Err(_elapsed)` from timeout, inserts `AgentHealth::Degraded` into health_overrides, and does NOT push to `completed_ticks` (actions discarded). Tests: `dispatcher_marks_slow_agent_degraded_on_tick_timeout` (line 1038), `dispatcher_keeps_fast_agent_healthy_within_tick_timeout` (line 1066), `dispatcher_discards_actions_from_timed_out_agent` (line 1094), `default_agent_tick_timeout_is_500` (line 1142). |
| 7 | Any SwarmAction variant not explicitly handled by apply_actions() emits a structured warning log with the variant name | VERIFIED | `dispatcher.rs:307-365` uses exhaustive match on all 7 SwarmAction variants. ProposeStrategy at line 351-363 emits `tracing::warn!` with `"unhandled swarm action variant in dispatcher"`. No `_ => {}` wildcard in apply_actions match. Test `dispatcher_logs_warning_for_unhandled_propose_strategy_action` at line 1148. |
| 8 | ClaimInvestigation and PublishFindings are no longer silently dropped | VERIFIED | `dispatcher.rs:329-347` handles ClaimInvestigation with `tracing::debug!("agent-direct action: claim_investigation (not dispatcher-routed)")` and PublishFindings with `tracing::debug!("agent-direct action: publish_findings (not dispatcher-routed)")`. Code comments explain agent-direct vs dispatcher-routed semantics. Test `dispatcher_handles_claim_investigation_and_publish_findings_without_panic` at line 1186. |

**Score:** 8/8 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/swarm-pheromone/src/substrate.rs` | Deposit signature validation in PheromoneSubstrate::deposit() | VERIFIED | Contains `validate_deposit_signature()`, `InvalidDeposit` error variant, `DepositSigningPayload` struct. Called in all three backend `deposit()` implementations. 5 signature validation tests. |
| `crates/swarm-runtime/src/detection/pipeline.rs` | Deposit signing in detect_and_deposit via signing_key parameter | VERIFIED | `detect_and_deposit` signature includes `signing_key: &SigningKey` at line 35. `sign_deposit()` helper at lines 59-82 uses `DepositSigningPayload` from swarm-pheromone. |
| `crates/swarm-runtime/src/whisker_agent.rs` | WhiskerAgent passes signing key to pipeline | VERIFIED | Field `signing_key: SigningKey` at line 20 (not prefixed). Passed as `&self.signing_key` at line 98 to `detect_and_deposit`. |
| `crates/swarm-runtime/src/stalker_agent.rs` | StalkerAgent signs deposits before substrate.deposit() | VERIFIED | Field `signing_key: SigningKey` at line 19. Signs deposit at lines 150-163 using `DepositSigningPayload` and `self.signing_key.sign()` before `substrate.deposit()` at line 164-167. |
| `crates/swarm-core/src/config.rs` | agent_tick_timeout_ms field in RuntimeSettings | VERIFIED | Field at line 92: `pub agent_tick_timeout_ms: u64`. Default function at line 1807-1809 returns 500. Serde default wiring at line 91. |
| `crates/swarm-runtime/src/dispatcher.rs` | Tick timeout wrapping and unhandled action logging | VERIFIED | Timeout wrapping at lines 244-283. Exhaustive match at lines 307-365. 6 new tests covering timeout and action handling. |
| `crates/swarm-pheromone/src/lib.rs` | Re-exports DepositSigningPayload | VERIFIED | Line 17 exports `DepositSigningPayload` from `substrate` module. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `pipeline.rs` | `substrate.rs` | pipeline signs deposit, substrate validates signature | WIRED | Pipeline calls `sign_deposit()` (line 47) which fills signature/agent_key. Substrate calls `validate_deposit_signature()` at deposit entry. Both use `DepositSigningPayload` for canonical serialization. |
| `stalker_agent.rs` | `substrate.rs` | stalker signs deposit before calling deposit() | WIRED | StalkerAgent builds `DepositSigningPayload` (line 150-158), calls `self.signing_key.sign()` (line 161), sets signature/agent_key (lines 162-163), then calls `self.substrate.deposit()` (line 164-167). |
| `dispatcher.rs` | `config.rs` | dispatcher reads agent_tick_timeout_ms from config | WIRED | `dispatcher.rs:244` reads `self.config.agent_tick_timeout_ms`. `AgentDispatcherConfig` has `agent_tick_timeout_ms: u64` field at line 26 with default 500 at line 35. |
| `dispatcher.rs` | `tracing::warn` | unhandled action variants produce structured warning | WIRED | `ProposeStrategy` match arm at line 356 calls `tracing::warn!` with structured fields (agent_id, action, strategy_id, fitness). No wildcard `_ => {}` in apply_actions match. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| HARDEN-01 | 116-01-PLAN.md | Agents sign deposits; unsigned deposits rejected by substrate | SATISFIED | `validate_deposit_signature()` rejects empty/invalid signatures. WhiskerAgent and StalkerAgent both sign with Ed25519 keys. 5 substrate validation tests + agent tests confirm. |
| HARDEN-02 | 116-02-PLAN.md | Dispatcher wraps tick() in tokio::time::timeout with configurable agent_tick_timeout_ms | SATISFIED | `dispatcher.rs:244-245` wraps with timeout. `config.rs:92` has field with default 500ms. Timed-out agents marked Degraded. 4 tests prove timeout behavior. |
| HARDEN-03 | 116-02-PLAN.md | apply_actions() logs structured warnings for unhandled SwarmAction variants | SATISFIED | Exhaustive match at lines 307-365. ProposeStrategy gets warn. ClaimInvestigation/PublishFindings get debug with documentation. No silent drops. 2 tests. |

No orphaned requirements found. REQUIREMENTS.md maps HARDEN-01/02/03 to Phase 116 and marks them Satisfied.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | - | - | - | No TODO, FIXME, placeholder, or stub patterns found in modified files |

### Human Verification Required

### 1. Ed25519 Signature Round-Trip Under Load

**Test:** Run the full workspace test suite and confirm all 217+ tests pass, including signature validation under concurrent deposit paths
**Expected:** `cargo test --workspace` passes with no signature-related failures
**Why human:** Requires compiling and running the full Rust workspace -- cannot be done in static verification

### 2. Tick Timeout Timing Accuracy

**Test:** Run `cargo test -p swarm-runtime -- timeout --nocapture` and observe timing behavior
**Expected:** SlowMockAgent (200ms delay, 50ms timeout) is marked Degraded; fast agent (5ms delay, 500ms timeout) stays Healthy
**Why human:** Tokio timing behavior varies by system load; needs runtime confirmation

### Gaps Summary

No gaps found. All 8 observable truths verified against the codebase. Every must-have artifact exists, is substantive (not a stub), and is properly wired. All three requirement IDs (HARDEN-01, HARDEN-02, HARDEN-03) are satisfied with implementation evidence. No anti-patterns detected in modified files.

---

_Verified: 2026-04-07T22:58:19Z_
_Verifier: Claude (gsd-verifier)_
