---
phase: 118-operational-hardening
verified: 2026-04-07T23:59:00Z
status: passed
score: 7/7 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 4/7
  gaps_closed:
    - "Dead-letter journals in production dispatch and notification paths receive max_dead_letter_bytes from RuntimeSettings, not None"
    - "The runtime can cycle through at least one secret rotation and one dead-letter rotation in integration conditions without losing in-flight deposits or notification records"
  gaps_remaining: []
  regressions: []
---

# Phase 118: Operational Hardening Verification Report

**Phase Goal:** Secret-dir changes are detected and applied independently of config reload, and dead-letter journals rotate by size instead of growing without bound
**Verified:** 2026-04-07T23:59:00Z
**Status:** passed
**Re-verification:** Yes -- after gap closure (plan 118-03)

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | When a secret file changes in secret_dir, only @secret: references are re-resolved without triggering a full config reload | VERIFIED | `reload_secrets_only()` on IngestState (ingest.rs:258) uses stored config template via ArcSwap, calls `resolve_outbound_secrets()`, avoids YAML re-read. `continue` at swarm_detect.rs:235 skips `reload_from_disk()`. |
| 2 | Active response adapter configs receive the updated secret values after a secret-dir change | VERIFIED | Unit test `reload_secrets_only_updates_auth_token` (ingest.rs:1805) and integration test `secret_rotation_and_dead_letter_rotation_cycle_without_data_loss` (operational_hardening_integration.rs:104) both verify auth_token transitions from initial to rotated value. |
| 3 | A full config reload is NOT triggered by a secret file change | VERIFIED | Unit test `reload_secrets_only_does_not_read_config_yaml` (ingest.rs:1882) uses nonexistent config YAML path; reload_secrets_only succeeds proving no YAML file read occurs. `continue` in swarm_detect.rs:235 prevents fallthrough to reload_from_disk(). |
| 4 | Dead-letter journals rotate when the file exceeds max_dead_letter_bytes in production dispatch/notification paths | VERIFIED | `DispatchingExecutor::from_config` accepts `max_dead_letter_bytes` (dispatch.rs:25) and passes it to `DeadLetterJournal::new` (dispatch.rs:30, 49). `NotificationRouter::new` accepts `max_dead_letter_bytes` (notification.rs:93) and passes it to `DeadLetterJournal::from_path` (notification.rs:100). `ConfiguredRuntimeStack::from_config` threads `config.runtime.max_dead_letter_bytes` (service.rs:1363). `RuntimeService::new` threads it to `NotificationRouter::new` (service.rs:482). No TODO comments remain. |
| 5 | The rotated file is renamed with a timestamp suffix | VERIFIED | `rotate_if_needed()` creates `{path}.{timestamp_ms}` format (dead_letter.rs:77+). Integration test verifies rotated files match `rotation-test.jsonl.*` pattern (operational_hardening_integration.rs:197-199). |
| 6 | max_dead_letter_bytes is configurable in RuntimeSettings | VERIFIED | Field exists at swarm-core/src/config.rs:97 with `#[serde(default)]` for backward-compatible YAML deserialization. |
| 7 | The runtime can cycle through secret rotation and dead-letter rotation in integration conditions without data loss | VERIFIED | Integration test `secret_rotation_and_dead_letter_rotation_cycle_without_data_loss` (operational_hardening_integration.rs:104-286) exercises both paths: writes secret, calls `reload_secrets_only()`, verifies rotated token, writes entries exceeding `max_dead_letter_bytes`, verifies rotation triggered, confirms `total_preserved == total_written` across all rotated + active files, and confirms secret still holds rotated value after both rotation cycles. Test passes. |

**Score:** 7/7 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/swarm-runtime/src/ingest.rs` | `reload_secrets_only()` method on IngestState | VERIFIED | Line 258, uses config_template ArcSwap, calls resolve_outbound_secrets |
| `crates/swarm-runtime/src/ingest.rs` | `current_response_adapter_config()` accessor | VERIFIED | Line 348, added in plan 03 for integration test access |
| `crates/swarm-runtime/src/config.rs` | `resolve_outbound_secrets` as public function | VERIFIED | Line 365, `pub fn resolve_outbound_secrets` |
| `crates/swarm-runtime/src/config.rs` | `load_config_unresolved()` function | VERIFIED | Exists for full reload path |
| `crates/swarm-runtime/src/bin/swarm_detect.rs` | SecretChange trigger calls reload_secrets_only with continue | VERIFIED | Line 218 calls method, line 235 continues to skip full reload |
| `crates/swarm-core/src/config.rs` | `max_dead_letter_bytes` field on RuntimeSettings | VERIFIED | Line 97, `pub max_dead_letter_bytes: Option<u64>` with serde default |
| `crates/swarm-response/src/dead_letter.rs` | `rotate_if_needed` method and size-based rotation logic | VERIFIED | Line 77, called from `write()` at line 41 |
| `crates/swarm-response/src/dispatch.rs` | `DispatchingExecutor::from_config` accepts and threads max_dead_letter_bytes | VERIFIED | Line 23-26 signature, lines 30 and 49 thread to DeadLetterJournal::new |
| `crates/swarm-response/src/notification.rs` | `NotificationRouter::new` accepts and threads max_dead_letter_bytes | VERIFIED | Line 93 signature, line 100 threads to DeadLetterJournal::from_path |
| `crates/swarm-runtime/src/service.rs` | ConfiguredRuntimeStack::from_config threads max_dead_letter_bytes | VERIFIED | Line 1363, passes `config.runtime.max_dead_letter_bytes` to DispatchingExecutor |
| `crates/swarm-runtime/src/service.rs` | RuntimeService::new threads max_dead_letter_bytes to NotificationRouter | VERIFIED | Line 482, passes `config.runtime.max_dead_letter_bytes` to NotificationRouter::new |
| `crates/swarm-runtime/tests/operational_hardening_integration.rs` | Integration test exercising both rotation paths | VERIFIED | 286-line test file, covers secret rotation, dead-letter rotation, combined proof, cleanup |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| swarm_detect.rs | ingest.rs | `state.reload_secrets_only()` on SecretChange | WIRED | Line 218 calls method, line 235 continues to skip full reload |
| ingest.rs | config.rs | `resolve_outbound_secrets` call | WIRED | Line 261 in reload_secrets_only() calls resolve_outbound_secrets with stored template |
| dead_letter.rs write() | dead_letter.rs rotate_if_needed() | `self.rotate_if_needed()` before append | WIRED | Line 41 calls rotate_if_needed before file open/append |
| service.rs ConfiguredRuntimeStack::from_config | dispatch.rs DispatchingExecutor::from_config | `config.runtime.max_dead_letter_bytes` passed as second arg | WIRED | service.rs:1361-1364 passes the value; dispatch.rs:23-26 receives it |
| service.rs RuntimeService::new | notification.rs NotificationRouter::new | `config.runtime.max_dead_letter_bytes` passed as third arg | WIRED | service.rs:479-482 passes the value; notification.rs:90-93 receives it |
| dispatch.rs from_config | dead_letter.rs DeadLetterJournal::new | `max_dead_letter_bytes` instead of None | WIRED | dispatch.rs:30 and 49 pass the parameter (not None) |
| notification.rs new | dead_letter.rs DeadLetterJournal::from_path | `max_dead_letter_bytes` instead of None | WIRED | notification.rs:100 passes the parameter (not None) |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| HARDEN-08 | 118-01-PLAN.md, 118-03-PLAN.md | SwarmSecretProvider file-watch monitors secret_dir independently; re-resolves @secret: refs without full config reload | SATISFIED | reload_secrets_only() path fully implemented, tested with 3 unit tests and 1 integration test, wired in swarm_detect binary via SecretChange trigger |
| HARDEN-09 | 118-02-PLAN.md, 118-03-PLAN.md | Dead-letter journals implement size-based rotation when exceeding max_dead_letter_bytes | SATISFIED | Rotation mechanism complete and tested. RuntimeSettings field exists. Production wiring threads max_dead_letter_bytes through ConfiguredRuntimeStack and RuntimeService to both DispatchingExecutor and NotificationRouter. No TODO comments remain. Integration test proves rotation without data loss. |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none) | - | - | - | All TODO comments for max_dead_letter_bytes threading removed. No placeholders, stubs, or anti-patterns found in modified files. |

### Human Verification Required

### 1. Secret Hot-Rotation Under Load

**Test:** Start `swarm_detect --serve`, write a secret file change while events are being processed, observe that adapter configs update without service disruption.
**Expected:** In-flight events continue processing, new events use rotated secret value, no config reload logged.
**Why human:** Requires live runtime with file-watch and concurrent event processing to validate no race conditions.

### 2. Dead-Letter Rotation Under Sustained Failure

**Test:** Configure max_dead_letter_bytes to a small value (e.g. 500) in YAML, point the EDR adapter at an unreachable endpoint, and send enough events to trigger multiple rotation cycles.
**Expected:** Rotated files accumulate with timestamp suffixes, active journal stays bounded, no entries lost.
**Why human:** Requires live runtime with sustained failure conditions to validate rotation behavior under production-like load.

### Gaps Summary

No gaps remain. Both gaps from the initial verification have been closed:

1. **Production wiring (previously PARTIAL):** `max_dead_letter_bytes` is now threaded from `RuntimeSettings` through `ConfiguredRuntimeStack::from_config` and `RuntimeService::new` to both `DispatchingExecutor::from_config` and `NotificationRouter::new`. All TODO comments removed. Production dead-letter journals will rotate when the configured threshold is exceeded.

2. **Integration test (previously FAILED):** The `secret_rotation_and_dead_letter_rotation_cycle_without_data_loss` integration test exercises both rotation paths in a single test, proving no data loss occurs. Test passes reliably.

All 7 observable truths verified. Clippy clean. No regressions in previously-passed items.

---

_Verified: 2026-04-07T23:59:00Z_
_Verifier: Claude (gsd-verifier)_
