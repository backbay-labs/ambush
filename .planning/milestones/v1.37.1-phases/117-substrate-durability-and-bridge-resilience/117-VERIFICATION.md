---
phase: 117-substrate-durability-and-bridge-resilience
verified: 2026-04-07T23:25:34Z
status: passed
score: 9/9 must-haves verified
re_verification: false
---

# Phase 117: Substrate Durability And Bridge Resilience Verification Report

**Phase Goal:** Threat-intel GC runs on all three backends and rewrites the local-journal file, and the TetragonBridge detects and recovers from silent stream hangs and accepts init-spawned processes
**Verified:** 2026-04-07T23:25:34Z
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | gc_expired_threat_intel() removes entries with expired TTLs from all three backends | VERIFIED | Trait method at substrate.rs:242, InMemory impl at :578, LocalJournal impl at :793, JetStream impl at jetstream.rs:708, Configured dispatch at :400. All three retain/delete expired entries based on `expires_at <= now`. |
| 2 | LocalJournal rewrites the threat-intel journal file during GC so expired entries do not persist on disk | VERIFIED | substrate.rs:800-803 calls `rewrite_jsonl(&self.threat_intel_journal_path, &guard.values().collect::<Vec<_>>())` after retain. Test `local_journal_gc_expired_threat_intel_rewrites_file` (line 1760) reopens substrate from disk and confirms only unexpired entries survive. |
| 3 | InMemory backend removes expired threat-intel entries from the BTreeMap | VERIFIED | substrate.rs:584 `guard.retain(\|_key, entry\| entry.expires_at > now)`. Test `gc_expired_threat_intel_removes_expired_entries` (line 1701) confirms purge count and query results. |
| 4 | JetStream backend deletes expired threat-intel keys from the KV store | VERIFIED | jetstream.rs:708-752 iterates all keys with intel prefix, deserializes each entry, checks `expires_at <= now`, and calls `store.delete(&key)` for expired entries. Non-nats stub at :865 returns unsupported_backend error. |
| 5 | Structured logs report the number of entries purged during threat-intel GC | VERIFIED | `tracing::info!(purged, ...)` at substrate.rs:587, substrate.rs:806, jetstream.rs:747. Debug-level logging for zero-purge at substrate.rs:589, substrate.rs:808, jetstream.rs:749. |
| 6 | TetragonBridge::poll() times out after event_timeout_secs of silence instead of hanging indefinitely | VERIFIED | bridge.rs:188-189 `tokio::time::timeout(timeout_duration, stream.next()).await` with `timeout_duration = Duration::from_secs(self.config.event_timeout_secs)`. Timeout branch at :219-227 drops stream, calls sleep_on_disconnect (which records error), returns Connection error. |
| 7 | A stream timeout increments BridgeHealth error_count and triggers reconnect-backoff | VERIFIED | Timeout branch calls `self.sleep_on_disconnect()` at :225, which calls `self.record_error()` at :126, which calls `guard.record_error()` at :151 to increment health error_count. Backoff computed via `reconnect_backoff()` at :127. |
| 8 | TetragonBridge schema validation accepts ProcessStartEvent with an empty parent_process | VERIFIED | `process_start_schema_valid` at bridge.rs:154-156 only checks `process_name` and `command_line` -- parent_process check removed. Tests `validate_schema_accepts_sentinel_parent_process` (:385) and `validate_schema_accepts_empty_parent_process` (:406) confirm. |
| 9 | When parent_process is empty the bridge stores the sentinel value '<none>' instead of empty string | VERIFIED | mapper.rs:11-16 uses `.filter(\|binary\| !binary.trim().is_empty()).unwrap_or_else(\|\| "<none>".to_string())`. Tests `missing_parent_maps_to_sentinel` (:113) and `empty_binary_parent_maps_to_sentinel` (:136) both assert `== "<none>"`. |

**Score:** 9/9 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/swarm-pheromone/src/substrate.rs` | gc_expired_threat_intel on trait, InMemory, LocalJournal, Configured dispatch | VERIFIED | Contains trait definition (line 242), InMemory impl (578), LocalJournal impl with rewrite_jsonl (793), Configured dispatch (400), 3 test functions (1701, 1743, 1760) |
| `crates/swarm-pheromone/src/jetstream.rs` | gc_expired_threat_intel on JetStream backend | VERIFIED | Contains nats impl (708) with key iteration and deletion, non-nats stub (865) |
| `crates/swarm-ingest-tetragon/src/bridge.rs` | Stream timeout in poll() and relaxed schema validation | VERIFIED | tokio::time::timeout at line 189, relaxed schema validation at 154-156, tests at 385, 406, 427 |
| `crates/swarm-ingest-tetragon/src/mapper.rs` | Sentinel '<none>' for missing parent process | VERIFIED | Sentinel substitution at line 16, tests at 113 and 136 |
| `crates/swarm-core/src/config.rs` | event_timeout_secs field on TetragonBridgeConfig | VERIFIED | Field at line 146, serde default at 145, default function at 1900 (value 30), validation at 711-716 |
| `crates/swarm-runtime/src/bridge_runtime.rs` | event_timeout_secs passed through config mapping | VERIFIED | Field passed at line 317 in tetragon_runtime_config function |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| substrate.rs (trait) | InMemory/LocalJournal/JetStream/Configured | gc_expired_threat_intel method dispatch | WIRED | Trait at :242, all 4 impl blocks present, Configured dispatches to each variant at :400-406 |
| substrate.rs (LocalJournal) | threat-intel journal file | rewrite_jsonl call | WIRED | rewrite_jsonl called at :800-803 with threat_intel_journal_path; test proves disk persistence at :1760 |
| bridge.rs (poll) | tokio::time::timeout | stream.next() wrapped in timeout | WIRED | Line 189 wraps stream.next() in timeout; Err(_elapsed) branch handles timeout at :219 |
| bridge.rs (timeout branch) | BridgeHealth | sleep_on_disconnect -> record_error -> health.record_error | WIRED | Chain: :225 -> :126 -> :151; error_count incremented in health struct |
| mapper.rs | ProcessStartEvent.parent_process | sentinel substitution for empty parent | WIRED | .filter().unwrap_or_else at :15-16 produces "<none>"; used in TelemetryPayload at :33 |
| config.rs | bridge.rs BridgeConfig | event_timeout_secs passthrough | WIRED | TetragonBridgeConfig :146 -> bridge_runtime.rs :317 -> BridgeConfig :22 -> poll() :188 |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| HARDEN-04 | 117-01 | gc_expired_threat_intel on all 3 backends with structured logs | SATISFIED | Truths 1, 3, 4, 5 verified |
| HARDEN-05 | 117-01 | LocalJournal rewrites threat-intel journal during GC | SATISFIED | Truth 2 verified; rewrite_jsonl call at substrate.rs:800-803, test at :1760 reopens from disk |
| HARDEN-06 | 117-02 | TetragonBridge::poll() wraps stream.next() in tokio::time::timeout with configurable event_timeout_secs | SATISFIED | Truths 6, 7 verified; timeout at bridge.rs:189, config at config.rs:146, default 30s |
| HARDEN-07 | 117-02 | Schema validation accepts empty parent_process, stores '<none>' sentinel | SATISFIED | Truths 8, 9 verified; validation at bridge.rs:154-156, sentinel at mapper.rs:16 |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none) | - | - | - | No TODO, FIXME, PLACEHOLDER, HACK, or XXX comments found in any modified file |

### Human Verification Required

None. All behavioral changes are verifiable programmatically through the existing test suite:
- 3 pheromone GC tests pass (including disk rewrite round-trip)
- 15 tetragon tests pass (including sentinel and config default tests)
- Clippy clean on both crates

### Gaps Summary

No gaps found. All 9 observable truths are verified. All 4 requirements (HARDEN-04 through HARDEN-07) are satisfied. All artifacts exist, are substantive, and are properly wired. All commits exist in git history. Both crates pass clippy with -D warnings and all tests pass.

---

_Verified: 2026-04-07T23:25:34Z_
_Verifier: Claude (gsd-verifier)_
