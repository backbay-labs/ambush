# Phase 286 recovery — findings 2 and 3 fix report

Branch: `codex/dst-286-recovery` (based on `4790bf2af`).
Scope: exactly two confirmed findings against codex's phase-286 "dispatch
journal" repair. Nothing else refactored. Every prior guarantee and passing
test preserved.

---

## FIX 1 — a transient read error must not permanently poison the dispatch journal

### File
`crates/swarm-runtime/src/dispatch_journal.rs`, `fn append` (~L452).

### The defect
`append` ran the pre-write integrity check and the write in one `and_then`
chain and poisoned the writer on *any* error from the combined result:

```rust
let result = self.validate_files(state).and_then(|()| { write_all + sync_all + write_checkpoint });
if let Err(error) = result { state.poisoned = true; return Err(error); }
```

`validate_files` re-opens and re-reads the journal file before the write. That
read can fail with a **transient I/O error** (`File::open` / `read` mapped to
`DispatchJournalError::Io` via `io_error(...)`) — a failure to *complete the
check*, not proof of corruption, with **nothing written**. Poisoning there set
`state.poisoned = true` permanently, so every subsequent `lock()` returned
`DispatchJournalError::Poisoned` and all live dispatch was bricked until process
restart.

### The fix
Split the pre-write validation from the write, and poison only on genuine
durability/integrity uncertainty:

```rust
if let Err(error) = self.validate_files(state) {
    if !matches!(error, DispatchJournalError::Io { .. }) {
        state.poisoned = true;
    }
    return Err(error);
}
// past validation, bytes may reach disk — any failure here still poisons
let result = (|| { write_all + sync_all + write_checkpoint })();
if let Err(error) = result { state.poisoned = true; return Err(error); }
```

Discriminator: `validate_files` can only yield `Io` (transient read/metadata
failure) or `Corrupt` (proven in-place corruption / tamper — hash, length,
inode, or writer-identity mismatch). The fix refuses **without poisoning only
for the transient `Io` variant**; every other outcome — `Corrupt`, and any
future non-`Io` variant — still poisons (the safe, fail-closed default), and the
entire write/`sync_all`/`write_checkpoint` step still poisons on any error,
exactly as before.

Why it preserves every guarantee:
- `validate_files` itself, its full-file re-read, and the in-place-corruption
  check are **untouched**.
- `Corrupt` from `validate_files` still poisons → `in_place_corruption_blocks_the_next_live_reservation` still passes (Corrupt, then Poisoned).
- The write/sync/checkpoint poison path is unchanged → `write_failure_poisoning_prevents_followup_permission` still passes (that test swaps in a read-only descriptor: `validate_files` succeeds, the write fails → poison).
- Fail-closed is preserved: a transient read failure still **refuses this
  dispatch** (returns the `Io` error); it just does not brick future ones.

### New test
`dispatch_journal_tests.rs::transient_read_error_during_validate_refuses_without_poisoning`
(`#[cfg(unix)]`, deterministic, hermetic). With a prior reservation on disk it
`chmod 0o000`s the journal file so the fresh `File::open` inside `validate_files`
fails with `EACCES` while every metadata check still sees the correct length and
inode (the already-open append descriptor is unaffected, and no durable byte
changes). It asserts: the reservation is refused with `DispatchJournalError::Io`;
`state.poisoned` is still `false`; then, after restoring permissions, the next
reservation **succeeds**, `lookup_persisted` shows `OutcomeUnknown`, the original
permission still refuses re-reservation with `AlreadyReserved`, and the journal
holds exactly three durable lines (header + two intents — no torn write). A root
process, which ignores the permission bits, is detected and the scenario is
skipped rather than false-failing.

---

## FIX 2 — retry-disabling over-reached into SIEM telemetry forwarding

### Files
`crates/swarm-response/src/resilience.rs` (shared `ResilientExecutor`),
`crates/swarm-response/src/siem.rs` (the two SIEM forwarders).

### The defect
Codex deleted the retry loop from the **shared** `ResilientExecutor::execute`.
That is correct for the three effectful dispatch adapters (`HttpEdr`,
`CrowdStrikeRtr`, `Webhook` in `dispatch.rs`) — a response effect may already
have happened — but wrong for the SIEM forwarders (`ResilientExecutor<SplunkHecAdapter>`
and `Generic(ResilientExecutor<SiemForwardAdapter>)` in `siem.rs`), which are
duplicate-safe telemetry that legitimately wants transient-failure retries.

### The fix
Restore the retry machinery from `main` (`5ad9b6850`) but gate it per executor:

- Restored fields `retry: RetryConfig` and helper methods `backoff_for_retry`,
  `receipt_is_retryable`, `error_is_retryable` (verbatim from `main`).
- Added `retries_enabled: bool` on `ResilientExecutor`.
- `ResilientExecutor::new(...)` → retries **disabled** (unchanged 5-arg
  signature, so all existing callers keep the no-double-dispatch guarantee by
  default). Added `ResilientExecutor::with_retries(...)` → retries **enabled**.
  Both delegate to a private `build(...)`.
- `execute`:
  - `retries_enabled == false`: invokes `self.inner.execute(...)` **exactly
    once** — byte-for-byte codex's current behavior (circuit check, then a single
    invocation, dead-letter with `attempts = 1`, outcome returned unchanged).
  - `retries_enabled == true`: the restored `for attempt in 0..total_attempts`
    loop with backoff/sleep and dead-letter on exhaustion.
- Wiring: `dispatch.rs`'s three constructors are **unchanged** (`new` → retries
  disabled). `siem.rs`'s two constructors switched to `with_retries` (retries
  enabled, with their real `RetryConfig`).
- `reqwest::retry::never()` on all four effectful-adapter HTTP client builders
  (`http_edr.rs`, `crowdstrike_rtr.rs`, `webhook.rs`) left **untouched** —
  controlled retries flow only through the executor loop, and only when enabled.

Why it preserves the no-double-dispatch guarantee: the effectful adapters still
construct via `new`, whose disabled path invokes the inner adapter at most once
and never retries an ambiguous outcome. `dispatch_integration`, the DST harness,
`negative_runtime_dispatch`, and the existing `enforced_ambiguous_outcomes_do_not_repeat_effects`
/ `http_effect_then_*` tests all still pass.

### Tests
- `resilience.rs::with_retries_retries_transient_failure_then_succeeds` — a
  transient `Timeout` under `with_retries` is retried and the second invocation
  succeeds (inner invoked twice, by design). Restored-behavior evidence.
- `resilience.rs::with_retries_exhausts_attempts_then_dead_letters` — `503`
  every attempt: 4 invocations (`max_retries = 3`), one dead-letter with
  `attempts = 4`.
- `resilience.rs::disabled_new_invokes_inner_exactly_once_on_transient_failure`
  — under `new`, a retryable `Timeout` returns unchanged with the inner invoked
  **exactly once** (the effectful guarantee at the executor level).
- `siem.rs::forwarder_retries_transient_siem_failure_until_it_succeeds` — a
  `SiemFindingForwarder` (ElkBulk → Generic path) against a flaky endpoint (503
  then 200) reaches `Executed` with the finding delivered exactly twice
  (wiring evidence: SIEM forwarders use `with_retries`).

---

## Verification (scoped, `-j2`, foreground, `--test-threads=1`)

- `cargo test -p swarm-runtime --lib` → **585 passed; 0 failed**. Includes the
  new `transient_read_error_during_validate_refuses_without_poisoning` and, still
  green: `in_place_corruption_blocks_the_next_live_reservation`,
  `write_failure_poisoning_prevents_followup_permission`,
  `concurrent_reservation_has_one_winner`,
  `completed_success_and_failure_never_reauthorize`,
  `entry_capacity_refuses_new_permission_without_evicting_durable_history`,
  `byte_capacity_refuses_intent_and_completion_without_erasing_unknown_outcome`,
  `created_storage_is_private_without_relying_on_umask`,
  `reservation_is_on_disk_before_return_and_remains_unknown_after_restart`.
- `cargo test -p swarm-response` → **75 lib passed; 0 failed**, plus the response
  negative integration tests. Includes the four new FIX 2 tests and the
  unchanged `enforced_ambiguous_outcomes_do_not_repeat_effects`,
  `http_effect_then_server_failure_is_not_retried`,
  `http_effect_then_timeout_is_not_retried`,
  `circuit_blocks_calls_until_cooldown_and_success_resets_failures`,
  `dry_run_still_bypasses_circuit_without_retries_or_failure_accounting`.
- `cargo test -p swarm-runtime --test dispatch_integration --test dst_fault_injection --test negative_runtime_dispatch`
  → dispatch_integration **21 passed**; dst_fault_injection **4 passed, 1 ignored**
  (nightly deep corpus); negative_runtime_dispatch **2 passed**. No-double-dispatch intact.
- `cargo fmt --all --check` → clean.
- `cargo clippy -p swarm-runtime -p swarm-response --all-targets -- -D warnings`
  → Finished, no warnings.
- `tools/check-mapping.sh` (0; 17 rows / 17 markers),
  `tools/check-negative-registry.sh` (0),
  `tools/check-workspace-layering.sh` (0),
  `tools/check-runtime-panic-contract.sh` (0; 0 live unwrap/expect sites) — all exit 0.

## Assurance-artifact impact
None required. No new invariant marker, MAPPING row, or negative-registry entry:
the dispatch-once / no-double-dispatch invariants are unchanged, and no new
`// INVARIANT:` marker was added. `RuntimeDispatchIdentityConsumedOnce`
(`DispatchJournal::reserve`, `:285`) is untouched and its line number is
unaffected (all edits are below it).

## Constraints honored
Edition 2024; fail-closed preserved everywhere; no new non-dev dependency
(`tokio` is already a normal dep of `swarm-response`, `tokio` "full" features);
`unwrap`/`expect` only in `cfg(test)` code (panic-contract scanner: 0 live
sites).
