# Phase 287 Plan 01 Summary

Fuzz, Loom, And Supply-Chain Hardening (v1.79). The FINAL phase of the v1.79 Assurance Foundation —
with it, phases 284–287 are complete. Where 285 made fail-closed auditable and 286 made
receipt-before-action a real engine guarantee, 287 gives the untrusted telemetry-parse boundary and
the concurrent write paths executable adversarial coverage and brings dependency policy to a dated,
deny-by-default shape. Executed 2026-09-08 with subagent-driven-development as **three independent
parallel tracks** (supply / fuzz / loom), each task-reviewed, cherry-picked onto `feat/assurance-287`.
Grounded in codex's read-only `287-CODEX-PREP.md`, re-verified per task.

## Delivered

- **Supply-chain (SUPPLY-01, SUPPLY-02; ea852a9b3):** all 22 `deny.toml` `[advisories].ignore` +
  version-skip entries carry a `last-checked` date, a blast-radius note, and a clearing condition in
  a companion `tools/supply-chain-review.toml` — the only schema-compatible carrier, since cargo-deny
  0.19.4 hard-rejects any extra key inside an ignore entry. `tools/check-supply-chain.sh` TOML-parses
  both, fails on any missing/malformed field, duplicate advisory ID, or drift, and DERIVES the `cargo
  audit --ignore` argv from the validated entries so the two cannot drift (add/remove an advisory ⇒
  exactly one argv change). Non-vacuous (planted counterexamples caught on the real tree); wired into
  CI with pinned tool versions. The stale rationales codex named (rustls-pemfile, webpki-roots,
  instant, the skip count) were re-verified against Cargo.toml and corrected.
- **Fuzz (FUZZ-01..04; fd9b46946):** a `fuzz/` cargo-fuzz workspace — its own nightly-pinned
  workspace, excluded from the root so the pinned stable 1.97.1 and the shipped graph are untouched.
  Four targets call the REAL decoders (`JsonRecordSource::from_str`, `parse_prometheus_text_for_fuzz`
  wrapping the real private parser, `GetEventsResponse::decode`+`map_process_exec`,
  `parse_config_unresolved` — the file-I/O-free config path, no secret resolution during fuzzing).
  `tools/seed-fuzz-corpus.sh` (+ a `corpus-seed` binary) CONVERTS `scenarios/*.yaml` + `rulesets/*.yaml`
  into each target's real wire format (JSON body, prost protobuf, synthetic Prometheus text, verbatim
  YAML). `fuzz-nightly.yml` runs each target 600s and uploads crashing input; `ci.yml` runs a bounded
  30s smoke per target. The two production changes are pure, behaviour-preserving fuzz seams (a
  one-line wrapper + a private→pub visibility change) — the visibility + layering gates pass.
- **Loom + the pheromone race repair (LOOM-01..04; 5a0791ecc):** `loom_concurrent_write` (pheromone
  deposit/decay) and `loom_concurrent_decision` (policy generation-vs-reload + last-slot) are
  `bounded_abstract_model`s (preemption bound 2, `max_permutations`/`max_duration` unset), with `loom`
  a `cfg(loom)`-gated dev-dependency that never enters the shipped graph. `loom-nightly.yml` runs both
  under `RUSTFLAGS="--cfg loom"` (the pheromone harness with `--no-default-features`, since tokio's
  `net` is `cfg(not(loom))`); MAPPING.md labels each harness `scope = "bounded_abstract_model"`. This
  track ALSO REPAIRED a real preexisting split-persistence race in `swarm-pheromone/src/substrate.rs`:
  `deposit` now holds the deposits write-lock across BOTH the journal append and the in-memory push,
  so a concurrent `gc_evaporated` rewrite (which holds the same lock) can never drop a fresh entry —
  proven by a non-Loom concurrent-reopen regression that fails when the fix is reverted.

## Success criteria (mirror ROADMAP)

1. **4 fuzz targets on real entry points, seeded, 30s PR smoke + 600s nightly crash-upload** — met:
   fd9b46946.
2. **Loom harnesses (pheromone + policy) nightly, documented preemption budget, labeled
   bounded_abstract_model** — met: 5a0791ecc (+ the real pheromone race repair).
3. **Every deny.toml ignore dated/blast-radius/clearing, enforced by the gate** — met: ea852a9b3.
4. **cargo audit --ignore deduped against deny.toml so the two cannot drift** — met: ea852a9b3.

## Notes

- **The one production change beyond the fuzz seams is the pheromone persistence-ordering repair** —
  scoped, contract-preserving, falsifiable; independently backstop-verified by the controller (loom
  models pass; the real-substrate concurrent-reopen regression passes and fails on revert).
- **Follow-up (out of scope this phase):** the same split-persistence pattern exists in
  `store_threat_intel_entry`/`gc_expired_threat_intel`; those journals are append-only so it is not
  an active bug, but it is a candidate for a future hardening pass.
- **Environment note:** `cargo fuzz run` deadlocks on this macOS host inside the ASan runtime's own
  init (confirmed via `sample`, unrelated to the code); the committed CI runs default ASan on
  ubuntu-latest, unaffected. Loom's pheromone harness requires `--no-default-features` to build under
  `--cfg loom` (the nats/async-nats → tokio-websockets path uses `tokio::net`, gated `not(loom)`).
- **v1.79 Assurance Foundation COMPLETE** with this phase: 284 (fixture determinism), 285 (assumption
  registry + invariant map), 286 (deterministic simulation + the durable dispatch-intent journal),
  287 (fuzz, loom, supply-chain). Next per the gameplan: the open-agent-protocol and provenance
  (296–299) items need the user's design input; the next unblocked numbered work is v1.81 (292–294).
