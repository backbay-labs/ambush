# Phase287 read-only continuation preparation

Source: frozen `4790bf2af32cf88665880aef4df1645061aeb43c`. Agent
`next_phase_audit` inspected source without edits or Cargo. Confidence is high
for source findings; runtime reproduction, timing and acceptance remain unverified.
Phase287 depends on accepted286 and has not begun implementation.

Canonical contract: `.planning/REQUIREMENTS.md:860` and
`.planning/ROADMAP.md:1165`. Four targets are `ingest_json_decode`,
`ingest_sentinel_decode`, `ingest_tetragon_decode`, `ruleset_yaml_parse`.
PR smoke is 30 seconds per target; nightly is 600 seconds per target with crash
artifact retention. Use real parser seams and target-format corpus conversion;
raw scenario YAML is not automatically valid input for every decoder. Reuse the
prior audit of public unresolved configuration parsing to avoid environment or
filesystem secret resolution during ruleset fuzzing.

## Loom production boundaries

| Requirement | Exact source seam | Bounded work |
|---|---|---|
| LOOM-01 | `swarm-pheromone/src/substrate.rs:699,866`: in-memory deposit and decay retain hold the same vector write lock | Model deposit, eligible eviction and observation with real decay predicates and fixed time. |
| Local persistence | Same file `:985,1177,1191`: journal append precedes vector lock; GC rewrites disk while holding the vector lock | Reproduce the split-persistence race, repair production ordering and add actual concurrent reopen regression. |
| LOOM-02 | `swarm-policy/src/configurable_gate.rs:13,26`: immutable rule vector rebuilt in a new gate | Model held immutable snapshots and publication. Policy crate itself has no reload operation. |
| Actual reload | `swarm-ingest-runtime/src/ingest/mod.rs:1573`; request routing `:146` | Reload serializes construction and publishes separate ArcSwaps. Assert one held runtime generation per decision/lease; do not claim all composition fields swap atomically. |
| Shared limits | `swarm-policy/src/configurable_gate.rs:85` | Supplemental last-slot test models atomic prune/check/increment under one mutex. |

The preexisting local pheromone race has this source-derived schedule:

1. Deposit appends a fresh entry to disk.
2. GC obtains the still-old in-memory vector lock and rewrites disk without it.
3. Deposit obtains that lock and pushes its fresh entry into memory.
4. Reopen loses the successful fresh deposit.

`substrate.rs` is identical at base `5ad9b6850` and final `4790bf2af`: Git blob
`c4665c12a116c84202f3fa1ce3b28dcd251f952e`. This is not an introduced Phase286
regression. It concerns pheromone evidence durability, separate from the new
DispatchJournal reservation/completion and duplicate-dispatch protocol. No runtime
reproduction was performed in this audit.

Production locks are standard synchronization; putting calls under `loom::model`
does not instrument them. Use explicit Loom state or a reviewed shared seam and
label both MAPPING entries exactly `scope = "bounded_abstract_model"`.
Start with a documented preemption bound of 2, measure the final bounded model,
and leave `max_permutations` and `max_duration` unset: those optional caps can stop
exploration successfully. Keep model size finite and CI timeout a failing bound.
Cached Loom 0.7.2 exists; neither crate currently depends on it. The repository
pins Rust 1.97.1. No Loom harness/workflow currently exists.

## Supply-chain preparation

Source: `deny.toml:8,114`, `tools/check-supply-chain.sh:10`. There are two advisory
ignores and twenty version skips, without individual review dates. The manually
repeated cargo-audit ignore IDs match today but have no enforced derivation.
Validate metadata with a TOML parser before invoking Cargo; derive audit argv from
validated advisory entries. Preserve cargo-deny schema compatibility.

Correct stale rationales before assigning fresh dates:

- rustls-pemfile is a direct project dependency in
  `swarm-runtime-http/Cargo.toml:21`, called from `serve.rs:222,230`.
- webpki-roots 0.26.11 re-exports the locked 1.0.7 roots through its compatibility
  dependency; these are not two independent trust-root snapshots.
- instant is reachable through notify/notify-types and nostr; the latter is owned
  by `swarm-perch-bridge/Cargo.toml:67`. Clearing only notify is insufficient.
- Historical comments count nineteen version skips; twenty are present.

Lockfile presence and cached sources were inspected; the active cargo-deny
feature graph was not executed. Record/pin tool versions for acceptance because
the existing CI gate installs tools without explicit version pins.

## Execution order and falsification

After286 acceptance: create explicit plans, implement supply metadata validation,
implement parser seams/corpus conversions, implement pheromone model plus real
persistence repair/regression, implement policy snapshot model/composition
regressions, then CI and final-tree evidence. Supply work can proceed in parallel
with bounded independent parser work within the accepted phase.

Required controls, each independently restored before a positive rerun:

- Revert journal append/publish ordering: actual fresh successful deposit must
  disappear on reopen and fail the persistence oracle.
- Use snapshot/release/replace eviction: concurrent fresh retention must fail.
- Mix policy generations between decision and lease: generation oracle must fail.
- Split last-slot check/increment: concurrent over-consumption must fail.
- Missing/invalid metadata, duplicate IDs, malformed TOML/date/types: the actual
  supply shell gate must reject before Cargo and identify the offending entry.
- Add/remove a validated advisory: recorded cargo-audit argv gains/loses exactly
  one matching ignore; failing deny/audit stub must propagate nonzero exit.
- Fuzz production parser mutation/crashing input: ordinary target rejects and CI
  preserves the reproducer.

A failing abstract model mutation alone does not prove production-source mutant
sensitivity. Bind real source mutations to actual regression execution where that
claim is required. Hosted workflow execution and required PR enforcement need
separate evidence; YAML presence is insufficient.
