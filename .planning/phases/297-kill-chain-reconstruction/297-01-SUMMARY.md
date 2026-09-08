# Phase 297 Plan 01 Summary

Kill-Chain Reconstruction (v1.82 Provenance Memory And Correlation). The SECOND of four
executable phases of this milestone — turns ephemeral `KillChainSequenceDetector` matches into
durable graph evidence, reconstructs multi-stage kill chains by mapping observed technique/stage
paths onto the declared stage ordering in `sequences/kill-chain-v1.yaml`, joins investigations
that span disjoint hunts along a genuine causal path into one `ReconstructedKillChain` persisted
alongside `IncidentRecord`, and narrates the result stage-by-stage. Executed 2026-09-08 as a
4-task pipeline (T1 durable edges → T2 reconstruction walker → T3 cross-hunt join + persist +
narrate → T4 this close) on branch `feat/chain-297`, commit range `509e06e03..29983b692`.
**v1.82 is NOT complete after this close — Phases 298/299 remain.**

## Delivered

- **Durable kill-chain-stage edges from the sequence detector (CHAIN-02; `b25b40985`):** when a
  `KillChainSequenceDetector` match is observed, `SphinxAgent` writes it into the knowledge graph
  as `SemanticRelation::KillChainStage` semantic edge(s) carrying the rule's stage + technique,
  namespaced by rule id (`:sequence:<rule_id>`), so the ephemeral detection becomes persisted,
  reloadable evidence. The pre-existing attack-technique KillChainStage emission is preserved
  unchanged; a new integration test proves the match produces edges that persist and reload.

- **`chain_reconstruction.rs` — read-only stage-ordering walker (CHAIN-01; `fe51b22bb`, hub-cap
  fix `ddcf7acc2`, anchor-scope fix `dd494e541`):** a new read-only module that, given a
  `KnowledgeGraphSnapshot` + the loaded kill-chain-v1 rules, walks the graph via Phase 296's
  `provenance_paths` and maps observed `AttackTechnique` nodes onto a rule's declared
  `attack_chain`, returning the longest connected prefix (≥2 stages) as a `ReconstructedChain`.
  It does not mutate the graph and owns its own rule loader (no `sequence_detector` visibility
  widening). Two review-driven fixes hardened the stage-connection fallback: it anchors on the
  hub rather than routing through it (`ddcf7acc2`), and the busy-hub fallback is scoped to
  `Engagement` nodes only by node-kind (`dd494e541`), so a globally-merged `ThreatPattern` can
  never bridge mutually-disconnected hunts through the `from`-exemption.

- **Cross-hunt `ReconstructedKillChain` + persistence + `narrate()` (CHAIN-03/04; `522645969`,
  hardened `b5ac84576` + `29983b692`):** `ReconstructedKillChain`/`ReconstructedChainHop` are new
  TCB-safe types in `swarm-spine::incident` (no `swarm-runtime` dependency); `persist_kill_chain`
  / `load_kill_chain_by_id` extend `IncidentStore` across all three backends (Memory, File via a
  `kill_chains/` dir, Configured) without disturbing the existing incident persistence or its
  tests. `join_cross_hunt_kill_chain` emits one `ReconstructedKillChain` per rule when two
  disjoint-hunt incidents are connected by a genuine causal path. `narrate()` produces a
  non-empty stage-by-stage narrative in reconstructed order, asserted stage-order-exact against
  the `outlook_mshta_transfer` and `remote_service_stager` fixtures (CHAIN-04).

## The cross-hunt-bridging security property (GRAPH-03 at the join level) — three iterations

CHAIN-03's SC4 ("two hunts sharing a causal path reconstruct into ONE chain, not two disjoint
incidents") carries a sharp inverse: two **genuinely unrelated** hunts must never be joined. A
globally-shared or co-referenced node must not fabricate a bridge. Three successive adversarial
reviews each found a surviving bridge, and the fix that finally closed the class did so
**structurally**, not by extending an exclusion list:

- Instance 1 — a shared `ThreatPattern` (globally merged by `threat_class`) bridged unrelated
  hunts. Excluded it.
- Instance 2 — a shared `AttackTechnique` (globally merged by `technique_id`) bridged them the
  same way. Excluded it too, and required a genuine `Causal` edge on the connecting path
  (`41d8a1f22`).
- Instance 3 (re-review PoC) — a causal edge entirely **internal to one hunt** (its own
  engagement → its own process) satisfied the flat "path contains *some* causal edge" check while
  the actual cross-hunt hop went through a shared host via non-causal `Entity` edges. Two
  unrelated hunts joined.

**Root cause of all three:** walking the all-edge `provenance_paths` BFS and reasoning *post-hoc*
about the returned path, which is blind to which segment crosses the hunt boundary. **The fix
(`b5ac84576`):** the bridge is now a **`Causal`-only path by construction** —
`KnowledgeGraphSnapshot::causal_provenance_paths` builds the adjacency over the `Causal`-only
subgraph (a single shared BFS core `bounded_paths_where` + `neighbor_index_where(predicate)`; the
all-edge `provenance_paths` and the causal-only variant are the two thin wrappers, so the graph
keeps one traversal implementation). A shared waypoint is now reachable **only if both hunts
genuinely causally interacted with it**; non-causal co-reference cannot appear on the bridge path
at all, so the position-blind class cannot arise regardless of node kind. The classification-node
exclusion is retained (defends a producer attaching causal edges to a globally-merged node); a
fail-closed guard (`29983b692`) refuses the degenerate same-anchor self-bridge. The walk stays
**undirected**, preserving the shared-causal-actor (fork/pivot) correlation signal a directed-only
walk would silently drop. The final adversarial re-review (opus) confirmed across six attack
vectors — including its own PoC — that no unrelated-hunt bridge survives.

## Honest boundaries (disclosed, not resolved by this close)

- **Producer-wiring gap (carried forward from Phase 296).** The cross-hunt join is
  capability-complete and proven by SC4-style tests, but in the real producer `Engagement`
  anchors carry no `Causal` edges yet — Phase 296's raw causal edges pivot on
  `pid`/`process_key`/resolved-IP that no normalized `swarm_core::telemetry` event populates. So
  on production traffic the join is a **fail-closed no-op** (no chains, never a false join) until
  296→297 producer wiring lands. That wiring is **Phase 298's** scope (Cross-Hunt Correlation,
  which migrates live correlation onto graph traversal). Recording this rather than overclaiming a
  production-live join.
- **No production call-site.** `join_cross_hunt_kill_chain` is a library capability; deciding
  *when* the runtime invokes it (resolving `CorrelatedIncident` → anchor) is deliberately left to
  Phase 298, following Phase 296's precedent (`CorrelationEngine::graph_provenance_link` takes
  literal node ids and leaves domain resolution to its caller).
- **Shared common infrastructure touched causally by both sides** (causal degree ≤ the hub cap of
  32) is accepted as a genuine causal relationship by design and bounded by the cap — a tuning
  knob, not a fabrication.

## Verification (final tree, `29983b692`)

- `cargo test -p swarm-runtime --lib chain_reconstruction::` → 20 passed (incl. SC4 positive, the
  shared-`Process` causal-bridge positive, and four negative pins: shared-`ThreatPattern`,
  shared-`AttackTechnique`, shared-`Entity`-without-causal, and the intra-hunt-causal + shared-host
  re-review PoC — all fail-before/pass-after).
- `cargo test -p swarm-runtime --lib sphinx_agent::` → 29 passed (traversal refactor, no regression).
- `cargo test -p swarm-spine` → 36 passed (+ doctests) — incident persistence unchanged.
- `cargo clippy -p swarm-runtime -p swarm-spine --all-targets -- -D warnings` clean;
  `cargo fmt --all --check` clean; `check-workspace-layering.sh` 0; `check-runtime-panic-contract.sh` 0.

## Next

Phase 298 (Cross-Hunt Correlation) — migrate correlation onto graph traversal, make incidents
restart-durable, and (the prerequisite this phase disclosed) wire producers so `Engagement`
anchors carry the Phase 296 raw causal edges, making the cross-hunt join fire on production
telemetry. Depends on Phase 297, now complete.
