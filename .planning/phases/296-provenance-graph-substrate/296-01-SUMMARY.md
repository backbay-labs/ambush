# Phase 296 Plan 01 Summary

Provenance Graph Substrate (v1.82 Provenance Memory And Correlation). The FIRST of four
executable phases of this milestone — deepens the existing four-graph knowledge substrate with
real OS-level causal nodes and edges, adds the bounded-hop traversal that Cross-Hunt Correlation
(Phase 298) and Kill-Chain Reconstruction (Phase 297) will consume, and bounds the graph's growth
with a proptest-backed GC proof and a soak ceiling before anything traverses it. Executed
2026-09-08 as a 4-task pipeline (T1 node + causal-relation model -> T2 bounded-hop traversal +
hub cap -> T3 GC property test + soak + retention footgun -> T4 this close) on branch
`feat/graph-296`, commit range `0baa0ef45..faa5d9dae`. **v1.82 is NOT complete after this close —
Phases 297/298/299 remain.**

## Delivered

- **Provenance node + causal-relation model (GRAPH-01/02; `0baa0ef45`, doc comment `69b1a7bef`):**
  `KnowledgeGraphNode` gains `ProcessNode` (`process_key`/`pid`/`host_id`/`executable_path`/
  `command_line`), `FileNode` (`file_path`/`host_id`), and `NetworkFlowNode` (5-tuple keyed:
  source/destination IP+port, protocol) — raw-telemetry-identifier variants distinct from the
  existing name-keyed `EntityNode(EntityKind::Process/IpAddress)` and the detection-level
  `EngagementNode`. `CausalRelation` gains `FileWrite` (`Process -> File`), `FileExecute`
  (`File -> Process` — the reversed direction is deliberate: the executable becomes the running
  process), `DnsResolution` (`Process -> NetworkFlow`, gated on the resolved IP matching the
  observed flow's destination), and `CredentialAccess` (`Process -> Entity(User)`). All four are
  emitted from `SphinxAgent::ingest_pheromone()`, pivoted on the new raw `ProcessNode` rather than
  the pre-existing name-keyed entity, so the new data model is actually exercised rather than left
  inert. Every new node/relation variant is wired through the exhaustive `KnowledgeGraphNode`
  impl matches, `merge_node()` (min/max timestamps, `observation_count +=`, fill-if-empty), and
  the unchanged `persist_snapshot()` path — verified with a new persist-across-restart test. All
  emission is strictly opt-in on new indicator fields (`pid`/`process_key`, `file_path`+
  `file_operation`, `source_port`/`destination_port`/`protocol`, `dns_query_name`+
  `dns_resolved_ip`, `credential_subject`); one of the 6 new unit tests proves an observation with
  none of these fields produces zero new nodes and none of the four new relations, so no
  pre-existing fixture or behavior changed.
- **Bounded-hop traversal with a hub-degree cap (GRAPH-03; `72c9c2156`):**
  `KnowledgeGraphSnapshot::provenance_paths(from, to, max_hops)` — a BFS with panic-free
  parent-pointer path reconstruction, returning the shortest path within `max_hops` (or empty if
  none exists; `from == to` returns the trivial zero-edge path). Traversal is undirected by
  documented design: the question this method answers is "are these two nodes connected within N
  hops," not "replay this causal chain in recorded order" — each edge's own `from_node_id`/
  `to_node_id` still records its original direction for audit fidelity. **The security
  property:** `PROVENANCE_HUB_DEGREE_CAP = 32` gates *expansion* (not reachability) of any node
  encountered after the initial `from` node — a node over the cap can still be reached as a path
  endpoint, but the search will not step onward from it to its other neighbors, so a high-degree
  node (a shared host/IP/technique accumulated across many unrelated engagements) cannot bridge
  two otherwise-disjoint hunt subgraphs. The load-bearing test constructs exactly that scenario —
  two subgraphs connected only by a hub pushed past the cap with filler edges — and proves the
  bridge is blocked while ordinary same-side traversal and hub-as-endpoint queries still succeed.
  `provenance_paths` (plus its private `neighbor_index` helper) is confirmed the sole
  graph-traversal code path in the file; `CorrelationEngine::graph_provenance_link` is a thin,
  additive, delegate-only pass-through — migrating `correlate_hunt_at` itself onto graph traversal
  is explicitly left to Phase 298 (XHUNT-01) and was not touched here.
- **`prune_stale` property test, 100k soak, and the retention footgun (GRAPH-04/05/06;
  `faa5d9dae`):** `proptest` added as a `swarm-runtime` dev-only dependency (confirmed absent from
  the normal dependency edge via `cargo tree -e normal`). A 256-case (above the required 200+)
  randomized property test (`InsertNode`/`InsertEdge`/`AdvanceClock`/`Prune`, weighted, 1-40
  ops/sequence) checks three invariants after every `Prune` step: no surviving edge references a
  pruned node; every node/edge an independently-derived cutoff oracle says must survive does
  survive (a genuine re-derivation of the `>=`-cutoff contract, not a tautological reuse of
  `prune_stale`'s own formula); and a second immediate `prune_stale` call is a no-op. All 256
  cases pass on every run; **no defect was found** in the pre-existing `prune_stale` — its
  edge-orphan guard and cutoff logic already hold up under fuzzing. A 100k-synthetic-event soak
  replays directly against `KnowledgeGraphSnapshot`'s vectors and the real, unmodified
  `prune_stale` (persistence side-effects deliberately skipped to keep the test lane fast — same
  GC function, same call pattern, minus the per-tick disk write), sweeping every 1,000 events,
  and asserts a post-GC ceiling of 172,866 against an unpruned total of 199,999 — a tight bound
  with only ~65 headroom over the ~172,801 actual survivors, independently re-derived and
  confirmed by the reviewer. **GRAPH-06:** the pre-existing hard config reject
  (`MemoryConfig::validate()`, `crates/swarm-core/src/config/state.rs:127-132`, unchanged) still
  rejects `knowledge_retention_days == 0` while `memory.enabled`; a new
  `SphinxAgent::warn_if_retention_footgun_reachable` guard, called in `tick()` immediately before
  `prune_stale`, adds defense-in-depth for a config that somehow bypasses that gate —
  `debug_assert!` panics loudly in debug/test builds and `tracing::warn!` fires unconditionally in
  every build profile, so a release build never silently no-ops forever. `prune_stale` itself is
  untouched, so its behavior for `retention_days > 0` (and its legitimate no-op when
  `memory.enabled` is false) is unchanged.
- **Ledger close (this task, T4):** `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, and
  `.planning/STATE.md` updated to record Phase 296 complete, GRAPH-01..06 satisfaction with exact
  commits, and — since three phases of v1.82 remain — the milestone's genuinely partial state
  (1 of 4 phases), with both caveats below recorded rather than glossed.

## Two honest caveats, recorded rather than glossed

1. **Producer-wiring gap (GRAPH-01/02) — the new edges do not yet fire on production
   telemetry.** All four new causal relations pivot on a raw `pid`/`process_key` (and, for
   `DnsResolution`, a resolved IP that must match the observed flow's destination). The Task 1
   review confirmed that no current normalized `swarm_core::telemetry` event carries these raw
   identifiers: `ProcessStartEvent`, `NetworkConnectEvent`, and `FilePersistenceEvent` all carry
   `process_name` (a string), not a `pid`, and `DnsQueryEvent` has no resolved-IP field at all.
   The model and emission logic are correct and exercised against synthetic fixtures — the 6 new
   unit tests prove the wiring end-to-end when the raw fields are present — but on real production
   telemetry as it is normalized TODAY, none of the four new edges will fire, because no producer
   populates the fields they gate on. This is a real, disclosed limitation, not a defect in this
   phase's scope (which was model-only, per the plan); closing it is follow-on work, most likely
   alongside Phase 297 (Kill-Chain Reconstruction), which is the first phase to actually consume
   these edges.
2. **Line-slip (GRAPH-06).** The requirement text names `sphinx_agent.rs:1097` as the silent-no-op
   GC footgun site. At the pre-phase base commit (`a7d77129f^`), that line was inside the
   unrelated `attack_technique_for_node` lookup function, not the retention/prune logic — confirmed
   directly (`git show a7d77129f^:crates/swarm-runtime/src/sphinx_agent.rs` at line 1097). The
   substantive target was always the `prune_stale`/`tick()` `retention_days == 0` no-op path,
   which this phase closes via the pre-existing hard config reject plus the new defense-in-depth
   guard, regardless of the stale line citation.

## Final verification (this task, on the closing tree)

- `cargo test -p swarm-runtime --lib sphinx_agent::` — **28 passed**, 0 failed (includes the
  256-case proptest and the 100k-event soak).
- `cargo test -p swarm-core --lib config::` — **89 passed**, 0 failed, including
  `memory_requires_positive_retention_days_when_enabled`.
- `bash tools/check-workspace-layering.sh` — exit 0.
- `bash tools/check-runtime-panic-contract.sh` — exit 0 (0 live `unwrap()`/`expect()` sites outside
  tests; the new `debug_assert!` is not flagged by this gate).
- `bash tools/check-gates-wired.sh` — exit 0.
- `git diff --stat` for this close's commit — `.planning/` files only.

## Task authorship note

All three implementation tasks were dispatched to subagents and independently reviewed; each
review came back clean (0 Critical/0 Important defects). Task 1's review flagged one item as
Important-*for-follow-up* rather than a blocking defect in this task's scope: `DnsResolution`'s
gate requires the resolved IP to equal the observed flow's destination, which is a defensible but
narrower reading than "just check the DNS fields exist," and is the same producer-wiring gap
recorded above — whoever wires real DNS producers or Phase 297's traversal onto this data needs
that decision in hand. Task 2's review confirmed the hub-degree-cap exemption for the initial
`from` node's own first expansion is a defensible reading that does not weaken the stated security
property (mid-path bridging through a hub is fully blocked either way).

## Notes

- Field/wire-name choices for the new indicator fields (`pid`, `process_key`, `file_path`,
  `file_operation`, `source_port`, `destination_port`, `protocol`, `dns_query_name`,
  `dns_resolved_ip`, `credential_subject`) were the implementer's own design decision — the plan
  specified node/relation *types*, not exact wire-field names. Cross-checked against
  `swarm-ingest-json/{auditd,sysmon,generic_json}.rs`, which already use `file_path` and
  `destination_port` for the same concepts with no naming collision.
- Full session ledger: `.superpowers/sdd/296-01-PLAN/progress.md`, `task-1-report.md`,
  `task-2-report.md`, `task-3-report.md`, and their paired `task-N-review.md` files.
