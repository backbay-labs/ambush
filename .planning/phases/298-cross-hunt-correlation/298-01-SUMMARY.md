# Phase 298 Plan 01 Summary

Cross-Hunt Correlation (v1.82 Provenance Memory And Correlation). The THIRD of four executable
phases — retires `CorrelationEngine`'s pairwise string-overlap heuristics in favour of graph-native
traversal (all four `IncidentGraphDimension` tags now come from real knowledge-graph edges), makes
each evidence link re-explainable across restart via a persisted `graph_path`, and pins two isolation
invariants: the optional correlation/memory lanes never gate the critical path, and incidents reload
with identical dimensions and evidence. Executed 2026-09-08 as a 4-task pipeline (T1 field → T2
migration → T3 isolation test → T4 restart test → T5 this close) on branch `feat/xhunt-298`, base
`be91c5572`. **v1.82 is NOT complete after this close — Phase 299 remains.**

## Delivered

- **`graph_path` on `IncidentEvidenceLink` (XHUNT-02; `b8f945bf6`):** an optional
  `graph_path: Option<ReconstructedChainHop>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`,
  reusing the spine-local plain-id `ReconstructedChainHop` (no `swarm-runtime` dependency — swarm-spine
  stays TCB-clean). The second serialization mirror (`PerchIncidentEvidenceLink` + `member_view` in
  swarm-ingest-runtime) was updated in lockstep. Pre-`graph_path` JSON deserializes to `None`; the
  `skip_serializing_if` keeps the key absent when `None`.

- **Graph-native correlation (XHUNT-01; `af3d259d7`, hardened `552ab2f1b`):** when a
  `KnowledgeGraphSnapshot` is present, `CorrelationEngine` decides inclusion and all four dimensions by
  graph traversal — for each candidate anchor pair it walks `provenance_paths` and maps the edge kinds
  crossed (`Causal`/`Entity`/`Semantic`/`Temporal`) directly onto `IncidentGraphDimension`s, attaching
  the justifying `ProvenancePath` as each link's `graph_path`. The `Causal` dimension is gated on
  `causal_provenance_paths` (never on a causal edge merely sitting on an all-edge path — the Phase 297
  lesson). Anchors resolve a hunt to BOTH `engagement:{sanitize_id(hunt_id)}` and
  `engagement:{sanitize_id(event_id)}` (production splits a hunt across both). The runtime caller loads
  the persisted signed snapshot and threads it through the three production ingest sites. No string
  overlap survives in the graph-present decision; the legacy string-overlap machinery is retained ONLY
  as an explicit, documented memory-off degraded fallback (Ruling 1).

- **Optional-lane isolation (XHUNT-03; `46e6fc72d`):** an integration test drives identical telemetry
  through two runtime stacks (both lanes on vs. both off) and asserts the `process_event` policy
  decision is identical; the enabled arm genuinely exercises both lanes (a real `SphinxAgent::tick` +
  graph-native correlation, proven by a populated `graph_path`). Test-only; the reviewer verified
  non-vacuity empirically.

- **Restart durability (XHUNT-04; `02afa5cd0`):** a `FileIncidentStore` persist → drop → reopen-fresh →
  reload test asserts full-incident and per-field equality of `graph_dimensions` and every evidence link
  including `graph_path`; non-vacuous (a `#[serde(skip)]` perturbation makes it fail).

## The security property (GRAPH-03 at the correlation level) — one adversarial round

Migrating correlation onto the graph meant it now bridges hunts through the graph, inheriting the exact
cross-hunt fabrication risk Phase 297 closed. The first task-2 review (opus, adversarial) found it,
PoC-proven: two genuinely unrelated hunts that merely share one MITRE technique were bridged through the
shared low-degree `AttackTechnique` classification node via `Semantic` edges — the hub-degree cap never
fires on a low-degree node, and correlation trusted the cap alone (it never read `graph.nodes`, so the
297 classification-node guard was structurally absent). The fix (`552ab2f1b`) closed the class
**structurally** and **unified** the guard: a `node_expandable` predicate was added to the shared BFS
core (`bounded_paths_where`, same non-expansion shape as the hub cap), a
`provenance_paths_excluding_classification_nodes` refuses to expand *through* any globally-merged
`ThreatPattern`/`AttackTechnique` node, and the node-kind rule became one shared `pub(crate)`
`KnowledgeGraphNode::is_globally_merged_classification` that both correlation and Phase 297's
`chain_reconstruction` guard now delegate to (no drift). The scoped adversarial re-review (opus)
confirmed the class is closed for every well-formed graph (2-hop, direct-`ThreatPattern`, interior, and
two-in-series variants all blocked), that the shared-core change is byte-identical for the
non-correlation callers (`provenance_paths`/`causal_provenance_paths` pass an all-permissive predicate;
chain_reconstruction 20 + sphinx_agent 29 green), and that the anti-masking positive genuinely
discriminates non-expansion from a post-hoc reject.

## Controller rulings (recorded in the ledger)

- **Ruling 1 — None-graph semantics (Option 1).** Graph-native decision when a snapshot is present;
  the memory-off path retains today's string-overlap behavior unchanged as an explicitly-named
  degraded fallback. Honors XHUNT-01 for the production cross-hunt config AND SC1 (pre-existing
  e2e/replay/persistence tests hit the fallback unchanged — no scenario-contract edits). SC2 read as
  "every link created FROM graph traversal carries a path"; fallback links legitimately carry `None`.
- **Ruling 2 — snapshot load trust.** The reviewer independently confirmed no assurance-registry
  invariant (MAPPING.md/assumptions.toml/negative-registry) requires a signer-bound load for a
  correlation consumer, and that `load_snapshot()` still runs the full Ed25519 signature + state-kind
  + replay-sequence verification — only the specific-signer binding is deferred. Accepted, correlation
  being off the critical path; threading the Sphinx signer to `load_trusted_snapshot` is the named
  follow-on.

## Honest boundaries (disclosed, not resolved by this close)

- **Producer-wiring gap (carried from 296/297).** Entity(host)/Semantic/Temporal edges fire from live
  telemetry, so cross-hunt correlation has real structure today; but the deep OS-causal edges
  (FileWrite/FileExecute/DnsResolution/CredentialAccess) still require raw `pid`/`process_key`/resolved-IP
  no normalized telemetry event carries, so the `Causal` dimension is sparse on production traffic until
  that producer-wiring lands. Not expanded here (no XHUNT requirement forced it).
- **Accepted residual R-1 (defense-in-depth).** A hand-crafted/corrupted LOADED snapshot with a
  `Semantic` edge to a classification-node id ABSENT from `graph.nodes` could bridge — but this is
  unreachable from any live graph (Sphinx co-upserts every classification node; `prune_stale` never
  orphans edges), is the same assumption the accepted Phase 297 guard makes, and is bounded off the
  critical path. Optional future hardening: fail-closed on an unresolved waypoint kind.

## Verification (final tree)

- `cargo test -p swarm-runtime correlation --lib` → 11 (tests 1-4 migrated to graph fixtures + the
  shared-classification-no-bridge PoC + the anti-masking positive + test 5 kept + the XHUNT-03 operator
  test, whose name also matches the `correlation` filter).
- `cargo test -p swarm-runtime --lib` → 630 (chain_reconstruction 20 + sphinx_agent 29 unchanged; the
  shared-BFS-core change is behavior-preserving for all non-correlation callers).
- `cargo test -p swarm-spine` → 40 unit + 4 integration (incl. the XHUNT-04 restart test; back-compat
  + round-trip from XHUNT-02).
- `cargo test -p swarm-runtime service::tests::operator` → 7 (incl. the XHUNT-03 isolation test).
- clippy `-D warnings` (swarm-runtime, swarm-spine, swarm-ingest-runtime), fmt, and
  `check-workspace-layering` / `check-runtime-panic-contract` / `check-decision-core-boundary` all clean.

## Next

Phase 299 (Dependency-Aware Triage, TRIAGE-01..05) — path-rarity scoring hitting a measured
false-positive reduction target, the LAST phase of v1.82. Depends on Phase 298, now complete.
