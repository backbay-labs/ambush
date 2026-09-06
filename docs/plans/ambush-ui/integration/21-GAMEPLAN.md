# 21 — The gameplan from 2026-09-06: land it, see it, then the frontier

**Status:** the execution record after Wave 3. Written on 2026-09-06 when the five stacked PRs
(#12–#16) were green, mergeable, unreviewed and unmerged, and remote `main` was still the
2026-08-30 README commit. It sequences the work from that point through the engine roadmap
(`.planning/ROADMAP.md`, phases 285–313). Each item is ticked only with evidence: a commit, a
run URL, or an evidence record. An unticked box is a promise, not a claim.

**Authority.** `00-DECISIONS.md` and the milestone plans (`10-`…`15-`) win on the console;
`.planning/ROADMAP.md` and `.planning/REQUIREMENTS.md` win on the engine; this file owns only
the order and the ledger.

**One rule carried forward.** Packaging for outside installation (compose, Helm, notarised
bundles, the release candidate the wave-3 roadmap §10 describes) is the LAST item, after the
engine roadmap completes. Nothing before it is scheduled around an outside event.

---

## Phase 0 — land it and see it

- [x] **Route A: fast-forward `main` to the #16 head and push.** Branch protection on `main`
  required no checks and no reviews (measured with `gh api` on 2026-09-06), the tip's hosted run
  was 16/16 green, and the imported history stays intact. Local: `git merge --ff-only
  codex/ambush-hold-watch` → `acd5024b5`. The push ran the workspace's own lefthook pre-push
  lanes over the whole import diff (file-size ratchet, workspace unit tests, desktop check,
  typecheck, unit tests, Tauri clippy and tests), which is the local gate re-run gate zero
  asked for.
- [ ] **PRs #13–#16 retargeted onto `main`** so GitHub records them merged; #12 closes on its own.
- [ ] **Cross the seam.** The real desktop window against the live stack (`docs/PERCH-DEV.md`
  steps 1–16 with a real window at step 7 and step 16): a finding card in `#lane-execution`,
  `E` opens the case, `D` records the two-legged dismissal, a hold arrives in The Watch, `G`
  then `Enter` after the dwell grants it and the receipt and lease cards land, a refusal, and
  the two-console conflict. Evidence: `evidence/window-walk.md` with screenshots and the ids.
- [ ] **W3-38 and W3-39 fixed** per `15-PLAN-HOLD-DURABILITY.md`: the alarm drainer heals the
  ledger on a channel-state refusal and parks a record after a bounded refusal budget; the
  sweep re-files an unfiled hold. Live reproduction re-run (spool against a wiped relay
  database) and recorded in `evidence/the-hold.md`.
- [ ] **`perch` on by default.** The exit task of The hold, taken only after the window walk.
- [ ] **Roadmap and evidence index updated**: `20-ROADMAP.md` §1 and §10 say "landed" with
  the remote SHA and the hosted run URLs.

## Phase 1 — an internal build someone on the team could run

- [ ] Rebase or retire the parked v1.79 stream: PRs #2, #3, #4, #5 and #11 (phase 285
  assurance, phase 286 collective hypothesis graph; #11 conflicts). Decide each against the
  engine roadmap below rather than merging by momentum.
- [ ] Prune the ~120 `checkpoint/*` remote branches and the ~50 local worktrees after
  triaging the two dirty ones (`swarm-team-six-hold-bridge`: an E2E mock extension;
  `swarm-team-six-wave3-bootstrap-fix`: rename, keyring and reset work). The
  `swarm-team-six-hold-daemon` diff is already landed as `a2e35ce96`.
- [ ] Drive the hold states nobody has driven: `expired`, a daemon crash between the
  compare-and-set and the outcome write (phase 286's fault-injection remit), and a
  containment-refusal `refused_late` (W3-35).
- [ ] The product measures instrumented on The Watch start accumulating: page-open → verdict
  latency, `FalsePositiveMeasurement` records per week, tuning recommendations sourced from
  this week's verdicts (`20-ROADMAP.md` §11).

## Phase 2 — the frontier, in the order the console makes visible

The engine roadmap already plans these as phases 285–313. The console changes their order,
because every bet below becomes something an operator sees on The Watch, the case canvas, or
the tuning bench.

1. **Red swarm in-tree** — phases 288 (red operator genome and target graph), 289 (attack
   scoring, stealth budget, pattern memory), 290 (bidirectional co-evolution), 291 (CI arms-race
   gate and structural isolation: the red lane can never reach response authority).
2. **Open agent protocol** — a new milestone the roadmap's "bring your own agent" paragraph
   promises: deposit INGRESS. An admitted external identity publishes a signed deposit fact over
   the wire the bridge already speaks; the daemon verifies it and deposits a pheromone; the TCB
   boundary already guarantees it cannot authorize. The first external member is an Ambush
   persona (ACP) that reads finding cards and deposits corroboration.
3. **Provenance-grade memory** — phases 296 (provenance graph substrate), 297 (kill-chain
   reconstruction), 298 (cross-hunt correlation), 299 (dependency-aware triage). PR #11's
   hypothesis graph is this lineage.
4. **Assurance as the floor**, interleaved — phases 285 (assumption registry and invariant
   map), 286 (deterministic simulation testing), 287 (fuzz, loom, supply chain), 292 (pure
   decision core), 293 (Kani), 294 (named safety properties and the partition-lease model).
5. **Rotating quorum** — phases 301 (VRF committee selection), 302 (key rotation and
   revocation), 303 (fail-closed contract preservation).
6. **Herd immunity** — phases 305 (information-flow control), 306 (cross-instance immunity
   sharing), 307 (adaptive deception and the integration proof).
7. **The detection commons** — phases 308 (normative spec), 309 (external conformance suite),
   310 (detector-authoring SDK), 311 (generated coverage and adopter IA).
8. **Federated colonies** — phases 312 (cross-operator evidence exchange), 313 (local
   activation boundary).

Then, and only then: packaging for outside installation.

## Ledger

| Date | Item | Evidence |
|---|---|---|
| 2026-09-06 | `main` fast-forwarded to `acd5024b5` locally; pre-push lanes running | this file's first commit |
