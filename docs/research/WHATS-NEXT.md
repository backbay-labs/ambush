# What Ambush Should Do Next — Final Plan

Decision-grade, grounded against the repo, and revised after three adversarial reviews. The critiques did not dislodge #1 from first place, but they corrected its *framing*, its *size*, its *deny mechanism*, and its *scope*. All four corrections are folded in below.

## (1) The call

**Build a headless end-to-end smoke that drives the real orchestrator (`deploySwarm` → `launchVector` → `consolidate` → `exportBundle` → `ambush-verify`) and forces a non-empty, dual-verdict attestation bundle — emitting real signed receipts over deterministic synthetic actions through the governed MCP gate, on the `evaluate_metered` rails, across 3–5 diverse lanes.** This is the keystone because every downstream move operates on data that *nothing currently emits*: the default `shell` lane only runs `cat AMBUSH_MISSION.md` (`swarm-orchestrator.ts:241`), writes nothing to `findingsAbsPath`, and calls no governed tool; `claude`/`codex` run interactively and never exit, so `onTerminalExit → checkFindings` (`:256`) never fires. The bundle is therefore degenerate today — `findings-present:'unsupported'`, ALLOW/DENY coverage `excluded` (`attestation.ts:132-149`). Metering, SIEM, and the slop-filter all consume receipts/findings that this void withholds.

But I am **explicitly rebutting the original framing**, per the reviews. This is *not* "real findings," *not* "the 2-minute demo," and *not* proof the swarm "runs a real operation." It produces real signed receipts over **synthetic** actions; `ambush-verify` hashes and signature-checks bytes we authored, so a smoke asserting `ok:true` over a self-seeded bundle is tautological if that is all it asserts. Its honest value is narrower and still decisive: it is the **regression spine** that closes the orchestration glue, the `swarm-mcp-gate` subprocess boundary, and attestation byte-compatibility — the exact surface with *zero* current coverage (the Rust `lib.rs` unit tests already cover allow/deny/metered/tamper). To be non-tautological, the smoke must assert **non-empty findings AND `deny` coverage = `covered`** by reading the manifest's `receipt_coverage` — not merely `ok:true`.

Two load-bearing corrections from the reviews, both verified and both fatal if ignored:

- **The "proven DENY path" does not reach the bundle.** The terminal-governor's `cat ~/.ssh/id_rsa` deny emits only to `bus.receipt()` (`terminal-governor.ts:133`); it is never written to `receipts.jsonl`, which is the *sole* source for `governor.listReceipts()` and thus the bundle (`chio-governor.ts:150-160`, `register-ipc.ts:102`). Worse, it signs with `ambush-governor-${op.id}` (`terminal-governor.ts:121`) — a *different identity* than the gate/bundle's random `governor.secret` (`chio-governor.ts:118`) — and a self-driven `pty.write` takes the **trusted** path that bypasses governance entirely (`terminal-governor.ts:18-21`). Reusing it would ship a **false green**. The bundle-visible DENY must instead go through the real MCP gate.
- **That means new code, so this is M, not S.** Bundle-visible receipts require a deterministic JSON-RPC MCP client issuing `initialize` + `tools/call` (one ALLOW `write`, one DENY `delete`/`exec`, which `chio-governor.ts:30-34` denies) into the gate's stdin (`proxy.rs:82-99`) — **no such client exists** — plus an **offline stub inner MCP server**, because the gate spawns the inner process before proxying (`main.rs:82-91`) and `ok` is uninstalled, falling to the multi-minute networked `npx` (`openknowledge-engine.ts:40`). Size it **M (M+ if stubbing the inner server)**.

Why it still beats the alternatives: metering enforcement (#3) is the *cheaper, non-fabricated* enforcing beat — but its *fan-out cap* and *over-budget deny* need no findings, so I have **decoupled them and promoted them beside Wave 1** rather than letting #1 falsely claim to unlock them. CI-first certifies a void. Slop-filter-first is impossible — it needs findings #1 hasn't produced. So #1 stays first, honestly labeled.

## (2) Ranked shortlist

| # | Move | Why now | Effort | Value | Unlocks |
|---|------|---------|--------|-------|---------|
| 1 | **Headless E2E smoke + synthetic seed**: MCP JSON-RPC client + offline stub inner-server, 3–5 diverse lanes (overlapping/noisy findings), one ALLOW + one DENY through the real gate, on `evaluate_metered(None)` rails; assert non-empty findings AND `deny:covered` | Lanes emit nothing → degenerate bundle; everything downstream operates on absent data | **M/M+** | **Existential (as regression spine, not demo)** | Real receipts for metering/SIEM; diverse findings for #4; falsifiable plumbing gate |
| 2a | **Push branch now** (`bb-connor/research-platform-design`) | 26 commits unpushed, no backup; CI cannot run on unpushed work | XS | High | Backup + precondition for any CI |
| 2b | **Relocate CI to root `.github/`, trigger on `master`+branch, gate on the smoke**, then open PR; fix `swarm-team-six` branding | Engine CI triggers on `main`, never run; root has no `.github/` | M (sized: Rust workspace build + node-pty) | High | Reviewable PR; regression guard |
| 3 | **Metering enforcement**: flip live gate to `evaluate_metered`, cap fan-out by model-family, stateful `BudgetEnforcer` per lane, Cost pane | Naive `Math.min(count,100)` is the "$600 burst"; needs no findings — the *honest* enforcing demo | M | High | Price-justification; non-fabricated on-stage refusal |
| 4 | **Validated slop-filter → `FindingsReview`** (Corroborated vs Quarantine + model-diversity meter) | Founder's lead-of-sale; the conversion event; now fed by #1's diverse lanes | L | **Highest ceiling** | The painkiller |
| 5 | **SIEM export** (`[[bin]]` on `swarm-siem` over `receipts.jsonl`; `siem:export` IPC; Audit panel) | Formatters + receipt source both exist; pure glue | S–M | High | First sellable Org surface |
| 6 | **Surface guard verdicts** (thread `gate_id`/guard name through `ReceiptSummary`) | `normalize()` flattens it; cheap | S | Med | 9-guard investment made visible |

## (3) Sequenced roadmap

**Wave 0 — zero-cost de-risk (today).**
1. **Push the branch immediately.** 26 commits, no backup; also the precondition for #2b's CI to ever execute. Pushing the branch is *not* opening the PR — the PR waits for green CI + non-empty bundle.
2. **Local `cargo build --workspace && cargo test`** across the 21 edition-2024 crates. The seed depends on the governor bin + `swarm-mcp-gate` + `swarm-metering` compiling, and these have *never* been CI-built. If the engine is red, #1 is blocked — learn that on minute one, not after building a TS harness.

**Wave 1 — close the emission void + the honest enforcing beat (M / M / M).**
3. **Build the seed harness (#1).** New non-interactive, exit-on-complete agent profile in `src/shared/agents.ts` + the `promptDelivery` switch in `launchVector` (`swarm-orchestrator.ts:236-244`): one lane writes `findingsAbsPath` directly; 3–5 lanes emit deliberately overlapping/noisy findings across simulated model families (so #4 has real input). Build the deterministic MCP JSON-RPC client + offline stub inner-server; drive one ALLOW (`write`) and one DENY (`delete`/`exec`) through the **real gate** so both land in `receipts.jsonl` (`receipt_log.rs:54`). Run the orchestrator headless under plain `node` (`bus.ts` is a bare `EventEmitter`; `pty-manager.ts:15-22` lazy-loads node-pty with a piped fallback) — call orchestrator/attest methods *directly*, since `register-ipc.ts` imports `BrowserWindow`/`dialog`. Be honest that this is E2E of the main-process *core*, not the product. **Parameterize for graduation**: the same harness must run real `claude` + governed `ok` MCP when present, so it is not permanently synthetic. Add a `test` script to `package.json` (no runner exists today). Do **not** let `eval/tests/test_demo_smoke.py` (a Python fixture simulation) masquerade as this.
4. **Flip the live gate to `evaluate_metered`** at `swarm-governor.rs:50` and `receipt_log.rs:61` (near-zero risk — `evaluate` already delegates to it with `None`, `lib.rs:72`). Doing this *inside* Wave 1 locks the smoke onto the path we ship and pre-stages the metering data source, avoiding a later smoke re-work. The *enforcement* half of #3 (fan-out cap, stateful `BudgetEnforcer`, Cost pane) rides **beside** #1 as the non-fabricated on-stage refusal.
5. **CI bring-up as its own sized item (#2b).** Relocate `engine/.github/workflows/ci.yml` to root `.github/`, retrigger on `master` + the feature branch, and budget the cold Rust workspace build + node-pty/electron-rebuild matrix explicitly — do not let it ride free. Gate on the smoke (typecheck, `cargo test`/clippy, fuzz seeds). Ride #6's guard-verdict surfacing along.
6. **Open the PR to `master`** only once CI is green over a non-empty bundle; fix `swarm-team-six` branding in the same PR.

*Exit criterion:* one command runs an Operation E2E and the manifest shows **non-empty findings, `deny:covered`, `allow:covered`**, `ambush-verify ok:true`, in CI.

**Wave 2 — visible + monetizable (M / L / S–M).** Finish metering enforcement + Cost pane; ship SIEM export (#5: bin + IPC + panel); **begin #4** (the slop-filter `FindingsReview`), now fed by #1's diverse lanes. Stretch: mint a scoped `swarm-authority` token per Vector at deploy and stamp it into the bundle — but it only has teeth once the MCP gate verifies admission (`admission.rs:35`), so it trails enforcement.

## (4) Non-goals (deliberately not yet)

- **`swarm-spine` lineage graph UI** — lowest value-per-effort; flat `RUNBOOK.md` consolidation suffices.
- **Inbound eval-receipt SDK / federation** — no inbound receipts, no buyer signal; build outbound first.
- **TrustBundle quorum / multi-signer authority** — single local `governor.secret`; deepening authority before the existing single hop is even minted at deploy is backwards.
- **Protocol bridges (MCP-edge, A2A, ACP/AG-UI)** — MCP is already governed.
- **`swarm-consensus` BFT** — founder decision #3 chose cross-model-family clustering, not BFT.
- **Notarized `.app` packaging** — L, not conversion-critical; unpacked `out/` is fine. *Do* harden the `AMBUSH_ALLOW_UNGOVERNED=1` escape hatch (`chio-governor.ts:79-101`) — loud, audited, blocked in packaged builds — but with the security self-review, not now.
- **Deep OpenKnowledge integration** — stub/pin `ok` for offline determinism; do not chase the networked dependency.

## (5) If you do only one thing this week

Push the branch today, then build the headless smoke that drives the real orchestrator and forces a **non-empty, `deny:covered`** bundle through the MCP gate — honestly a regression spine over synthetic actions, not a demo, but the one thing without which metering, SIEM, and the slop-filter are all glue over a void.