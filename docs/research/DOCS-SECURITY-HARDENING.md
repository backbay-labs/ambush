# Ambush Doc-Suite Improvement & Hardening Plan

## 1. Overall verdict

The suite is **trustworthy enough to publish after one focused correction pass — except where it makes safety claims.** Five of six reviews grade `good`/`needs-work`; the prose is unusually code-faithful and the line-range citations largely verify. SWARM-MODEL and GOVERNANCE-SECURITY are near-excellent on internals. Two documents must not ship as-is:

- **ENGINE-INTEGRATION (needs-work):** two HIGH errors sit under its core recommendations, so an implementer following it literally builds against engine behavior that doesn't exist.
- **The security narrative (graded `misleading`):** PRODUCT/GOVERNANCE-SECURITY market signed receipts, fail-closed governance, guards, dry-run, and a human gate as protections for the swarm, when none of that is wired to the component that actually runs offensive agents.

Net: ship-blocking on the security framing and ENGINE-INTEGRATION specifics; everything else is tightening.

## 2. Critical accuracy fixes (grouped)

**A. Engine protections are largely not on the hot path.** GOVERNANCE-SECURITY §4 + threat rows T3/T4/T5 present `forbidden_path`/`shell_command`/`egress_allowlist` as active engine mitigations. Evidence: the runtime only constructs `GuardAction::ResponseAction` (`swarm-runtime/src/lib.rs:679`), the guard pipeline is `Option<GuardPipeline>` defaulting to `None` (`:543,:564`), and only `secret_leak.handles()` accepts `ResponseAction`. Correction: state that today **only `secret_leak` inspects live actions**, the pipeline is optional/default-None, and the file/shell/egress guards fire only when a caller supplies the matching `GuardAction` (tests/`default_pipeline()`).

**B. ENGINE-INTEGRATION's two load-bearing errors.** (1) Option B/Phase 2-3 route `/v1/operator/*` through `swarm_detect --serve`; that surface (`detect_http_router`, `ingest/mod.rs:2311-2343`) never mounts it — `/v1/operator/*` is `LocalOperatorSurface` served by the separate `swarmctl serve` process (`swarm-cli/src/core.inc:2741`). (2) Option A/Phase 1 parses `swarm_detect --json` into `SwarmFinding[]`; non-serve `--json` emits only per-event **counts/verdicts** (`swarm_detect.rs:1116-1182`), never envelopes. Correction: rebuild Option B around what `swarm_detect` exposes (`/v1/events/stream` SSE, `/v2/api/*`), name `swarmctl serve` as a distinct optional process for operator/review, and source findings from the SSE `Finding` event or `/v2/api/findings`, not `--json`.

**C. The Chio policy is not "read-only," and governance is fail-open.** ROADMAP:50 and the `chio-governor.ts:7-9` comment both say "intel tools + read-only inspection." `DEFAULT_POLICY` (`chio-governor.ts:13-29`) allows `write/edit/move/checkpoint/skills/exec` and denies only `delete`. When `chio` is absent, `wrapMcp` returns the raw `ok mcp` command and agents run **ungoverned** (`:84`). Correction everywhere: "allows the intel tools plus write/edit/move/checkpoint/skills/exec; denies only delete; fail-open when chio is missing." Flag `exec`-on-allowlist as a known gap.

**D. Worktree isolation is conditional and not a security boundary.** PRODUCT:34-36/114-116 says "every agent runs in its own git worktree + branch." `WorktreeManager.create()` falls back to a scratch dir (`branch:null`, `isGit:false`) for non-git targets (`worktree-manager.ts:37-42`) — i.e. for 3 of 5 personas. Correction: "worktree + branch when the target is a repo, otherwise an isolated scratch dir," and add that worktrees live inside the target tree and are organizational, not a sandbox.

**E. Over-broad guarantee claims.** PRODUCT:40 "non-repudiation for everything the swarm touches" and GOVERNANCE-SECURITY:16 "both planes are fail-closed" overreach; receipts cover only governed intel-MCP calls, and the control plane is fail-open without chio (and chio is not vendored in-repo). Correction: scope to "every governed intel-vault tool call," and mark fail-closed as a property of the **external, unverifiable** chio binary.

**F. Small but real facts to correct.** PRODUCT verdict list omits `UNKNOWN` (`types.ts:97`); `reporting` is shown as a live transition but is never assigned (`swarm-orchestrator.ts`); `live_mode` is presented as the dry-run gate but is dead — `RuntimeMode→ExecutionMode` (`lib.rs:693-695`) is the real driver; SWARM-MODEL:24-25 "Four are persisted state" is wrong (only Operation, with nested Vectors); the `100` cap is per deploy/scale call, not a per-operation ceiling.

## 3. Cross-doc consistency fixes

- **`reporting` status / verdict set:** make PRODUCT match SWARM-MODEL/ARCHITECTURE (`reporting` reserved/unused; add `UNKNOWN`). ENGINE-INTEGRATION additionally needs a `HELD`/`PENDING` verdict so `PolicyVerdict::RequireHuman` survives mapping.
- **"Default agent":** code's `DEFAULT_AGENT_ID` is `shell`, but the hermes profile's description string says "fleet default." Add a parenthetical in SWARM-MODEL:169 so the term doesn't contradict PRODUCT/ARCHITECTURE.
- **Chio policy wording:** reconcile ROADMAP:50 ("read-only") with GOVERNANCE-SECURITY:99-106 (accurate enumeration). The accurate one wins.
- **Intel UI status:** PRODUCT/renderer treat the embedded `ok` webview as shipped; ROADMAP lists "embed the OpenKnowledge web UI" as future v0.2. Move it to v0 "What works."
- **Worktree-cleanup leak:** SWARM-MODEL:701 lists it; ROADMAP omits it. Add to ROADMAP limitations.
- **Single active operation:** ROADMAP:71 states it; PRODUCT never does. Add to PRODUCT §7.
- **Manager naming:** ROADMAP uses `EngineRuntime`/"Stage 1/2/3"; ENGINE-INTEGRATION uses `SwarmEngine`/"Phase/Option A-C." Pick one.
- **Dedupe:** the "two halves unwired" framing recurs in PRODUCT, ARCHITECTURE, ROADMAP, GOVERNANCE, ENGINE-INTEGRATION. Centralize a single canonical "Shipped vs Planned / Known Limitations" table (ROADMAP) and link to it from the others.

## 4. Most valuable gaps to fill

1. **Honest security caveat block** in PRODUCT/GOVERNANCE: agents run unsandboxed with the operator's full env; engine guards/leases/dry-run/human-gate are engine-only; Chio governs only intel writes and is optional.
2. **ConfigurableApprovalGate + PolicyConfig.rules** (`configurable_gate.rs`) — GOVERNANCE presents engine policy as static-only, so §8(2) "make configurable" reads as missing when it's a control-plane gap.
3. **Static-gate defaults** (`human_gate_severity=High`, `lease_ttl_ms=60000`, per-scope/minute budget) so thresholds are quantified.
4. **Correct findings data path** in ENGINE-INTEGRATION (SSE `Finding` / `/v2/api/findings`) and the **full IPC wiring triple** (`ipc.ts`, `preload/index.ts`, the hardcoded broadcast array in `register-ipc.ts`).
5. **Test/CI baseline:** zero control-plane tests under `src/`; note this against the "reliable core" / "security review" milestones.
6. **Non-git scratch fallback, single-active-operation, no UI for custom objectives, OpenKnowledge GPL boundary** in PRODUCT.

## 5. Security-hardening shortlist (cheapest high-impact first)

Tied to the threat model (prompt-injected/over-eager offensive agent with operator privileges):

1. **Stop leaking secrets:** replace `env:{...process.env}` (`swarm-orchestrator.ts:194`) with an allow-list (PATH, HOME, TERM, AMBUSH_*, one model key). Near-zero effort, removes the largest exfil blast radius.
2. **Least-privilege Chio policy:** drop `exec/skills/move` (and ideally scope `write/edit` to `findings/`) in `chio-governor.ts:13-29`. Closes governed-path RCE escalation.
3. **Real fail-closed governance:** when chio is absent, refuse to launch or launch in a visible "UNGOVERNED" mode, and stop `mission.ts:36-39` asserting writes are signed.
4. **Process-group kill:** spawn detached/`setsid`, `killpg`/`taskkill /T` (`pty-manager.ts:90,118-124`) so recall kills detached exfil/persistence children.
5. **Runaway limits:** per-vector wall-clock timeout + `ulimit`/`sandbox-exec`/`firejail` CPU/proc caps.
6. **Supply chain + Electron:** pin OpenKnowledge instead of `npx -y @latest` (`openknowledge-engine.ts:37`); set strict CSP, `sandbox:true`, webview nav handlers (`index.ts:31-34`).
7. **Untrusted vault:** provenance-tag findings and sanitize `RUNBOOK.md` (`swarm-orchestrator.ts:286-334`) against injection propagation.
8. **OS-boundary containment** (highest effort): run vectors in a container/netns with default-deny egress, or interpose `swarm-guard` + a real human-gate on agent shell/file/network actions.

## 6. Punch-list (value-to-effort, top-down)

1. Fix Chio policy wording in ROADMAP:50 + the `chio-governor.ts:7-9` comment (5 min).
2. Add `UNKNOWN` verdict; mark `reporting` reserved in PRODUCT.
3. Conditionalize worktree-isolation language in PRODUCT (§2/§4c/§5).
4. Scope PRODUCT:40 + GOVERNANCE:16 to governed intel-MCP only; note fail-open + chio not vendored.
5. Fix SWARM-MODEL "five nouns" arithmetic + lifecycle mermaid (idle→failed vs deploying→failed/127).
6. Add the engine-guard caveat to GOVERNANCE §4/T3-T5; fix `live_mode`→`RuntimeMode/ExecutionMode`.
7. **Code: env allow-list** (#5.1) — ship with a security-caveat doc update.
8. **Code: Chio least-privilege policy** (#5.2) + fail-closed degradation (#5.3).
9. Rewrite ENGINE-INTEGRATION operator-surface attribution, finding data path, consolidate-is-flat-readdir, `RequireHuman→HELD`, `SwarmFinding` shape, IPC wiring triple.
10. Add Known Limitations to ROADMAP (worktree leak, exec allowlist, no tests, no backpressure); move Intel webview to "What works."
11. Add static-gate defaults + ConfigurableApprovalGate to GOVERNANCE; add single-op/non-git/license gaps to PRODUCT.
12. **Code: process-group kill, resource limits, dependency pin + Electron hardening, vault provenance** (#5.4-5.7), each paired with the doc claim it makes true.

Key files: `docs/{PRODUCT,SWARM-MODEL,GOVERNANCE-SECURITY,ENGINE-INTEGRATION,ROADMAP}.md`; `/Users/connor/orca/workspaces/ambush/ruffe/src/main/governance/chio-governor.ts`; `.../src/main/swarm/{swarm-orchestrator,worktree-manager,mission}.ts`; `.../src/main/engine/openknowledge-engine.ts`; `.../src/main/terminal/pty-manager.ts`; `.../engine/crates/swarm-runtime/src/lib.rs`.