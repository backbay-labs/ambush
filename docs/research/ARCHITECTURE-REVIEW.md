# Doc-Accuracy Review — docs/ARCHITECTURE.md (backfill of the failed lane)

**Grade: excellent.** Unusually faithful to the code. Every load-bearing claim verified: strict main/preload/renderer model, the "single source of truth" IPC contract + three-place lockstep (ipc.ts / register-ipc.ts / preload), the `bus` typed helpers + `broadcast()` fan-out, the `evt:terminal:exit → onTerminalExit` loopback, the deploy-swarm sequence, the Operation/Vector/AgentProfile model, the vector lifecycle, all five subsystems, and the §7 file map. The Rust §5 crate table matches `engine/Cargo.toml` exactly (15 members) and is more complete than the engine's own README. Defects are all low-severity.

## Low-severity accuracy fixes
- §1 diagram lists 5 runtimes — **`opencode` is missing** (there are 6: claude, codex, cursor, opencode, hermes, shell). `agents.ts:31-38`. Also unify `cursor-agent` (diagram) vs `cursor` (id).
- §6 says count "clamped 1–100 in deploySwarm/scale" — **`scale` clamps 0–100** (scale-to-0 = full recall). `swarm-orchestrator.ts:264`.
- §4.3 `mcpCommand()` shown as `["ok","mcp"]` — understates the npx form `[npx,-y,@inkeep/open-knowledge@latest,mcp]`.
- §4.3 `start()` "parses URL from stdout" — actually **optimistically sets running=true + url=127.0.0.1:39847 regardless** (known ROADMAP bug). 
- §2.3 sequence implies synchrony — `deploySwarm` returns immediately via `void launchVector`; vectors are still idle/deploying in the returned snapshot.

## Gaps to fill
- **`createOperation` provisioning is undocumented** — the real precondition to deploy (vault + governor.configure + engine.configure/start). Single biggest comprehension gap. `swarm-orchestrator.ts:69-99`.
- Injected agent env vars `AMBUSH_VECTOR_ID/FINDINGS/VAULT` (how non-MCP agents locate findings). `:193-199`.
- Prompt-delivery timing (stdin 1200ms auto-Enter; shell `cat AMBUSH_MISSION.md` 400ms). `:210-215`.
- `scale()` semantics; renderer typing companions (global.d.ts / webview.d.ts).

## Consistency
- Agent-runtime count: PRODUCT/§3 list 6, §1 diagram lists 5 → internally inconsistent.
- Swarm cap: PRODUCT/ROADMAP emphasize "UI slider to 50; orchestrator to 100" (DeployControls max=50); ARCHITECTURE omits the UI-50 cap.
- Otherwise consistent: `reporting` documented as unused everywhere; license story identical; DEFAULT_POLICY YAML matches code.

**Net:** ARCHITECTURE.md is the strongest doc in the suite (vs ENGINE-INTEGRATION which has load-bearing errors and the GOVERNANCE/PRODUCT security narrative which is misleading). Minor polish only.
