# Feature Research

**Domain:** Autonomous EDR/XDR response agent, configurable policy engine, mode de-escalation, governance oversight
**Researched:** 2026-04-08
**Confidence:** HIGH (codebase evidence) / MEDIUM (domain patterns from web)

## Feature Landscape

### Table Stakes (Users Expect These)

Features operators and security teams assume exist. Missing these means the autonomous response loop is incomplete or untrustworthy.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| PounceAgent triggered by escalation pheromones | EDR autonomous response agents must have a deterministic trigger that reflects accumulated signal, not raw events | MEDIUM | Depends on existing `ConcentrationMonitor` + `SwarmMode` escalation path |
| PounceAgent executes through existing guard pipeline | Response without guard checks is a safety regression; operators expect the same safety lane as before | LOW | `DispatchingExecutor` + `ApprovalGate` already exist; PounceAgent wires them together |
| PounceAgent respects mode and policy before acting | Autonomous action in detect_only mode would be a critical safety violation | LOW | Mode is already surfaced via `SwarmEnvironment::current_mode()`; gate check must be mandatory |
| PounceAgent dry-run mode | Operators must be able to preview autonomous behavior before enabling live response | LOW | Existing `ExecutionMode::DryRun` on adapters; PounceAgent needs an explicit dry-run config flag |
| Auditable response receipts linked to detection lineage | Every autonomous action must be reconstructable; receipt-less response is unacceptable in regulated environments | MEDIUM | `swarm-spine` receipt primitives exist; PounceAgent must embed hunt_id and detection lineage in every receipt |
| Fail-closed on missing or expired leases | Autonomous agents that proceed without a valid lease are a blast-radius risk | LOW | `CapabilityLease.expires_at_ms` already exists; enforcement requires a checked path before `execute()` |
| Configurable policy rules beyond static gate | The current `StaticApprovalGate` hardcodes severity thresholds; operators must be able to adjust them per deployment | MEDIUM | New `ConfigurablePolicyGate` with YAML-backed rules; replaces hardcoded `human_gate_severity` |
| Policy verdict explanations in audit log | SOC teams expect to know *why* an action was allowed, denied, or held — not just the verdict | LOW | `PolicyDecision.reason` field already exists; must be emitted to structured logs and receipts |
| Mode de-escalation from Incident/Alert back to Normal | Modes that never clear cause alert fatigue and leave PounceAgent in permanent high-sensitivity posture | MEDIUM | `ConcentrationMonitor` only transitions upward today; needs downward path when concentration drops |
| De-escalation cooldown period | Without cooldown, pheromone noise causes rapid mode flapping between Alert and Normal | LOW | Configurable minimum dwell time after escalation before de-escalation is evaluated |
| TomAgent governance oversight with veto authority | Industry standard: destructive autonomous actions require a supervisor agent or human gate above the policy layer | HIGH | New agent in dispatcher registry; inspects pending PounceAgent decisions and can emit veto receipts |
| TomAgent produces auditable veto records | Governance oversight is only meaningful if veto decisions are as auditable as action receipts | LOW | Same receipt primitives as PounceAgent; veto record must carry the rejected action + reason |

### Differentiators (Competitive Advantage)

Features that go beyond commodity EDR and reflect the specific design philosophy of this runtime.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Pheromone-driven response triggering | Response actions are driven by accumulated multi-source signal, not single-event triggers — much harder to fool than threshold-on-one-event designs | LOW | Natural extension: PounceAgent subscribes to mode transitions published by `ConcentrationMonitor` |
| Signed response receipts with detection lineage | Chain of custody from raw telemetry through pheromone deposit through policy verdict through execution receipt is a strong audit story vs commodity EDR | MEDIUM | Requires embedding hunt_id, deposit IDs, and policy decision into receipt before signing |
| TomAgent veto as a composable first-class agent | Governance oversight modeled as an agent in the same dispatcher (not an external policy service) means it participates in the same bounded-tick, health-check, and audit lifecycle | HIGH | TomAgent must implement `SwarmAgent` trait; veto decisions land in substrate as pheromone events or receipt records |
| Mode de-escalation with configurable cooldown | Most EDR runtimes rely on manual analyst clearance; automatic de-escalation with a cooldown guard is safer and reduces analyst burden | MEDIUM | Needs de-escalation threshold (configurable below alert threshold), cooldown duration, and durable de-escalation record |
| Dry-run preview of autonomous response without code changes | Operators can validate PounceAgent behavior end-to-end (including policy evaluation) without touching adapter config or disabling the agent | LOW | Single config flag flips PounceAgent into dry-run; receipts still emitted with `mode: dry_run` marker |
| Configurable policy rules in repo-owned YAML | Policy gate behavior described in version-controlled config means policy changes are auditable, reviewable, and testable without code changes | MEDIUM | New rule schema: per-action, per-severity, per-threat-class allow/deny/require_human overrides |

### Anti-Features (Commonly Requested, Often Problematic)

Features that seem good but create safety or complexity problems in this context.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Immediate autonomous execution without governance agent | Faster time-to-contain | Blast radius risk; industry research confirms destructive autonomous actions must have a human-in-the-loop or supervisor veto path for high-severity events | TomAgent veto window on destructive actions; allow immediate execution only for safe/low-impact actions |
| Policy rules evaluated in the hot detection path | Seems like tighter coupling | Couples response policy latency to detection latency; policy evaluation is cheap but rule loading and reloading must not stall the detector | Keep policy evaluation in PounceAgent tick, separate from WhiskerAgent detection lane |
| Fully automatic de-escalation with no cooldown | Reduces mode stale time | Rapid oscillation between Alert and Normal on noisy telemetry (mode flapping); operators lose confidence in mode semantics | Mandatory cooldown config with a sensible default (e.g., 5 minutes) |
| Multi-agent quorum for veto (distributed governance) | Stronger safety guarantees | The runtime is single-node; distributed quorum requires independent trust boundaries that don't exist yet | TomAgent single-agent veto is sufficient for now; quorum governance is explicitly deferred |
| TomAgent mutating policy rules at runtime | Seems like a natural self-healing governance loop | Policy mutation by an agent without operator review is a governance regression; it breaks the operator-controlled policy model | TomAgent vetoes actions; operators edit policy rules; the agent never writes rules |
| Automatic lease renewal by PounceAgent | Prevents expiry disruption | Removes the fail-closed safety guarantee; an agent that auto-renews its own lease is effectively ungated | Leases expire and require a fresh policy evaluation; expired lease is a deliberate gate |

## Feature Dependencies

```
[Mode De-escalation]
    └──requires──> [ConcentrationMonitor downward evaluation] (existing monitor, new downward path)
    └──requires──> [De-escalation cooldown config]
    └──requires──> [Durable de-escalation record in substrate]

[PounceAgent]
    └──requires──> [Mode De-escalation] (so PounceAgent isn't permanently stuck in high-sensitivity posture)
    └──requires──> [Configurable Policy Rules] (so policy behavior can be tuned without code changes)
    └──requires──> [TomAgent] (governance veto before destructive actions execute)
    └──consumes──> [ConcentrationMonitor escalation events] (existing, already published)
    └──executes through──> [DispatchingExecutor + ApprovalGate] (existing guard pipeline)

[TomAgent]
    └──requires──> [PounceAgent] (nothing to govern without the response agent)
    └──implements──> [SwarmAgent trait] (same dispatcher contract as Whisker/Stalker/Weaver)

[Configurable Policy Rules]
    └──replaces──> [StaticApprovalGate hardcoded thresholds]
    └──requires──> [YAML rule schema in swarm-policy]

[Policy Audit Trail]
    └──enhances──> [PolicyDecision.reason] (already exists, must be surfaced in receipts)
    └──enhances──> [PounceAgent response receipts]

[Signed Response Receipts with Lineage]
    └──requires──> [PounceAgent]
    └──enhances──> [swarm-spine receipt primitives] (already exist)
```

### Dependency Notes

- **PounceAgent requires TomAgent:** Destructive action execution without a governance veto path is an industry-standard safety gap. TomAgent must be wired before PounceAgent goes live on destructive actions.
- **Mode de-escalation requires new downward evaluation in ConcentrationMonitor:** The existing monitor only transitions upward (`if target_mode > self.mode_state.current`). A parallel downward path is needed.
- **Configurable policy rules replace the static gate:** `StaticApprovalGate` should remain available as a fallback, but the new `ConfigurablePolicyGate` becomes the default production path.
- **De-escalation cooldown conflicts with immediate clearance:** The cooldown must prevent PounceAgent from downshifting posture too fast; operators should be able to override via explicit operator action, not automatic logic.

## MVP Definition

### Launch With (v1.39)

Minimum features to close the detect-to-respond loop with autonomous execution and governance.

- [x] PounceAgent — consumes mode transitions from ConcentrationMonitor, evaluates policy, executes through guard pipeline
- [x] PounceAgent dry-run mode — config flag, dry-run receipts emitted but no execution side effects
- [x] Lease expiration enforcement — fail-closed on expired `CapabilityLease` before execute()
- [x] Configurable policy rules — YAML-backed rule overrides in swarm-policy replacing hardcoded static gate
- [x] Policy audit trail — verdict reason surfaced in structured logs and response receipts
- [x] Mode de-escalation — ConcentrationMonitor downward path from Incident/Alert to Normal
- [x] De-escalation cooldown — configurable minimum dwell time, prevents mode flapping
- [x] TomAgent — governance oversight agent implementing SwarmAgent; veto window on destructive actions
- [x] TomAgent veto receipts — auditable veto record with rejected action + reason

### Add After Validation (v1.x)

- [ ] Per-threat-class policy overrides — extend configurable rules to allow different thresholds per ThreatClass (e.g., stricter rules for DataExfiltration vs. Discovery)
- [ ] PounceAgent action prioritization — when multiple escalation events are queued, execute in priority order by severity/threat-class
- [ ] Operator-initiated de-escalation override — allow operator to manually clear mode via swarmctl without waiting for cooldown

### Future Consideration (v2+)

- [ ] Multi-agent TomAgent quorum — requires independent trust boundaries and distributed node architecture
- [ ] PounceAgent adaptive response selection — select response action based on historical receipt outcomes (requires strategy memory integration)
- [ ] Policy rule hot-reload without restart — depends on file-watch integration similar to existing secret-dir reload

## Feature Prioritization Matrix

| Feature | Operator Value | Implementation Cost | Priority |
|---------|----------------|---------------------|----------|
| PounceAgent core (mode trigger -> guard -> execute) | HIGH | MEDIUM | P1 |
| PounceAgent dry-run mode | HIGH | LOW | P1 |
| Lease expiration enforcement (fail-closed) | HIGH | LOW | P1 |
| Configurable policy rules | HIGH | MEDIUM | P1 |
| Mode de-escalation + cooldown | HIGH | MEDIUM | P1 |
| TomAgent with veto authority | HIGH | HIGH | P1 |
| Policy audit trail in receipts | MEDIUM | LOW | P1 |
| TomAgent veto receipts | MEDIUM | LOW | P1 |
| Per-threat-class policy overrides | MEDIUM | MEDIUM | P2 |
| Operator-initiated de-escalation override | MEDIUM | LOW | P2 |
| PounceAgent action prioritization | LOW | MEDIUM | P3 |

**Priority key:**
- P1: Must have for v1.39 — closes the respond loop with governance
- P2: Should have, add when core is validated
- P3: Nice to have, future consideration

## Competitor Feature Analysis

Industry patterns observed from SentinelOne, CrowdStrike Falcon, Microsoft Defender XDR, and SOAR platforms (Torq, Swimlane):

| Feature | Industry Pattern | Our Approach |
|---------|-----------------|--------------|
| Autonomous response triggering | Single-event threshold or ML classifier score triggers response | Pheromone concentration from multi-source deposits — harder to spoof, requires sustained multi-agent agreement |
| Policy gate | Severity-based allow/deny rules per action type, often UI-configured | YAML-backed configurable rules in repo-owned config; same audit model as detector rulesets |
| Governance oversight | Human-in-the-loop approval gate for destructive actions; some platforms use SOAR playbook approval workflows | TomAgent — a first-class agent in the dispatcher with veto authority, same lifecycle as detection agents |
| Mode de-escalation | Analyst manually clears incident state, or timer-based auto-close | Pheromone concentration drops below threshold after cooldown period — signal-driven, not timer-driven |
| Dry-run preview | "Simulation mode" or "report-only" in most platforms, often hard to toggle without policy changes | Config flag on PounceAgent; dry-run receipts are structurally identical to live receipts |
| Audit trail | Separate audit log table or SIEM integration | Response receipts signed and linked to detection lineage (hunt_id chain); same receipt model as rest of runtime |

## Sources

- Codebase: `crates/swarm-runtime/src/escalation.rs` — ConcentrationMonitor upward-only transition logic confirmed
- Codebase: `crates/swarm-policy/src/static_gate.rs` — hardcoded `human_gate_severity` and lease TTL confirmed
- Codebase: `crates/swarm-response/src/dispatch.rs` — DispatchingExecutor guard pipeline confirmed
- Codebase: `crates/swarm-guard/src/lib.rs` — GuardResult contract confirmed
- Codebase: `crates/swarm-runtime/src/dispatcher.rs` — AgentRegistry and SwarmAgent trait contract confirmed
- Domain: [Autonomous SOC Explained — Security Boulevard](https://securityboulevard.com/2026/04/autonomous-soc-explained-how-agentic-investigation-solves-what-playbooks-couldnt/) (MEDIUM confidence — 2026 article)
- Domain: [SOAR playbook governance — IBM](https://www.ibm.com/think/topics/security-orchestration-automation-response) (MEDIUM confidence)
- Domain: [Configure automated investigation — Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/m365d-configure-auto-investigation-response) (MEDIUM confidence)
- Domain: [AI Guardrail Design — QueryPie](https://www.querypie.com/features/documentation/white-paper/28/ai-agent-guardrails-governance-2026) (MEDIUM confidence)
- Domain: [Agentic Oversight Framework — Sardine](https://go.sardine.ai/hubfs/Whitepapers/The%20Agentic%20Oversight%20Framework%20-%20Procedures,%20Accountability,%20and%20Best%20Practices%20for%20Agentic%20AI%20Use%20in%20Regulated%20Financial%20Services.pdf) (MEDIUM confidence)

---
*Feature research for: Swarm Team Six v1.39 — PounceAgent, policy hardening, mode de-escalation, TomAgent governance*
*Researched: 2026-04-08*
