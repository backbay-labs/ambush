# Ambush — Product Overview

> **Vector Swarm**: a cybersecurity agent-swarm operations environment. Turn one
> security mission into dozens of governed, parallel agents in seconds — and roll
> their ephemeral output into a durable, searchable intel vault.

---

## 1. Vision & positioning

**One line:** *Ambush is the incident-response console for agent swarms — spin up massive agentic horsepower on a dime, govern every tool call with signed receipts, and consolidate findings into a living intel wiki.*

Security work is bursty. A breach, a CTF clock, or a release-blocking review all demand
a sudden surge of focused effort, then quiet. Hiring doesn't scale that way; agents do.
Ambush treats a swarm of CLI coding/security agents like an emergency-response team you
can summon on demand: define the mission once, fan it out across many isolated lanes,
watch them work in real time, and capture everything they learn as governed, auditable
knowledge.

The single biggest value-add is **speed and scale of fan-out** — going from one objective
to many coordinated agents in seconds, and scaling that headcount up or down as the
situation changes.

---

## 2. The core problem

Security and incident-response work needs **on-demand, massive, governed agent fan-out**:

- **On-demand & massive.** When something is on fire (or a CTF timer is ticking), you want
  N agents attacking the problem from N angles *now*, not after standing up infrastructure.
  Ambush deploys a configurable swarm (the UI slider goes to 50; the orchestrator accepts
  up to 100 lanes) where each lane launches concurrently — fan-out speed is the whole point.
- **Isolated.** Parallel agents that share a working directory trample each other. Every
  Ambush agent runs in its **own git worktree + its own live terminal**, so lanes never
  collide and each one's changes are inspectable on its own branch.
- **Governed.** Letting many autonomous agents loose against a target is risky. Ambush routes
  agent tool calls against the intel vault through **Chio**, a fail-closed policy gate that
  signs every allow/deny decision into an append-only receipt log — non-repudiation for
  everything the swarm touches.
- **Durable.** Agent terminals are ephemeral. Findings are not. Every lane reports into a
  shared **OpenKnowledge** intel vault (a markdown wiki + wiki-link graph, git-synced), and a
  one-click consolidate rolls all of it into a single linked kill-chain runbook.

No existing tool combines all four. Terminal multiplexers give you parallel shells but no
knowledge layer or governance. Agent frameworks give you orchestration but not isolated
worktrees, a calm human-readable intel surface, or signed receipts. Ambush is built around
exactly that intersection.

---

## 3. Personas & jobs-to-be-done

| Persona | Job to be done | How Ambush helps |
|---|---|---|
| **Incident responder / on-call SRE** | "We're under active attack — I need many eyes on telemetry, hosts, and code *right now*, with an audit trail." | Surge a swarm against the incident, watch lanes live, and get a signed receipt log + consolidated runbook for the post-incident review. |
| **Red-teamer / pentester** | "Run recon, triage, exploit-dev, and lateral-movement lanes against this target in parallel, and keep evidence organized." | The built-in offensive playbook seeds purpose-named lanes; findings cross-link into a navigable intel graph. |
| **CTF player** | "I have hours, many challenges, and one brain. Parallelize." | Point the swarm at a CTF endpoint, fan out solver lanes, and consolidate flags + writeups as they land. |
| **Security engineer / AppSec reviewer** | "Swarm-review this codebase for vulnerabilities before release, with a paper trail of what was checked." | Point the operation at a target repo (enables worktrees), deploy review lanes, and consolidate findings into a single report. |
| **Security lead / manager** | "Prove what the agents did and didn't do." | The Receipts tab surfaces every governed tool call with verdict, tool, server, and policy hash. |

---

## 4. Primary use cases (narratives)

Each scenario follows the same arc: **Operation → deploy Vectors → intel vault → consolidate → receipts.**

### (a) Emergency-response surge

A suspicious process is beaconing out of a production host at 2 a.m. The on-call responder
opens Ambush and creates an **Operation** ("Operation Nightfall"), sets the objective
("contain and characterize the suspected compromise") and the target (the host/URL under
investigation). Standing up the operation also stands up its **intel vault** and, if `chio`
is present, its governance policy and receipt database.

They drag the swarm slider to, say, 12 and hit **Deploy**. Twelve **Vectors** launch
concurrently, each in its own worktree + live terminal, each handed a mission briefing
(`AMBUSH_MISSION.md`) and a governed intel-MCP config. As lanes work, they write findings
continuously into the shared **intel vault** as markdown, cross-linked with `[[wiki-links]]`.
The responder watches the terminals live, kills lanes that wander, and redeploys or scales
up as the picture sharpens.

When the dust settles, **Consolidate** rolls every lane's findings into a single
`RUNBOOK.md` kill-chain — a linked, evidence-backed timeline. The **Receipts** tab is the
audit record: every governed action the swarm took against the vault, signed and replayable.

### (b) CTF solve

A player creates an Operation, sets the target to the CTF endpoint (e.g.
`ctf.example:1337`), picks an agent runtime, and deploys a swarm. The default offensive
**playbook** seeds lanes — *recon, triage, exploit, lateral, persist, harden, report* —
so each Vector starts with a distinct angle on the challenge. Solver lanes drop flags,
payloads, and notes into the **intel vault** as they go, linking related discoveries so the
graph reflects the challenge structure. **Consolidate** produces a clean writeup of what
worked, and the **receipts** prove exactly which tools each lane invoked.

### (c) Security code-review swarm

An AppSec engineer creates an Operation, leaves the host/URL target blank, and points
**Target repo / working dir** at the codebase — which enables git worktrees so each lane
reviews on its own branch without conflicts. They deploy a swarm of review Vectors; lanes
hunt for injection, authz gaps, secrets, and dependency risk in parallel, each writing
findings (with severity and file references) into the **intel vault**. **Consolidate**
assembles a single linked review report; the **receipts** log documents the governed writes,
giving the team a defensible record of the review.

---

## 5. Key concepts glossary

- **Operation** — One mission/incident. Has a name, an objective, a free-form **target**
  (host, URL, or CTF endpoint), and an optional **target repo/working dir** (which enables
  git worktrees). Creating an Operation provisions its intel vault and governance.
- **Vector** — One attack/work lane, run by a single agent inside its **own git worktree +
  live terminal**. Each Vector has a codename, an objective, a status
  (`idle → deploying → running → reporting → done/failed/killed`), a branch, and a
  `findings/<id>.md` path in the vault. Lanes can be killed, redeployed, recalled, or scaled.
- **Swarm** — The set of Vectors deployed under an Operation. You choose an agent runtime and
  a count; lanes launch concurrently. Fan-out speed and scale are the core value-add.
- **Intel Vault** — The shared knowledge layer, powered by **OpenKnowledge** (a WYSIWYG
  markdown wiki + wiki-link graph + git sync), embedded as a subprocess engine. All lanes
  report here; it's where ephemeral terminal work becomes durable, searchable knowledge.
- **Receipt** — A signed, append-only record of one governed tool call, emitted by **Chio**.
  Each carries a verdict (`ALLOW`/`DENY`/`CANCELLED`/`INCOMPLETE`), the tool and server, and
  a policy hash. The Receipts tab is the swarm's audit trail; Chio is **fail-closed**, so any
  tool not explicitly allowed is denied.
- **Kill-chain Runbook** — `RUNBOOK.md`, the single consolidated artifact produced by
  **Consolidate**. It links each Vector to its findings, marks which lanes produced intel, and
  inlines the collected findings into one evidence-backed timeline.
- **Playbook** — The default offensive/IR template (`recon, triage, exploit, lateral, persist,
  harden, report`) used to auto-name and seed Vector objectives when the operator doesn't
  supply explicit ones. Lanes beyond the seven cycle back through the list.
- **Agent profile** — A CLI runtime a Vector can run: **Claude Code**, **Codex**, **Cursor
  Agent**, **OpenCode**, **Hermes**, or **Shell (manual)** (the default — works with no agent
  installed, so the swarm mechanism is demonstrable out of the box). Like Orca, "if it runs in
  a terminal, it runs in a Vector."

---

## 6. Differentiation

Ambush deliberately fuses three lineages into one security-shaped tool:

- **Orca's parallel-agent power** — the worktree-per-agent isolation model, live PTY
  terminals, and "any CLI agent" runtime flexibility. This is what makes massive, non-colliding
  fan-out cheap and fast.
- **OpenKnowledge's calm intel layer** — a human-readable markdown wiki + graph that turns a
  flurry of agent output into durable, navigable, git-synced knowledge instead of scrollback
  you lose when the terminal closes.
- **Chio's governance** — fail-closed policy enforcement with signed, append-only receipts on
  every tool call against the vault.

**Why "governed swarm + durable intel" matters specifically for security:** offensive and
incident-response work is exactly where ungoverned autonomy is most dangerous and where an
audit trail is most valuable. Ambush lets you scale aggressive parallel effort *and* keep
non-repudiation and a coherent knowledge record — power without losing control or losing the
plot. Most agent tools optimize for one of those; Ambush is built for the intersection.

---

## 7. Non-goals / scope boundaries (v0)

What Ambush v0 intentionally does **not** try to be:

- **Not a hosted/cloud service.** It's a local desktop control plane; swarms run on the
  operator's machine.
- **Not an agent model or a new CLI agent.** Ambush orchestrates existing CLI agents; it
  doesn't ship its own model.
- **Not a hard sandbox.** Worktrees isolate working state and Chio governs *intel-vault* tool
  calls, but agents otherwise run with the operator's environment. Treat the swarm as you would
  any powerful local automation.
- **Governance covers the intel MCP, not the whole agent.** Chio currently governs tool calls
  against the OpenKnowledge intel server. Arbitrary shell/agent actions outside that path are
  not receipt-logged.
- **Graceful degradation, not hard requirements.** If `ok` (OpenKnowledge) or `chio` are
  absent, agents still run and findings are written as plain markdown — the swarm just runs
  ungoverned and the wiki is a folder instead of a live UI.
- **The Rust engine is not yet wired into the control plane.** See below.

### The engine (planned convergence)

Under `engine/` lives a separate **Rust detection + live-response engine** (originally
*Swarm Team Six / ClawdStrike Ambush*, Apache-2.0): ingest telemetry → detect (whisker) →
pheromone state → fail-closed policy gate → capability-scoped response → signed receipt chain.
It shares Ambush's philosophy — **fan-out + fail-closed governance + signed receipts** — and
is intended to converge so the desktop app becomes the operator surface for the engine's
detections and responses. **Today the two halves are independent**: the engine is its own
Cargo workspace, and the control plane does not yet drive it. Treat engine integration as
roadmap, not shipped behavior.

---

## 8. Success metrics

Metrics that reflect Ambush's value proposition — fast, scalable, governed, durable swarms:

- **Time-to-N-agents.** Seconds from **Deploy** to N Vectors `running`. Fan-out latency is the
  headline metric; lanes launch concurrently by design.
- **Max concurrent Vectors** sustained per Operation (UI allows up to 50; orchestrator up to
  100), and how cleanly the swarm scales up/down via scale/recall.
- **% of findings consolidated.** Share of Vectors that produced a non-empty findings file and
  made it into `RUNBOOK.md` (the consolidate step marks ✅ vs · per lane).
- **% of governed tool calls with receipts.** When `chio` is present, the fraction of intel-vault
  tool calls that produced a signed receipt — ideally 100% (fail-closed) — plus the allow/deny
  ratio as a signal of how well the policy is scoped.
- **Intel-graph connectivity.** Density of `[[wiki-links]]` between findings — a proxy for how
  navigable and reusable the captured knowledge is, vs. a pile of disconnected notes.
- **Mission throughput.** For bounded tasks (CTF, review): flags captured / vulnerabilities
  confirmed per unit of wall-clock time across the swarm.

---

*Status: v0, runnable. The swarm mechanism (worktree fan-out, PTY terminals, mission
briefings, consolidation), the OpenKnowledge engine embedding, and the Chio governance wrapper
are wired end-to-end with graceful degradation when external binaries are absent.*
