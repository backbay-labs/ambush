# Wave 3 — the integration: decided, reconciled, and planned to the task

**What this is.** Waves 1 and 2 (`../` and `../build/`) designed **Perch**, an operator console
for the swarm engine, as a hard fork of the Buzz desktop app. Between their writing and
2026-09-02 the chat app was renamed Ambush in place, both repositories came to share one name,
and the project owner decided to build the console *inside* the whole Ambush workspace and to
merge the two repositories. This directory is the plan from that point on. It **cites** the
first two waves and **supersedes** them only where `00-DECISIONS.md` says so.

**The rule.** `00-DECISIONS.md` wins over `../build/00-REGISTRY.md`, which wins over
`../APPENDIX-NORMATIVE.md`, which wins over any prose document. Anything none of them mention
stands as wave 1 wrote it.

## Reading order

| # | File | What it settles | Read it if you are… |
|---|---|---|---|
| **00** | [`00-DECISIONS.md`](00-DECISIONS.md) | The four decisions of 2026-09-02 (naming, one repository, whole workspace, runtime mode), the amendment rows they force, and the integrator rulings on wave 2's internal contradictions | everyone, first |
| **01** | [`01-DESIGN.md`](01-DESIGN.md) | The design as it now stands in one repository: layout, processes, the wire, the two-legged write, the safety spine, error handling, testing — with the deltas from wave 1/2 called out | anyone about to build |
| **10** | [`10-PLAN-MIGRATION.md`](10-PLAN-MIGRATION.md) | The repository merge, task by task: history rewrite, second Cargo workspace, ignore rules, CI and hook re-rooting, verification | the person doing it today |
| **11** | [`11-PLAN-GROUND.md`](11-PLAN-GROUND.md) | Ground: the rename, the three file splits, the relay patches re-landed, the CSP pin and sign gate, the dev compose, the operator `nostr_pubkey` | the first engineering milestone |
| **12** | [`12-PLAN-FIRST-CARD.md`](12-PLAN-FIRST-CARD.md) | First card: the bridge crate, one finding card across the seam, promote, dismiss, and the tuning report moving | the walking skeleton |
| **13** | [`13-PLAN-THE-HOLD.md`](13-PLAN-THE-HOLD.md) | The hold: the daemon-side hold store and decide route, the 46010 row and 26006 alarm, The Watch and the verdict pane, the two-legged write | the product's central artifact |
| **14** | [`14-PLAN-OPERATOR-COMPLETE.md`](14-PLAN-OPERATOR-COMPLETE.md) | Operator-complete: leases, ledger and export, tuning bench, gaps, governance strip, handoff, deposits read, signed envelopes | the remaining surfaces |
| **20** | [`20-ROADMAP.md`](20-ROADMAP.md) | Sequencing, the two parallel tracks and where they join, exit criteria per milestone, the surviving kill criteria and success metrics, the re-sizing | planning or staffing |

## How the three waves relate

| | wave 1 (`../`) | wave 2 (`../build/`) | wave 3 (this directory) |
|---|---|---|---|
| Answers | what Perch is, and why | what to type, in what order | what changed on 2026-09-02, and the plan from here |
| Authority | `00-BRIEF.md` + `APPENDIX-NORMATIVE.md` | `00-REGISTRY.md` | `00-DECISIONS.md` |
| Names | engine = "Ambush", chat = "Buzz" | same | engine crates keep `swarm-*`; the product is Ambush; markers are `swarm:*`; the feature area is `perch` |
| Paths | `BUZZ ` = block/buzz, unprefixed = this repo | same | `workspace/` = the former chat repo, unprefixed = engine root |

## The one rule, restated

The console never authorizes. A human decision is two legs — a signed intent card on the relay
and a separate POST to the daemon, which re-derives authority from scratch — and that is
guaranteed by a process boundary, not a convention (ADR 0014). Nothing in wave 3 touches it.
