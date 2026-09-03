# Perch — the plan set

**What this is.** A complete, cited design for **Perch**, Ambush's operator console: eleven
documents that take `block/buzz` — a mature Nostr-relay-backed workspace where humans and agents
are the same kind of participant — and re-point it at Ambush's autonomous threat-hunting swarm.
It was produced by a panel writing in parallel from one brief, attacked by four red-team critics
(feasibility, product, security, coherence), revised against every blocking finding, and then
reconciled end to end. Nothing in either repository was modified; this directory is the only
output.

**The pitch, in one paragraph.** Ambush already decides, acts, and proves. What it cannot do is
*receive an answer from a human*. Its tuning engine ranks detector-threshold and host-exclusion
recommendations from analyst verdicts it has no door to accept —
`build_alert_tuning_report` is shipped and real, its only writers are two HMAC webhooks, and the
operator surface's 49 routes include none that takes feedback. Buzz has the mirror-image hole: a
finished two-pane triage queue whose needs-action lane is hardwired to an event kind nothing in
the codebase can emit, and an approval card whose shipped body reads *"Approval actions are not
yet available in Desktop."* Perch is the graft. It is the Buzz desktop app, re-skinned and cut by
a third, organized around the one thing an analyst does most: look at what the swarm surfaced,
decide, and move on — where the decision is typed, signed, recorded against a case, and by Friday
is why a detector got retuned.

---

## The documents

| # | File | What it settles | Read it if you are… |
|---|---|---|---|
| **00** | [`00-BRIEF.md`](00-BRIEF.md) | The constitution: the product, the fourteen-surface list, the integration commitment, the seven render laws, the four mechanized risks, the non-goals, twelve open questions — and **§13, the ten amendments ratified after the nine documents were written.** | Everyone, first. Then §13 before citing anything. |
| **A** | [`APPENDIX-NORMATIVE.md`](APPENDIX-NORMATIVE.md) | The registry: route table, key map, marker/kind/tag registry, the hold→human path, backend-bill labels, shared constants, verified counts, vocabulary. **Values live here once; documents cite it.** | Everyone, second. Anyone about to restate a number. |
| **01** | [`01-POSITIONING.md`](01-POSITIONING.md) | The category, the user, the wedge, the pitch and demo, the adoption arc, and the six-objection counter-case with a falsification table. | Deciding whether to fund it. Anyone writing external copy. |
| **02** | [`02-ARCHITECTURE-INTEGRATION.md`](02-ARCHITECTURE-INTEGRATION.md) | Three repos, the crate-by-crate and directory-by-directory keep/delete verdict, the new bridge crate, CI and licensing reconciliation, the eleven-step Monday sequence. | The engineer who will cut the fork. |
| **03** | [`03-DOMAIN-EVENT-MAPPING.md`](03-DOMAIN-EVENT-MAPPING.md) | The wire: every Ambush object → a `kind:9` marker card, `kind:46010`, an ephemeral, or daemon-HTTP-only; the two identity chains; subscription filters; what the runtime must grow. | Anyone touching an event, a filter, or a signature claim. |
| **04** | [`04-SURFACES-AND-UX.md`](04-SURFACES-AND-UX.md) | All fourteen surfaces: job, objects, layout, every state, what each refuses to do. Owns the **route table** and the **key map**. Walks a full shift and three flows. | Building or drawing any screen. |
| **05** | [`05-DESIGN-SYSTEM.md`](05-DESIGN-SYSTEM.md) | Palette (measured contrast, ink/mark split), the security-semantic ramps, type, motion, icons, the hand-authored chart language, the 119-file component inventory. | The designer. The engineer picking a token. |
| **06** | [`06-COPY-AND-VOICE.md`](06-COPY-AND-VOICE.md) | Six voice laws, the noun and verb glossaries, and the microcopy library written out in full, paste-ready — including the destructive-approval pane, which is specified as a safety control. | Writing any string. Reviewing any string. |
| **07** | [`07-REALTIME-AND-DATA.md`](07-REALTIME-AND-DATA.md) | Every hop from telemetry to pixel with its rate ceiling, coalescing rule, loss policy and latency budget; the spool; the four streams; two clock domains; retention; perf budgets. | The bridge author. Anyone debugging "why is this stale". |
| **08** | [`08-TRUST-AND-GOVERNANCE-UX.md`](08-TRUST-AND-GOVERNANCE-UX.md) | The moment a human says yes: what is *actually* enforced and by whom, the action matrix, the verdict pane's fixed order, asymmetric friction, lease UX, verification tiers, the export bundle, ten ways a console weakens a fail-closed system, and **35 invariants written as tests**. | Everyone building the verdict path. The security reviewer. |
| **09** | [`09-ROADMAP-AND-RISKS.md`](09-ROADMAP-AND-RISKS.md) | Four phases + a background deletion track, 95 engineer-weeks bottom-up, the **eleven-item backend bill** (normative), three kill criteria with numbers, a 25-row risk register, the decision log, success metrics. | Planning, staffing, or deciding to stop. |

---

## Settled, at a glance

**The product.** A shift-shaped verdict queue where every human decision is a typed act that
becomes the swarm's next tuning input and the quarter's audit artifact.

**The integration.** The Buzz relay stays as the read / subscribe / search substrate.
`swarm_detect --serve` remains the *only* writer of Ambush state. Perch is the Buzz Tauri app,
re-skinned. **The relay fork is two match arms**, both for kind `46010`, and it is offered
upstream as a genuine bug fix. Durable evidence rides `kind:9` with seven versioned marker
comments, so it degrades honestly in the Flutter app, the web client, the CLI and a search
snippet, at zero cost to three hand-synced kind registries. Live telemetry rides ephemeral
`26000`–`26006`. One new Ambush crate, `swarm-perch-bridge`, subscribes **in-process** to
`RuntimeEvent`, spools to disk before any network I/O, and publishes over a WebSocket.

**The safety spine.** Writes are two-legged and never conflated: leg 1 is a signed human *intent*
card on the relay; leg 2 posts the decision to the daemon, which re-evaluates policy and
governance from scratch and mints the capability lease at **decision** time (its TTL is 60
seconds — a hold-time lease is dead before a human reads the page). **Perch never authorizes**,
and that is guaranteed by a process boundary, not a convention.

**What the console refuses to say.** No shield. No bare source count. No quorum fraction. No
uniform Undo. No "everything looks good". No claim of an Ed25519 signature over an artifact that
carries none — four of the seven card types carry none, so verification renders a *tier*, and
the "verify" affordance on a tier-0 card re-fetches from the daemon rather than checking a
signature that is not there.

**Fourteen surfaces, eleven routes, closed.** Adding one requires deleting one.

**The bill.** Eleven Ambush backend items (`APPENDIX-NORMATIVE.md` §5), of which the daemon-side
hold store is the largest and gates everything: `RequireHuman` is a *refusal* today, not a queue.
95 engineer-weeks total, 19 of them serial Rust through one engineer — which is 59% of the
calendar on one person and the plan's strongest argument for a second Rust hire.

**The art direction.** Decided: Quiet, with Night Bridge's guarded throw for the grant control
— [`build/art/DECISION.md`](build/art/DECISION.md).

---

## Still open

The brief's twelve open questions each carry a recommended default and a trigger to revisit
(`00-BRIEF.md` §10). The four that actually decide the schedule:

1. **Does the hold store land before the console?** Default: yes, and never ship a demo implying
   a working gate. If it slips a milestone, ship `/watch-floor` + `/ledger` + `/gaps` as v0 with
   the queue visibly labelled *not yet wired*.
2. **Where does the case-promotion bar sit?** Default: a held destructive action, **or** a
   correlated incident with ≥2 members, **or** an analyst promoting by hand — as config, with a
   promoted/suppressed counter on `/` from day one. This is now on the critical path of the
   *thesis*, not adjacent to it: a verdict has nowhere to live until a finding belongs to an
   incident record.
3. **One Rust engineer or two?** Default: one, with the nineteen-serial-week consequence stated
   out loud rather than discovered in month four.
4. **Does `B6` (signing the facts before they leave the daemon) land before the first external
   demo?** Default: after. Tier 0 is a *rendered honest state*, so a tier-0 demo is showable — as
   long as the badge says so.

---

## Start here

**If you are about to build it.** `00-BRIEF.md` §1–§4 and §13 → `APPENDIX-NORMATIVE.md` (all of
it; it is the registry you will otherwise re-derive wrong) → `02` §14, the Monday sequence →
`09` §2–§3, Phases 0 and 1 with the backend bill → `03` §5 and §11, the hold end to end → `08`
§0 and §9, what is actually enforced and the 35 invariants. Then `04` for the surface you are
building. **Do not start any surface before `AppShell.tsx` and `MessageRow.tsx` are split** —
they are at 997 and 998 lines against a hard 1000-line CI cap, and the marker renderer registry
has to come out of `MessageRow` before the first evidence card exists.

**If you are about to draw it.** `01` §1 and §10, the category and the brand continuity rules →
`05` in full, which is the design system and carries measured contrast for every token →
`04` §2, every surface's layout and states → `06` §5, the microcopy library, because in this
product the strings *are* the design → `08` §3.3 and §6.2, the verdict pane's fixed field order
and the verification tiers, which are the two places where a visual decision is a safety
decision. Note what does not exist yet: `05` §12 describes three hero screens in prose, and
nobody has drawn them.

**If you are deciding whether to fund it.** `01` in full — it is written to be read alone, it
states the three things that are *not* true yet before it states anything that is, and §9 is an
honest counter-case with a falsification table. Then `09` §6 (the sizing assumptions, stated so
they can be argued with), §8 (three written kill criteria with numbers), and §13 (success
metrics, including the one that would prove the whole thesis wrong: the fraction of Friday's
tuning recommendations sourced from this week's own human verdicts). If that number stays near
zero after a month of real use, the thesis is wrong and this plan says so in advance.

---

## How to use this set without breaking it

- **Cite the appendix, do not restate it.** Five things crossed all nine documents — the route
  table, the key map, the marker registry, the shared constants, and the path by which a hold
  reaches a human — and each was independently re-decided in three or four places. That is what
  produced a keymap specified two incompatible ways and a safety invariant written against the
  banned key. `APPENDIX-NORMATIVE.md` is the fix; keeping it the fix requires discipline.
- **Changing the appendix is a brief amendment** under `00-BRIEF.md` §12, recorded in §13.
- **Citations answer three questions or they do not count.** The red team's systemic finding was
  that this set verified that *names exist* and was credulous about *behaviour*. Every load-bearing
  `path:line` must say, in the same sentence: **who calls this, what process is it in, and what
  does it do to the data** — and where the answer is "nothing", "a different one", or "less than
  claimed", it says so beside the citation. `02` §0, `03` §How-to-read, `05` §13, `06` §7.4 and
  `08` §0 each carry the pass they ran.
- **Where a document still carries a `path:line` pointer into a *sibling document*, distrust it.**
  Those were written before the reconciliation pass and the line numbers have moved. Section
  references are reliable; line references into siblings are not.
