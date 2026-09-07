# The window walk — the console on a real window, against the live stack

**Recorded:** 2026-09-06/07, on `main` at `97adf18b6` (fixes) with the daemon built from
`9537971f3` and the desktop from the same tree, launched with `just fresh=1 desktop-standalone`
(the recipe fix `e5bf15a86`/`6fa7a607b` was needed to launch at all). **Driver:** a human-shaped
one — Orca's accessibility tree and screenshots over the real Tauri window, every click and key
sent as a person sends them. This is the seam `walking-skeleton.md` named and left: the React
tree on a real WebKit view, above the commands that record drove headless.

Every claim names the id that produced it. A row marked *found* is a defect this walk surfaced;
the fixes it took are named where they landed, and the rest are `16-PLAN-WINDOW-WALK.md`.

## Stack

| Component | Detail |
|---|---|
| Relay | `ambush-relay` from the hold-watch worktree build, `ws://localhost:3000`, Postgres 14 on 127.0.0.1:5433, Redis 6380, community "Local Dev" |
| Daemon | `target/debug/swarm_detect` from `main`, `rulesets-dev/perch-window-dev.yaml` — a local copy of `perch-hold-dev.yaml` with this console's verdict key pinned (see "the key" below), debug-signed with `sign_dev_ruleset`, binary attested with `attest_debug_binary`; state carried over from the hold-watch daemon (`data/perch-hold-dev`, `rulesets-dev/data`); spool `/tmp/ambush-perch-dev` |
| Desktop | `ambush-desktop` dev build, identity restored from the dev operator nsec (`sha256("ambush-perch-dev-operator-v1")`), community reconnected through "Reconnect to Ambush Relay ws://localhost:3000", Operator console preview switched on in Settings → Experiments |

## What a person did, and what happened

| Step | Evidence |
|---|---|
| onboarding | "Use an existing key" → the nsec → harnesses detected (Claude Code, Codex, Ambush READY) → model settings skipped → "Reconnect to Ambush Relay ws://localhost:3000" → username `console` → starter team → workspace. Screenshot `1db7f8bb` |
| the operator's channels | the sidebar lists the twelve `lane-*` channels and every case channel the bridge added the operator to (nineteen from the earlier runs, then the two this walk raised) |
| the key | Settings → Detector shows the verdict key this console minted, `973b6e1adfc6a4a0dee3b9d1c494141bed8bb269fedea9319d8310036596508b` (key id `35404bac…`), and says to pin it in `verdict_public_key_hex`. Pinned in the local profile; daemon restarted 00:24:49Z. The committed dev profiles keep the headless driver's key on purpose |
| The Watch | after the restart: Holds 21, one open (`hold_39a64f32…`, raised at daemon boot, see found-4), Named you 1, counters `divergences 0 · unadmitted frames 1 · open holds 1`. Screenshot `4e26dfbe` |
| `#lane-execution` | finding cards from real evidence — agent `swarm:ed25519:07d21ffc…`, execution, CRITICAL, confidence 0.90, host `host-ops-1-r28362` marked ADVERSARY-CONTROLLED, the evidence JSON behind "show all 660 characters" — with the `E PROMOTE / C / D / I` row and "Promote this finding to a case first"; signer `c194c360…ce8e` is the ingest identity and admitted. Screenshot `97a9b5cc` |
| a new hold | ingest of `walk-d82c41-{1,2}` on `host-walk-d82c41` at 00:27:41Z (`/v1/ingest/events` → accepted ×2) → `hold_e826b510-0e10-49c0-9af9-dfbd2e51bcdb`, `notified`, case `0091f282-da1f-4c2e-b9fa-59b0a57761e1`, the case channel in the sidebar within seconds |
| the verdict pane | the Watch row opens the pane: ACTION `isolate_host` / `host_id host-ops-1` (adversary-controlled), BLAST RADIUS `host_connectivity_isolated` · scope `host: host-ops-1` · max affected scopes 1 · capabilities `network_connectivity, remote_management` · "served by the runtime's rehearsal preview", IF YOU UNDO `RestoreHostConnectivity` executable inverse, WHY WE ARE ASKING `static.human_gate` · "authorized but held for human approval", WHAT GRANTING OPENS capability lease "minted at your decision, not now · 60 s" then a containment lease "on the lease board · 15 min", the grant control with the dwell at 100 %, Refuse `R · nothing is dispatched, and there is no undo`. Screenshot `43e4f5d2` |
| **grant, leg 1 and 2** | `G` → "ARMED — PRESS ENTER TO RECORD" → `Enter`. The daemon's record afterwards: `state executed`, decision `grant`, operator `console`, voter `swarm:ed25519:973b6e1a…`, signature key id `35404bac…` (this console's key), `governance_clearance receipt_signature_ok`, `decided_at_ms 1788741336782`, `nostr_intent_event_id d6395437ae52c908617cddb07e807ea7fa33742156ceb103789374455df36f9a` (leg 1's card), `outcome granted_executed`, `dispatched true`, receipt `resp:walk-d82c41-2:lease:walk-d82c41-2:isolate_host:1788741336782`; daemon log 00:35:36.787Z `containment leased`, lease `containment:walk-d82c41-2:isolate_host:resp:…:1788741336782`, `GET /v1/operator/containment/leases` lists it open with the blast radius and the rollback plan. That is The hold's exit narrative, driven by a person |
| **refuse, on the boot-raised hold** | `R` on `hold_39a64f32…` → leg 1 refused: "the intent card could not be published: TauriInvokeError: this hold has no case channel"; the daemon record still `notified`, `case_channel null`, no intent. Found-6 and found-14 |

## Found by this walk

1. **The governance strip renders its templates raw** — `bridge: down (last envelope {lastSeen})` on every surface; `{ago}`, `{n}`, `{unauthorized}` would render the same. `GovernanceStrip.tsx` renders `COPY[mode]` verbatim. → `16-PLAN-WINDOW-WALK.md` Task 2.
2. **The console never opens three of its seven REQs.** `perchLaneMovement.ts::desiredSpecs` hard-codes `telemetryWanted: false, activeCaseIds: [], openCaseId: null`, so the telemetry, case-activity and case-live subscriptions are never sent; the strip and the Watchfloor are starved by construction, and a case timeline does not update live. Measured: an authenticated subscriber on the same relay received 26000 ×11 and 26001 ×11 in twelve seconds from the telemetry identity `3cd72748…`. → Task 1.
3. **No 26004 governance-status frame exists.** The bridge publishes 26000 and 26001 (26002/26003/26005 on their triggers); there is no `RuntimeEvent::GovernanceStatus` and no producer for the frame the strip keys on, so even with found-2 fixed the strip could never read healthy. → Task 3.
4. **A daemon restart on the durable substrate re-raises an escalation and mints a hold** for evidence the previous daemon already held: at boot (00:24:49.6Z) the journal replay re-crossed the execution threshold for `hunt-evt-2-r28362`, `static.human_gate` held `isolate_host` again as `hold_39a64f32…`, and "pheromone concentration crossed escalation threshold" then logged every 100 ms (1,572 lines in the first eight minutes). → Task 6 (the flood) and a decision row (the re-raise).
5. **The console mints its own verdict key and the operator pins it** — works as designed, and the walk shows the flow end to end. Not a defect; recorded because the committed dev profiles cannot serve a real window without this step.
6. **A hold whose case channel already existed never learns it.** `hold_39a64f32…` was filed (notified, card and notice on the relay) into a case channel, yet the daemon record keeps `case_channel: null`, and leg 1 refuses on exactly that field. `HoldPublisher::plan_open` re-asserts membership only, and `on_ok(AddMember)` never calls `mark_case_channel`. → Task 5.
7. *(folded into 6)*
8. **A case channel opened from the sidebar is not a case.** Clicking `case-0091f282` in the sidebar renders the channel view, and the hold card refuses: "A hold card arrived on a surface that does not hold them ( lane ). It is not rendered here." W3-5 makes `/cases/$caseId` the only case surface; the sidebar should take a `case-*` channel there. → Task 4.
9. *(dev tooling)* `just fresh=1 desktop-standalone` refused to run in the main checkout — fixed (`e5bf15a86`, `6fa7a607b`).
10. **After a decision the pane loses its subject.** Within seconds of the grant the hold left the open list and the pane read "The daemon has no record of this hold, so there is nothing to decide here." The daemon has the record (`executed`); the pane should carry `sending → recorded → acknowledged` and the outcome, per `01-DESIGN.md` §5. → Task 4.
11. **Decided holds past their TTL rendered as "EXPIRED — NO ACTION WAS TAKEN".** Six executed and fourteen refused holds from the earlier runs read that way beside the one open hold: the clock test ran before the open-state test in `holdRows.ts`. **Fixed** in `97adf18b6` with a test that pins it.
12. **The Containments board rendered "No open containments" against a daemon holding a host.** Its parser read `leases` and flat fields the E2E mock had invented; `GET /v1/operator/containment/leases` serves `open_leases[{lease, remaining_ms, expired}]` with the action kind at `lease.action.type` and the scope at `lease.blast_radius.scope_value`. **Fixed** in `97adf18b6`: parser, mock and spec follow the daemon, and the captured answer is `src/testing/perch/daemonContainmentFixture.json`.
13. **The tuning bench's E2E fixture was one hour behind Monday.** Its "this week" verdict was stamped `now − 1 h`, which in the first hour of a Monday UTC is last week; the first hosted run on the landed `main` (00:16Z on 2026-09-07) failed exactly there. **Fixed** in `97adf18b6`: `weekStartMs` is one shared definition and the fixture never stamps a verdict before the week began.
14. **A failed leg 1 renders as recorded.** The refusal above read "Your decision is recorded on the case. The daemon did not answer, so this console … the intent card could not be published: …" — three claims, two of them false (nothing was recorded, and the daemon was never asked). → Task 4.

## What this walk did not do

- The two-console conflict (a second console racing this one) and the `superseded` card were not driven here; the headless record drove them.
- The finding path (`E` then `D` on a real window) was not driven; the lane rendered the cards and their controls, and the headless record drove the commands.
- `refused_late`, `expired` during the session, and a daemon crash between compare-and-set and the outcome write were not driven (W3-35 stands).
- Screenshots are Orca captures on the authoring machine (`/var/folders/…/orca-computer-use/<id>-screenshot.png`), cited by id above; they are not committed.
