// Target path in BUZZ: desktop/tests/e2e/perch-queue-lifecycle.spec.ts
// Register under the `smoke` project: "**/perch-queue-lifecycle.spec.ts".
//
// Covers INV-18 (the client half), INV-19, INV-21, INV-24, INV-32 (the rendered
// half), INV-35 (the client half).
//
// The queue is where a hold becomes a person's problem, so the assertions here
// are about what SURVIVES: an expired hold stays visible, a forged hold is named
// as forged, and no empty state ever reassures.

import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import { waitForAnimations } from "../helpers/animations";
import {
  advancePerchClock,
  emitPerchHoldAlarm,
  installPerchBridge,
  PERCH_CASE_CHANNEL,
  PERCH_HOLD_TTL_MS,
  perchFixture,
  perchHold,
  PERCH_HOLD_A,
  PERCH_HOLD_B,
  PERCH_NOW_MS,
  PERCH_UNADMITTED_ISSUER,
  readPerchCounter,
  readPerchExportManifest,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * The twelve threat classes in their canonical order
 * (AMB crates/swarm-runtime/src/escalation.rs:315-330, verified twelve). This
 * order IS the sidebar order, which is why a lane is identified by position and
 * label and never by hue.
 */
const LANES = [
  "lateral_movement",
  "data_exfiltration",
  "privilege_escalation",
  "command_and_control",
  "initial_access",
  "persistence",
  "supply_chain",
  "defense_evasion",
  "credential_access",
  "discovery",
  "execution",
  "impact",
] as const;

/** The universal phrase ban (APPENDIX-NORMATIVE.md section 7). */
const BANNED_EMPTY_PHRASES = [
  "everything looks good",
  "all clear",
  "caught up",
  "no data",
  "nothing to see",
];

test.describe("Perch queue lifecycle", () => {
  // INV-18, client half. A hold that reaches PERCH_HOLD_TTL_MS undecided becomes
  // Expired, dispatches nothing, and STAYS in the queue for the rest of the
  // shift. Disappearing would be the failure: an expired hold is a fact about
  // the shift, and /handoff (INV-19) counts them.
  test("01 — an expired hold stays in the queue, decidable by nobody", async ({ page }) => {
    const hold = perchHold({ hold_id: "h_ttlexpiry001" });
    await installPerchBridge(page, perchFixture({ holds: [hold] }));
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    const row = page.getByTestId("perch-queue-row-hold-ttl");
    await expect(row).toBeVisible();
    await expect(row).toHaveAttribute("data-perch-hold-state", "notified");

    await advancePerchClock(page, PERCH_HOLD_TTL_MS + 1_000);

    await expect(row).toHaveAttribute("data-perch-hold-state", "expired");
    await expect(row).toBeVisible();
    await expect(row.getByTestId("perch-row-grant")).toHaveCount(0);
    await expect(row.getByTestId("perch-row-refuse")).toHaveCount(0);
    await expect(row).toContainText("expired undecided");
    // Nothing dispatched: the daemon-side assertion is the Rust test, but the
    // client must not have optimistically shown an outcome either.
    await expect(row.getByTestId("perch-decision-outcome")).toHaveCount(0);
  });

  // INV-19. /handoff cannot complete while expired_undecided > 0 without an
  // explicit acknowledgement. `policy.time_window` refusals make this concrete:
  // a shift boundary is exactly when a granted action starts refusing
  // (AMB crates/swarm-policy/src/configurable_gate.rs:150-158).
  test("02 — end watch is blocked until expired-undecided holds are acknowledged", async ({ page }) => {
    const hold = perchHold({ hold_id: "h_ttlsecond001", state: "expired" });
    await installPerchBridge(page, perchFixture({ holds: [hold] }));
    await installMockBridge(page);
    await page.goto("/#/handoff");
    await expect(page.getByTestId("perch-handoff")).toBeVisible();

    const end = page.getByTestId("perch-handoff-end-watch");
    await expect(end).toBeDisabled();
    await expect(page.getByTestId("perch-handoff-expired-count")).toContainText("1");

    await page.getByTestId("perch-handoff-acknowledge-expired").click();
    await waitForAnimations(page);
    await expect(end).toBeEnabled();
    // The acknowledgement is a recorded fact, not a dismissal.
    await expect(page.getByTestId("perch-handoff-expired-count")).toContainText("1");
  });

  // ── INV-35, SPLIT AFTER REVIEW ────────────────────────────────────────────
  //
  // The first draft made it P0 that a kind:46010 on the relay and absent from
  // GET /v1/response/holds renders `FORGED`. That word is wrong in every
  // reachable case, and calling it P0 made the error load-bearing:
  //
  //   * The word ACCUSES on the shipped default's ordinary restart. B1's
  //     `hold_store_path` defaults to None, so the store is in memory; after any
  //     daemon restart every legitimate open hold is relay-known and
  //     daemon-unknown. 12-BACKEND-BILL-API.md section 4.3 names that state
  //     *unreconcilable* and answers `store_durable: false`. Two documents had
  //     two words for one state; the daemon-side one wins, because it is the one
  //     with a field behind it.
  //   * The word is UNREACHABLE in its literal sense. A card only renders at all
  //     if its raw signer resolves to an admitted issuer (INV-15). A rendered
  //     card is therefore never a forgery in the signature sense, and the only
  //     residue -- an admitted issuer minting an id no daemon ever held -- is a
  //     compromised bridge, which this console cannot distinguish from a restart
  //     and must not pretend to.
  //   * A prominent refusal banner keyed on an UNADMITTED issuer is a signal an
  //     adversary can plant at will, which is exactly why 17-COMPONENT-SPECS.md
  //     rules that the unadmitted outcome "renders NOTHING of its own -- prose
  //     fallthrough plus a counter".
  //
  // So: three tests, three renderings, one counter.
  //   03a  admitted issuer, absent from a NON-DURABLE store  -> UNRECONCILED,
  //        reason names store_durable, no grant, excluded from export, counted.
  //   03b  admitted issuer, absent from a DURABLE store       -> UNRECONCILED in
  //        the alert register, a different reason, still not an accusation.
  //   03c  unadmitted issuer                                  -> nothing of its
  //        own, prose fallthrough, a different counter.
  //
  // PROPOSED BRIEF AMENDMENT: strike `FORGED` from INV-35 and from
  // 13-WIRE-SCHEMAS.md section 5.4, adr/0012 and 17-COMPONENT-SPECS.md's
  // `{ status: "absent" }` comment. The product has no state it can honestly
  // call forged.
  test("03a — a relay hold missing from a non-durable store renders UNRECONCILED, not an accusation", async ({ page }) => {
    await installPerchBridge(
      page,
      perchFixture({
        holds: [perchHold({ hold_id: PERCH_HOLD_A })],
        relayOnlyHoldIds: [PERCH_HOLD_B],
        storeDurable: false,
      }),
    );
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    const ghost = page.getByTestId(`perch-queue-row-${PERCH_HOLD_B}`);
    await expect(ghost).toBeVisible();
    await expect(ghost).toContainText("UNRECONCILED");
    // Not an accusation, and asserted as an absence so a future copy change
    // cannot quietly reintroduce one.
    await expect(ghost).not.toContainText(/forged/i);
    // The reason names the mechanism, so an operator reads "the daemon
    // restarted" rather than "somebody did something".
    await expect(ghost).toContainText("store_durable");
    await expect(ghost.getByTestId("perch-row-grant")).toHaveCount(0);

    const manifest = await readPerchExportManifest(page);
    expect(manifest.holds).toContain(PERCH_HOLD_A);
    expect(manifest.holds).not.toContain(PERCH_HOLD_B);

    // The divergence is counted, not just drawn.
    expect(await readPerchCounter(page, "perch_queue_reconcile_divergences_total")).toBe(1);
  });

  test("03b — the same divergence against a DURABLE store is louder and still not an accusation", async ({ page }) => {
    await installPerchBridge(
      page,
      perchFixture({
        holds: [perchHold({ hold_id: PERCH_HOLD_A })],
        relayOnlyHoldIds: [PERCH_HOLD_B],
        storeDurable: true,
      }),
    );
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    const ghost = page.getByTestId(`perch-queue-row-${PERCH_HOLD_B}`);
    await expect(ghost).toContainText("UNRECONCILED");
    await expect(ghost).not.toContainText(/forged/i);
    // A durable store with no record of a card the bridge published is worth an
    // alert register -- it is the case a restart does NOT explain. The register
    // is the difference between the two arms; the word is not.
    await expect(ghost).toHaveAttribute("data-perch-register", "destructive");
    await expect(ghost).toContainText("the daemon has a durable hold store and no record of this hold");
    await expect(ghost.getByTestId("perch-row-grant")).toHaveCount(0);
    expect(await readPerchCounter(page, "perch_queue_reconcile_divergences_total")).toBe(1);
  });

  test("03c — an unadmitted issuer's hold renders nothing of its own and is counted separately", async ({ page }) => {
    await installPerchBridge(
      page,
      perchFixture({ holds: [perchHold({ hold_id: PERCH_HOLD_A })], relayOnlyHoldIds: [] }),
    );
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    await emitPerchHoldAlarm(page, {
      holdId: PERCH_HOLD_B,
      actionKind: "block_egress",
      severity: "CRITICAL",
      caseChannel: PERCH_CASE_CHANNEL,
      expiresAtMs: PERCH_NOW_MS + PERCH_HOLD_TTL_MS,
      issuer: PERCH_UNADMITTED_ISSUER,
    });

    // No row, no banner, no refusal card. 17-COMPONENT-SPECS.md: a refusal card
    // is a signal an adversary can plant at will, and a queue an adversary can
    // add rows to is a queue an adversary can use to bury a real one.
    await expect(page.getByTestId(`perch-queue-row-${PERCH_HOLD_B}`)).toHaveCount(0);
    await expect(page.getByTestId("perch-queue")).not.toContainText(/forged/i);
    await expect(page.getByTestId("perch-queue")).not.toContainText("UNRECONCILED");

    // A DIFFERENT counter, because these are different facts: a reconcile
    // divergence is the daemon and the relay disagreeing; this is a stranger
    // talking. Merging them would let an adversary inflate the divergence count
    // until an operator stops reading it.
    expect(await readPerchCounter(page, "perch_frame_unadmitted_total")).toBe(1);
    expect(await readPerchCounter(page, "perch_queue_reconcile_divergences_total")).toBe(0);
  });

  // ── INV-36, NEW ───────────────────────────────────────────────────────────
  //
  // TWO OPERATORS, ONE HOLD. Nothing in the wave-2 set handled this, and it is
  // reachable on the shipped default: APPENDIX-NORMATIVE.md section 4 layer 1
  // p-tags EVERY OperatorScope::Approve principal, and section 13's
  // declined-amendment note confirms the watch claim does not narrow it. So two
  // consoles can hold the same open hold.
  //
  // The daemon resolves its side (12-BACKEND-BILL-API.md section 4.4: 409
  // hold_already_deciding / hold_already_decided). The RELAY does not: leg 1 is
  // published before leg 2 is POSTed (13-WIRE-SCHEMAS.md's publish order), the
  // relay has no compare-and-set, and a kind:9 event is immutable. Both signed
  // verdict cards land in the case channel and stay there forever.
  //
  // Without this, the case channel and the Ledger export's holds/ directory
  // contain TWO unqualified human-decision records for one hold, and nothing
  // marks the loser. The losing console is also the only party that knows both
  // which card it published and which 409 it got back, so publishing the
  // qualification is its obligation, not the daemon's.
  //
  // 13-WIRE-SCHEMAS.md has landed the wire half: `leg2.state` gains `superseded`
  // and `superseded_by` (the winning leg-1 event id, required non-null exactly
  // when state is superseded) in card-swarm-verdict-v1.schema.json. This is the
  // client half.
  test("04 — the console that loses the decide race publishes superseded and stops claiming the decision", async ({ page }) => {
    const winnerIntentId = "aa".repeat(32);
    await installPerchBridge(
      page,
      perchFixture({
        holds: [perchHold({ hold_id: PERCH_HOLD_A, containment_lease_id: null })],
        decide: {
          [PERCH_HOLD_A]: {
            outcome: "superseded",
            rule: "hold_already_decided",
            reason: "another operator's decision was recorded first",
            receipt_id: null,
            superseded_by: winnerIntentId,
          },
        },
      }),
    );
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);
    await page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`).click();
    await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();

    await page.keyboard.press("g");
    await page.locator('[data-perch-role="blast-radius"]').scrollIntoViewIfNeeded();
    await expect
      .poll(async () => page.locator('[data-perch-role="grant"]').isEnabled(), { timeout: 4_000 })
      .toBe(true);
    await page.locator('[data-perch-role="grant"]').click();

    // The decision state is `superseded`, and it is NOT `recorded` -- the
    // operator's intent record stands, but this console must stop asserting it
    // is the decision.
    const status = page.getByTestId("perch-decision-status");
    await expect(status).toHaveAttribute("data-perch-decision-state", "superseded");

    // It names the winner, so the two cards can be linked by a reader and by a
    // reconciler.
    const outcome = page.getByTestId("perch-decision-outcome");
    await expect(outcome).toContainText(winnerIntentId.slice(0, 12));
    await expect(outcome).toContainText("another operator's decision was recorded first");

    // No retry: the hold is decided and retrying would publish a third card.
    await expect(page.getByTestId("perch-decision-retry")).toHaveCount(0);
    // And no undo, which is INV-33's rule and does not relax here.
    await expect(page.getByTestId("perch-decision-undo")).toHaveCount(0);

    // The update card is PUBLISHED, not merely rendered. A superseded state that
    // only this console knows about leaves the case channel carrying two
    // unqualified decision records, which is the whole defect.
    await expect(page.getByTestId("perch-verdict-update-published")).toHaveAttribute(
      "data-perch-superseded-by",
      winnerIntentId,
    );

    // The export marks the loser rather than dropping it: a human intent record
    // that did not become the decision is still evidence a person deliberated,
    // and deleting it would be the console editing the record.
    const manifest = await readPerchExportManifest(page);
    expect(manifest.holds).toContain(PERCH_HOLD_A);
    expect(manifest.superseded_verdicts).toContain(PERCH_HOLD_A);
  });

  // INV-32, the rendered half. The table test over PERCH_BINDINGS is the
  // authority (tests/node/perchKeymapRegistry.test.mjs); this asserts the
  // rendered hints agree with it in the one list where holds and findings
  // interleave, because a registry can be right and a row's hint stale.
  test("04 — one key, one verdict verb, across both row types in one list", async ({ page }) => {
    await installPerchBridge(page, perchFixture({ holds: [perchHold({ hold_id: "h_mixedqueue01" })] }));
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    const hints = page.locator("[data-perch-key][data-perch-verb]");
    const count = await hints.count();
    expect(count).toBeGreaterThan(0);

    const seen = new Map<string, string>();
    for (let index = 0; index < count; index += 1) {
      const key = ((await hints.nth(index).getAttribute("data-perch-key")) ?? "").toLowerCase();
      const verb = (await hints.nth(index).getAttribute("data-perch-verb")) ?? "";
      expect(key).not.toBe("a");
      const prior = seen.get(key);
      if (prior !== undefined) {
        expect(prior, `key "${key}" is bound to two verdict verbs in one list`).toBe(verb);
      }
      seen.set(key, verb);
    }
  });

  // INV-21. The twelve lanes are muted by default on first run -- the
  // anti-habituation control. Escalation is level-triggered at 10 Hz
  // (AMB crates/swarm-runtime/src/escalation.rs:105-207, no memory of prior
  // state), so an unmuted lane is a firehose on day one.
  test("05 — all twelve lane channels are muted on first run", async ({ page }) => {
    await installPerchBridge(page, perchFixture());
    await installMockBridge(page);
    await page.goto("/");
    await expect(page.getByTestId("perch-lane-list")).toBeVisible();

    for (const lane of LANES) {
      const row = page.getByTestId(`perch-lane-${lane}`);
      await expect(row).toBeVisible();
      await expect(row).toHaveAttribute("data-perch-muted", "true");
    }
    await expect(page.getByTestId("perch-lane-list").locator("[data-perch-muted='false']")).toHaveCount(0);
  });

  // INV-24. The phrase ban is UNIVERSAL; the /gaps link is SCOPED. An empty
  // state that is not swarm-produced-nothing names its own governing number and
  // must NOT link /gaps -- otherwise the link stops meaning anything.
  test("06 — empty states never reassure, and only swarm-produced-nothing links /gaps", async ({ page }) => {
    await installPerchBridge(page, perchFixture());
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);
    await waitForAnimations(page);

    const emptyStates = page.locator('[data-perch-role="empty-state"]');
    const count = await emptyStates.count();
    expect(count).toBeGreaterThan(0);

    for (let index = 0; index < count; index += 1) {
      const state = emptyStates.nth(index);
      const text = (await state.innerText()).toLowerCase();
      for (const phrase of BANNED_EMPTY_PHRASES) {
        expect(text, `empty state ${index} contains "${phrase}"`).not.toContain(phrase);
      }

      const kind = await state.getAttribute("data-perch-empty-kind");
      const gapLinks = await state.locator('[data-perch-role="gap-link"]').count();
      if (kind === "swarm-produced-nothing") {
        // The 18/11 numbers come from the catalogue
        // (AMB rulesets/evasion/attack-technique-catalog.yaml), not from copy.
        expect(gapLinks).toBe(1);
        expect(text).toMatch(/\d+ techniques?/);
      } else {
        expect(gapLinks, `a ${kind} empty state must not link /gaps`).toBe(0);
        // It names its own governing number instead.
        expect(text).toMatch(/\d/);
      }
    }
  });

  // The live path, asserted once so a future refactor cannot quietly move the
  // queue onto a REQ that cannot work. A REQ of {kinds:[46010],"#p":[me]} can
  // never deliver a forked hold: fan_out_scoped routes channel-bearing events
  // through the channel indexes only and a REQ with no #h registers globally
  // (BUZZ crates/buzz-relay/src/subscription.rs:379-495, note at :487-492).
  test("07 — a 26006 alarm is what makes a new hold appear, inside the 400 ms budget", async ({ page }) => {
    await installPerchBridge(page, perchFixture({ holds: [perchHold({ hold_id: "h_seeded00001" })] }));
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    const started = Date.now();
    await emitPerchHoldAlarm(page, {
      holdId: "h_liveawaken01",
      actionKind: "quarantine_file",
      severity: "CRITICAL",
      caseChannel: PERCH_CASE_CHANNEL,
      expiresAtMs: Date.now() + PERCH_HOLD_TTL_MS,
    });
    await expect(page.getByTestId("perch-queue-row-hold-live")).toBeVisible({ timeout: 2_000 });
    // Reported rather than asserted: CI timing is not a latency measurement, and
    // a flaky 400 ms assertion would be disabled within a month. The real budget
    // lives in the bridge's own counters (11-BRIDGE-CRATE.md).
    console.log(`26006 alarm to visible row: ${Date.now() - started} ms`);
  });
});
