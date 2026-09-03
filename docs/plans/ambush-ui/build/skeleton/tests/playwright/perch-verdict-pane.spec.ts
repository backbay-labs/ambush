// Target path in BUZZ: desktop/tests/e2e/perch-verdict-pane.spec.ts
// Register in desktop/playwright.config.ts under the `smoke` project's
// testMatch: "**/perch-verdict-pane.spec.ts".
//
// Covers INV-02, INV-03, INV-10, INV-11, INV-28, INV-33.
//
// The Verdict Row is the one surface where a wrong pixel is a wrong decision, so
// every assertion here reads the DOM the operator actually gets, not a prop.

import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import { waitForAnimations } from "../helpers/animations";
import {
  installPerchBridge,
  perchFixture,
  perchHold,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * All 15 ResponseAction variants
 * (AMB crates/swarm-core/src/types.rs:419-468, read line by line). Twelve are
 * destructive; the three that are not are trigger_edr_scan, deploy_decoy and
 * escalate. Only four are containment actions and only three of those have an
 * executable inverse -- 12 -> 4 -> 3 is the real ladder, so the fixture marks
 * which is which rather than pretending the twelve are uniform.
 */
const RESPONSE_ACTIONS = [
  { kind: "block_egress", destructive: true, containment: false, reversible: false },
  { kind: "isolate_host", destructive: true, containment: true, reversible: true },
  { kind: "revoke_credential", destructive: true, containment: false, reversible: false },
  { kind: "sinkhole_dns", destructive: true, containment: false, reversible: false },
  { kind: "terminate_user_session", destructive: true, containment: true, reversible: false },
  { kind: "trigger_edr_scan", destructive: false, containment: false, reversible: false },
  { kind: "inject_firewall_rule", destructive: true, containment: false, reversible: false },
  { kind: "quarantine_file", destructive: true, containment: true, reversible: true },
  { kind: "kill_process", destructive: true, containment: false, reversible: false },
  { kind: "suspend_process", destructive: true, containment: true, reversible: true },
  { kind: "disable_user_account", destructive: true, containment: false, reversible: false },
  { kind: "force_password_reset", destructive: true, containment: false, reversible: false },
  { kind: "remove_scheduled_task", destructive: true, containment: false, reversible: false },
  { kind: "deploy_decoy", destructive: false, containment: false, reversible: false },
  { kind: "escalate", destructive: false, containment: false, reversible: false },
] as const;

/** Render law 1's order. The DOM order IS the invariant; do not sort this. */
const SLOT_IDS = [
  "action",
  "blast-radius",
  "if-you-undo",
  "why-we-are-asking",
  "what-granting-opens",
] as const;

async function openVerdictPane(
  page: import("@playwright/test").Page,
  fixture: ReturnType<typeof perchFixture>,
) {
  await installPerchBridge(page, fixture);
  await installMockBridge(page);
  await page.goto("/");
  await waitForPerchQueue(page);
  await page.getByTestId(`perch-queue-row-${fixture.holds[0].hold_id}`).click();
  await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();
  await waitForAnimations(page);
}

test.describe("Perch verdict pane", () => {
  // INV-02. Fifteen snapshots, one per ResponseAction variant. The assertion is
  // presence AND order: an unfillable slot renders an explicit absence, it never
  // collapses, because at 02:41 an operator reads by position.
  for (const action of RESPONSE_ACTIONS) {
    test(`01 — ${action.kind}: five slots, fixed order, none omitted`, async ({ page }) => {
      const hold = perchHold({
        hold_id: `h_${action.kind}`,
        action_kind: action.kind,
        containment_lease_id: action.containment ? `containment-${action.kind}` : null,
        every_step_reversible: action.reversible,
      });
      await openVerdictPane(page, perchFixture({ holds: [hold] }));

      const slots = page.locator('[data-perch-role="verdict-slot"]');
      await expect(slots).toHaveCount(SLOT_IDS.length);
      for (const [index, id] of SLOT_IDS.entries()) {
        await expect(slots.nth(index)).toHaveAttribute("data-perch-slot", id);
        // An empty slot must still carry rendered text -- the explicit absence.
        await expect(slots.nth(index)).not.toHaveText("");
      }

      // The eight destructive actions that are NOT containment actions never mint
      // a ContainmentLease (AMB swarm-runtime/src/lib.rs:829-831), so a pending
      // countdown beside them would be a fabricated fact.
      const pendingLease = page.getByTestId("perch-pending-containment-lease");
      await expect(pendingLease).toHaveCount(action.containment ? 1 : 0);
    });
  }

  // INV-03. Enabled Undo requires resolve_inverse -> Ok for EVERY step.
  // terminate_user_session is the sharp case: it IS a containment action and it
  // maps to InverseGap::Irreversible (AMB swarm-response/src/rollback.rs:183-189),
  // so "has a containment lease" must not be mistaken for "can be undone".
  test("02 — Undo is disabled unless every rollback step resolves", async ({ page }) => {
    const reversible = perchHold({ hold_id: "h_reversible01", action_kind: "suspend_process", containment_lease_id: "c-1", every_step_reversible: true });
    const irreversible = perchHold({ hold_id: "h_irreversible", action_kind: "terminate_user_session", containment_lease_id: "c-2", every_step_reversible: false });
    await openVerdictPane(page, perchFixture({ holds: [reversible, irreversible] }));

    await expect(page.getByTestId("perch-undo-affordance")).toBeEnabled();

    await page.getByTestId("perch-queue-row-hold-irrev").click();
    await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();
    await expect(page.getByTestId("perch-undo-affordance")).toBeDisabled();
    // The disabled control states the daemon's own reason rather than greying out.
    await expect(page.getByTestId("perch-undo-affordance")).toContainText(
      "a terminated session cannot be resumed",
    );
  });

  // INV-10. Two independent assertions, because the class and the computed
  // colour fail in different ways: `bg-primary` is a class check a refactor can
  // dodge, and applyAccentColor writes --primary INLINE on the root element
  // (BUZZ desktop/src/shared/theme/ThemeProvider.tsx:198,213-218), so the
  // computed value is what an operator actually sees.
  test("03 — the grant control is never the primary action", async ({ page }) => {
    await openVerdictPane(page, perchFixture({ holds: [perchHold()] }));
    const grant = page.locator('[data-perch-role="grant"]');
    await expect(grant).toHaveCount(1);
    await expect(grant).not.toHaveClass(/\bbg-primary\b/);

    const primaryBackground = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue("--primary").trim(),
    );
    const grantBackground = await grant.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(grantBackground).not.toBe(`hsl(${primaryBackground})`);

    // Render law 6. The accessible name says what the control actually does.
    await expect(grant).toHaveAccessibleName(/record my decision and send it to the daemon/i);
    await expect(grant).not.toHaveAccessibleName(/^\s*approve\b/i);
  });

  // ── INV-11, THE STRICT DWELL READING ──────────────────────────────────────
  //
  // APPENDIX-NORMATIVE.md section 2 words the gate as TWO INDEPENDENT
  // conditions: "the BLAST RADIUS block having been fully visible AND >=1500 ms
  // on this hold_id". The first draft of this test asserted exactly that, and
  // the reading is defeatable:
  //
  //     open the pane, wait 1.4 s looking at the ACTION slot, scroll -- and the
  //     control enables about 100 ms after the blast radius first appears.
  //
  // That is the anti-habituation gate the whole two-stroke design exists for,
  // satisfied by a scroll. proto-verdict, the artifact that actually implemented
  // the gate, found this and committed to the STRICT reading: the 1500 ms
  // accrues ONLY while the BLAST RADIUS block's last child is fully visible, and
  // FREEZES (never resets) when it is not. The strict reading implies both of
  // the appendix's conditions and is not implied by them.
  //
  // ADOPTED HERE, and the assertion is the freeze rather than the conjunction --
  // because the conjunction is what the loose implementation also satisfies, and
  // a test that both readings pass is a test that does not choose.
  //
  // PROPOSED BRIEF AMENDMENT: APPENDIX-NORMATIVE.md section 2's `G` row and
  // 08 section 3.5 should read "accrues only while the BLAST RADIUS block is
  // fully visible; freezes otherwise", replacing the two-condition wording.
  //
  // The gate needs BOTH mechanisms, and the static half of
  // tools/check-perch-grant-affordance.sh (R3) greps for both: an
  // IntersectionObserver at threshold 1.0 on the block's last child, AND a
  // periodic rect sample, because a fast scroll can carry the sentinel past
  // without the observer ever reporting a full frame. A safety gate must not be
  // defeatable by scroll velocity.
  test("04 — the grant is two-stroke, dwell-gated, ignores key repeat, and resets", async ({ page }) => {
    const first = perchHold({ hold_id: "h_dwell_first" });
    const second = perchHold({ hold_id: "h_dwell_second" });
    await openVerdictPane(page, perchFixture({ holds: [first, second] }));

    const grant = page.locator('[data-perch-role="grant"]');
    const blastRadius = page.locator('[data-perch-role="blast-radius"]');
    await expect(grant).toBeDisabled();

    // (a) key-repeat does not arm. Buzz's own handler already bails on
    // event.repeat (BUZZ desktop/src/app/useAppShellKeyboardShortcuts.ts:57-64),
    // so this is house practice, not a new rule.
    await page.evaluate(() =>
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "g", repeat: true, bubbles: true })),
    );
    await expect(page.getByTestId("perch-grant-armed")).toHaveCount(0);

    // (b) a real G arms, and the control stays disabled: armed is not enabled.
    await page.keyboard.press("g");
    await expect(page.getByTestId("perch-grant-armed")).toHaveCount(1);
    await expect(grant).toBeDisabled();

    // (c) THE STRICT READING. Time spent NOT looking at the blast radius does
    // not accrue. Two seconds of wall clock elapse here -- comfortably past
    // 1500 ms -- with the block scrolled out of view, and the control must
    // still be disabled. Under the loose reading this passes and then enables
    // the instant the block appears, which is the defect.
    await page.getByTestId("perch-verdict-pane").evaluate((el) => {
      el.scrollTop = 0;
    });
    await expect(blastRadius).not.toBeInViewport();
    await page.waitForTimeout(2_000);
    await expect(grant).toBeDisabled();
    // The pane says WHY it is still disabled. A gate that is silent for two
    // seconds reads as a broken button, and a broken button gets clicked twice.
    await expect(page.getByTestId("perch-grant-dwell")).toContainText("0%");

    // (d) the dwell accrues while the block is fully visible...
    await blastRadius.scrollIntoViewIfNeeded();
    await expect(blastRadius).toBeInViewport({ ratio: 1 });
    await page.waitForTimeout(800);
    // ...and FREEZES, rather than resetting, when it leaves. Freezing is the
    // choice proto-verdict argued: a reset punishes an operator who glanced at
    // the queue, and punishing a careful operator is how a gate gets removed.
    const partial = await page.getByTestId("perch-grant-dwell").innerText();
    await page.getByTestId("perch-verdict-pane").evaluate((el) => {
      el.scrollTop = 0;
    });
    await page.waitForTimeout(1_000);
    await expect(page.getByTestId("perch-grant-dwell")).toHaveText(partial);
    await expect(grant).toBeDisabled();

    // (e) resuming completes it.
    await blastRadius.scrollIntoViewIfNeeded();
    await expect
      .poll(async () => grant.isEnabled(), { timeout: 4_000 })
      .toBe(true);

    // (f) arming resets on hold_id change. An armed grant carried across rows is
    // the single worst failure this pane can have.
    await page.getByTestId("perch-queue-row-h_dwell_second").click();
    await expect(page.getByTestId("perch-grant-armed")).toHaveCount(0);
    await expect(page.locator('[data-perch-role="grant"]')).toBeDisabled();
    await expect(page.getByTestId("perch-grant-dwell")).toContainText("0%");

    // (g) no grant control is reachable from a multi-select context.
    await page.getByTestId("perch-queue-select-all").click();
    await expect(page.locator('[data-perch-role="grant"]')).toHaveCount(0);
  });

  // INV-33. Three distinct states, no optimistic render, no undo affordance.
  test("05 — the grant path renders sending / recorded / acknowledged with no undo", async ({ page }) => {
    const hold = perchHold({ hold_id: "h_slowdecide01" });
    await openVerdictPane(
      page,
      perchFixture({
        holds: [hold],
        decide: {
          "h_slowdecide01": { outcome: "dispatched", rule: null, reason: null, receipt_id: "receipt-1", delay_ms: 1_200 },
        },
      }),
    );

    await page.keyboard.press("g");
    await page.locator('[data-perch-role="blast-radius"]').scrollIntoViewIfNeeded();
    await expect.poll(async () => page.locator('[data-perch-role="grant"]').isEnabled(), { timeout: 4_000 }).toBe(true);
    await page.locator('[data-perch-role="grant"]').click();

    const status = page.getByTestId("perch-decision-status");
    await expect(status).toHaveAttribute("data-perch-decision-state", "sending");
    await expect(status).toHaveAttribute("data-perch-decision-state", "recorded");
    await expect(status).toHaveAttribute("data-perch-decision-state", "acknowledged");
    await expect(page.getByTestId("perch-decision-undo")).toHaveCount(0);
  });

  // INV-28. A late refusal is a NORMAL outcome. The shipped default makes this
  // the common case, not the edge one: containment.lease_store_path defaults to
  // None (AMB swarm-core/src/config/runtime.rs:94-95), so all four containment
  // actions refuse at runtime.containment_refused
  // (AMB swarm-runtime/src/lib.rs:836-844).
  test("06 — a daemon RefusedLate renders as an outcome naming the rule, not a client error", async ({ page }) => {
    const hold = perchHold({ hold_id: "h_refusedlate01", action_kind: "isolate_host", containment_lease_id: "c-3" });
    await openVerdictPane(
      page,
      perchFixture({
        holds: [hold],
        decide: {
          "h_refusedlate01": {
            outcome: "refused_late",
            rule: "runtime.containment_refused",
            reason: "no containment lease store is configured",
            receipt_id: null,
          },
        },
      }),
    );

    await page.keyboard.press("g");
    await page.locator('[data-perch-role="blast-radius"]').scrollIntoViewIfNeeded();
    await expect.poll(async () => page.locator('[data-perch-role="grant"]').isEnabled(), { timeout: 4_000 }).toBe(true);
    await page.locator('[data-perch-role="grant"]').click();

    const outcome = page.getByTestId("perch-decision-outcome");
    await expect(outcome).toHaveAttribute("data-perch-register", "outcome");
    await expect(outcome).not.toHaveAttribute("data-perch-register", "error");
    await expect(outcome).toContainText("runtime.containment_refused");
    await expect(outcome).toContainText("no containment lease store is configured");
    await expect(page.getByTestId("perch-decision-retry")).toHaveCount(0);
  });

  // INV-28's governance arm cannot fire until B2g lands, so the legend says so
  // rather than the test pretending. 12-BACKEND-BILL-API.md section 5 owns it.
  test("07 — the refusal legend draws the governance arm as not-yet-reachable", async ({ page }) => {
    await openVerdictPane(page, perchFixture({ holds: [perchHold()] }));
    await page.getByTestId("perch-refusal-legend-open").click();
    await waitForAnimations(page);
    const governanceRow = page.getByTestId("perch-refusal-legend-governance");
    await expect(governanceRow).toHaveAttribute("data-perch-reachable", "false");
    await expect(governanceRow).toContainText("cannot occur until the decide path re-runs governance");
  });
});
