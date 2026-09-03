// Target path in BUZZ: desktop/tests/e2e/perch-containment.spec.ts
// Register under the `smoke` project: "**/perch-containment.spec.ts".
//
// Covers INV-04, INV-05, INV-06, INV-07 (the UI half), INV-34.
//
// Every assertion here traces to a doc comment in Ambush's own source. The
// containment surface is the one place where the runtime already wrote down
// exactly what an honest UI must do, and the shipped UI does not exist yet.

import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import { waitForAnimations } from "../helpers/animations";
import {
  installPerchBridge,
  perchFixture,
  perchHold,
  waitForPerchQueue,
  type PerchMockContainment,
} from "../helpers/perchBridge";

/**
 * The five RollbackStepStatus variants
 * (AMB crates/swarm-response/src/rollback.rs:209-223). `restored()` is true only
 * for Reversed (:226-228), which is why Simulated and Unsupported must not read
 * as success and Irreversible must not read as a failure to retry.
 */
const ROLLBACK_STATUSES = ["reversed", "simulated", "irreversible", "unsupported", "failed"] as const;

const CONTAINMENTS: PerchMockContainment[] = [
  { lease_id: "containment-live", action_kind: "isolate_host", remaining_ms: 812_000, expired: false },
  // remaining_ms saturates at zero, so these two are indistinguishable on that
  // field alone (AMB swarm-runtime-http/src/http/containment.rs:76-81 says so in
  // its own doc comment). `expired: true` on a STILL-LISTED row means the sweep
  // tried and failed -- a host is still contained.
  { lease_id: "containment-instant", action_kind: "quarantine_file", remaining_ms: 0, expired: false },
  { lease_id: "containment-stuck", action_kind: "suspend_process", remaining_ms: 0, expired: true },
];

async function openContainments(page: import("@playwright/test").Page, fixture = perchFixture({ containments: CONTAINMENTS })) {
  await installPerchBridge(page, fixture);
  await installMockBridge(page);
  await page.goto("/#/leases");
  await expect(page.getByTestId("perch-containment-list")).toBeVisible();
  await waitForAnimations(page);
}

test.describe("Perch containments", () => {
  // INV-06. Two facts, two elements, and the two rows must differ in the DOM.
  test("01 — remaining_ms and expired are two elements, and 0/false differs from 0/true", async ({ page }) => {
    await openContainments(page);

    const instant = page.getByTestId("perch-containment-row-containment-instant");
    const stuck = page.getByTestId("perch-containment-row-containment-stuck");

    for (const row of [instant, stuck]) {
      await expect(row.getByTestId("perch-containment-remaining")).toHaveCount(1);
      await expect(row.getByTestId("perch-containment-expired")).toHaveCount(1);
    }

    // A single progress bar reaching zero is forbidden: it cannot distinguish
    // "expires in an instant" from "expired an hour ago and the sweep failed".
    await expect(page.locator('[data-perch-role="containment-release"] progress')).toHaveCount(0);

    const instantText = (await instant.innerText()).trim();
    const stuckText = (await stuck.innerText()).trim();
    expect(instantText).not.toBe(stuckText);
    await expect(stuck.getByTestId("perch-containment-expired")).toContainText("the sweep tried and failed");
    // Voice law L3's one permitted intensifier.
    await expect(stuck).toContainText("still contained");
  });

  // INV-05. The caller reads the BODY, never the status code. The daemon's own
  // handler deliberately returns lease_closed:false on a 200
  // (AMB swarm-runtime-http/src/http/containment.rs:191-247) so a caller cannot
  // read success into an unfinished release; swarmctl already exits non-zero on
  // it (AMB swarm-cli/src/core.inc:3101-3120).
  test("02 — a 200 with lease_closed:false renders in the error register", async ({ page }) => {
    await openContainments(
      page,
      perchFixture({
        containments: CONTAINMENTS,
        // The mock answers HTTP 200 and this body.
        decide: {},
        relayOnlyHoldIds: [],
      }),
    );

    await page.getByTestId("perch-containment-row-containment-live").click();
    await page.locator('[data-perch-role="containment-release"]').click();
    await waitForAnimations(page);

    const outcome = page.getByTestId("perch-release-outcome");
    await expect(outcome).toHaveAttribute("data-perch-register", "error");
    await expect(outcome).toContainText("lease_closed");
    // And it must not have inferred success from the status code.
    await expect(outcome).not.toContainText("Released");
  });

  // INV-04. Five variants, five pairwise-distinct DOM texts.
  test("03 — the five rollback step statuses render five distinct strings", async ({ page }) => {
    await openContainments(page);
    await page.getByTestId("perch-containment-row-containment-live").click();
    await page.getByTestId("perch-rollback-plan-open").click();
    await waitForAnimations(page);

    const texts: string[] = [];
    for (const status of ROLLBACK_STATUSES) {
      const step = page.getByTestId(`perch-rollback-step-${status}`);
      await expect(step).toHaveCount(1);
      texts.push((await step.innerText()).trim());
    }
    expect(new Set(texts).size).toBe(ROLLBACK_STATUSES.length);
    // The two that are most often conflated, named explicitly so a future
    // copy edit that merges them fails here rather than in production.
    expect(texts[2]).not.toBe(texts[3]); // irreversible !== unsupported
    expect(texts[1]).not.toBe(texts[0]); // simulated !== reversed
  });

  // INV-07. The disabled row-menu item with its reason is the explanation; it is
  // not an affordance. A ContainmentLease has private fields, one constructor and
  // no setter (AMB swarm-response/src/containment.rs:74-95), and closing one
  // twice produces two rollback receipts for one containment.
  test("04 — no element offers extending a containment, and the disabled item states why", async ({ page }) => {
    await openContainments(page);
    await page.getByTestId("perch-containment-row-containment-live").click({ button: "right" });
    await waitForAnimations(page);

    const disabled = page.locator('[data-perch-role="containment-extend-disabled"]');
    await expect(disabled).toHaveCount(1);
    await expect(disabled).toBeDisabled();
    await expect(disabled).toContainText("cannot be extended");
    await expect(disabled).toContainText("mint a new containment lease over the same containment");

    // Nothing else in the menu is an extend control.
    const enabledExtend = page.getByRole("menuitem", { name: /extend/i }).and(page.locator(":not([aria-disabled='true'])"));
    await expect(enabledExtend).toHaveCount(0);
  });

  // INV-34. One list, both row types. Snooze is disabled on a hold for a SAFETY
  // reason (08 section 7.1), not an arithmetic one -- the 60-minute TTL leaves
  // every preset in range (BUZZ desktop/src/features/reminders/lib/timePresets.ts:31-44
  // starts at 30 minutes), so the disabled state must say why.
  test("05 — snooze is disabled on a hold row and enabled on a finding row, in one list", async ({ page }) => {
    await installPerchBridge(
      page,
      perchFixture({ holds: [perchHold({ hold_id: "h_mixedrows001" })] }),
    );
    await installMockBridge(page);
    await page.goto("/");
    await waitForPerchQueue(page);

    const holdSnooze = page.getByTestId("perch-row-snooze-hold-mixed");
    const findingSnooze = page.getByTestId("perch-row-snooze-finding-mixed");

    await expect(holdSnooze).toBeDisabled();
    await expect(holdSnooze).toContainText("a hold cannot be snoozed");
    await expect(findingSnooze).toBeEnabled();

    // Both rows are in the same list, which is the point: they interleave.
    const list = page.getByTestId("perch-queue-needs-action");
    await expect(list.getByTestId("perch-row-snooze-hold-mixed")).toHaveCount(1);
    await expect(list.getByTestId("perch-row-snooze-finding-mixed")).toHaveCount(1);
  });
});
