import { expect, test } from "@playwright/test";

import {
  installPerchWatchBridge,
  PERCH_HOLD_A,
  perchHold,
  readBlastRadius,
  setPerchHolds,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * What happens to a hold, and to the pane holding it, across a decision. The
 * window walk caught it: a granted hold left the open queue and the pane read
 * "no record" for a hold the daemon plainly held (found-10).
 */

test("a granted hold leaves the open queue, and the pane keeps it with its receipt (found-10)", async ({
  page,
}) => {
  // The blast radius must be readable, so the two-stroke grant can complete.
  await page.setViewportSize({ width: 1280, height: 1400 });
  await installPerchWatchBridge(page, {
    holds: [perchHold({ hold_id: PERCH_HOLD_A })],
    decide: {
      outcome: "dispatched",
      receipt_id: "receipt-9f3c1a2b",
      dispatched: true,
    },
    // Leg 2 is held open long enough to move the daemon's list underneath it.
    decideDelayMs: 1_200,
  });
  await page.goto("/");
  await waitForPerchQueue(page);
  await page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`).click();
  await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();

  // Grant it: read the blast radius, arm, record.
  await readBlastRadius(page);
  await page.keyboard.press("g");
  await expect(page.getByTestId("perch-grant-armed")).toBeVisible();
  await page.keyboard.press("Enter");

  // Leg 1 landed; leg 2 is still in flight. While it is, the daemon runs the
  // action and the hold turns `executed` — it leaves the OPEN queue but stays
  // in the daemon's terminal-inclusive list.
  await expect(
    page.locator('[data-perch-decision-state="recorded"]'),
  ).toBeVisible();
  await setPerchHolds(
    page,
    [perchHold({ hold_id: PERCH_HOLD_A, state: "executed" })],
    { openCount: 0 },
  );

  // Leg 2 completes; its invalidation re-reads the now-executed hold.
  await expect(
    page.locator('[data-perch-decision-state="acknowledged"]'),
  ).toBeVisible({ timeout: 10_000 });

  // The open queue no longer asks about it...
  await expect(page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`)).toHaveCount(
    0,
  );
  // ...but the pane kept its subject: the card, and the receipt, copyable.
  await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();
  await expect(page.getByTestId("perch-write-state-receipt")).toContainText(
    "receipt-9f3c1a2b",
  );
  // Never the lie the walk caught: the daemon plainly has this record.
  await expect(page.getByTestId("perch-detail-unreconciled")).toHaveCount(0);
});
