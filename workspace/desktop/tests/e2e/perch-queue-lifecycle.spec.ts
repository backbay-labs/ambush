import { expect, test } from "@playwright/test";

import {
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  installPerchWatchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_HOLD_A,
  PERCH_LANE_CHANNEL,
  PERCH_LANE_CHANNEL_NAME,
  perchHold,
  readBlastRadius,
  setPerchHolds,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * What happens to a hold, and to the pane holding it, across a decision — and
 * what happens to a case channel opened from the sidebar. The window walk
 * caught both: a granted hold left the open queue and the pane read "no record"
 * for a hold the daemon plainly held (found-10), and a `case-*` channel opened
 * from the sidebar rendered as an ordinary channel (found-8).
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

test("clicking a case channel in the sidebar opens it as a case, not a channel (found-8)", async ({
  page,
}) => {
  // Open a case the ordinary way: `E` on a lane finding mints it and lands on
  // `/cases/$caseId`, and the bridge creates its `case-*` channel in the
  // sidebar.
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(
    PERCH_LANE_CHANNEL_NAME,
  );
  const eventId = await emitPerchMessage(page, {
    channelName: PERCH_LANE_CHANNEL_NAME,
    content: findingCardBody(),
    pubkey: PERCH_ADMITTED_ISSUER,
    id: PERCH_FINDING_CARD_EVENT_ID,
  });
  await page
    .locator(`[data-message-id="${eventId}"]`)
    .getByTestId("perch-evidence-finding")
    .getByTestId("perch-finding-actions")
    .getByTestId("perch-finding-action-promote")
    .focus();
  await page.keyboard.press("e");
  await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
  // Wait for the case to actually open: that is when the bridge's `case-*`
  // channel has arrived in the channel list and, with it, the sidebar.
  await expect(page.getByTestId("perch-case")).toBeVisible();

  const caseChannel = `case-${PERCH_CASE_CHANNEL.slice(0, 8)}`;
  await expect(page.getByTestId(`channel-${caseChannel}`)).toBeVisible();
  // Leave the case for an ordinary channel, IN THE SPA — a reload would drop
  // the runtime-created case channel from the mock's sidebar.
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page).toHaveURL(new RegExp(`/channels/${PERCH_LANE_CHANNEL}$`));

  // Now click the case channel: W3-5 makes `/cases/$caseId` its only surface,
  // so the sidebar takes it there and the case renders — never the channel view.
  await page.getByTestId(`channel-${caseChannel}`).click();
  await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
  await expect(page.getByTestId("perch-case")).toBeVisible();
});
