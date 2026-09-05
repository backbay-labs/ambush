import { expect, test, type Page } from "@playwright/test";
import {
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_LANE_CHANNEL_NAME,
  type PerchMockFixture,
} from "../helpers/perchBridge";

/**
 * The case's Canvas tab: five headings seeded once into a canvas the relay
 * has never held, never into one an operator emptied, and a wall-clock TTL.
 */

const HEADINGS = [
  "Timeline",
  "Hypothesis",
  "Actions taken",
  "Open questions",
  "Handoff notes",
];

/** `E` on the lane's finding card, which mints the case and lands on it. */
async function openCase(
  page: Page,
  options?: { fixture?: PerchMockFixture; canvasContent?: string },
): Promise<void> {
  await installPerchBridge(page, options?.fixture, {
    mock:
      options?.canvasContent === undefined
        ? undefined
        : { canvasContent: options.canvasContent },
  });
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
  const card = page
    .locator(`[data-message-id="${eventId}"]`)
    .getByTestId("perch-evidence-finding");
  await expect(card).toBeVisible();
  await card
    .getByTestId("perch-finding-actions")
    .getByTestId("perch-finding-action-promote")
    .focus();
  await page.keyboard.press("e");
  await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
  await expect(page.getByTestId("perch-case")).toBeVisible();
}

async function openCanvasTab(page: Page): Promise<void> {
  await page.getByTestId("perch-case-tab-canvas").click();
  await expect(page.getByTestId("perch-case-canvas")).toBeVisible();
}

/** Every `set_canvas` the mock bridge has taken, in order. */
async function setCanvasCalls(page: Page): Promise<number> {
  return page.evaluate(
    () =>
      (
        window as typeof window & {
          __AMBUSH_E2E_COMMAND_LOG__?: { command: string }[];
        }
      ).__AMBUSH_E2E_COMMAND_LOG__?.filter((e) => e.command === "set_canvas")
        .length ?? 0,
  );
}

test("a fresh case's Canvas tab seeds the five headings, once", async ({
  page,
}) => {
  await openCase(page);
  await openCanvasTab(page);
  const canvas = page.getByTestId("perch-case-canvas");
  for (const heading of HEADINGS) {
    await expect(canvas).toContainText(heading);
  }
  await expect.poll(() => setCanvasCalls(page)).toBe(1);
  await expect(page.getByTestId("perch-case-canvas-seed-failed")).toHaveCount(
    0,
  );
});

test("reopening the same case seeds nothing more", async ({ page }) => {
  await openCase(page);
  await openCanvasTab(page);
  await expect.poll(() => setCanvasCalls(page)).toBe(1);
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(
    PERCH_LANE_CHANNEL_NAME,
  );
  await page.goBack();
  await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
  await openCanvasTab(page);
  // Give a second seed every chance to happen before asserting it did not.
  await page.waitForTimeout(500);
  expect(await setCanvasCalls(page)).toBe(1);
});

test("a canvas an operator emptied is not re-seeded", async ({ page }) => {
  await openCase(page, { canvasContent: "" });
  await openCanvasTab(page);
  await page.waitForTimeout(500);
  expect(await setCanvasCalls(page)).toBe(0);
  await expect(page.getByTestId("perch-case-canvas")).not.toContainText(
    "Hypothesis",
  );
});

test("the TTL is a wall clock, never a progress bar", async ({ page }) => {
  await openCase(page);
  await openCanvasTab(page);
  const ttl = page.getByTestId("perch-case-ttl");
  await expect(ttl).toBeVisible();
  await expect(ttl.locator("progress")).toHaveCount(0);
  await expect(
    page.getByTestId("perch-case-canvas").locator("progress"),
  ).toHaveCount(0);
});
