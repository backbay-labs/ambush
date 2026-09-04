import { expect, test, type Page } from "@playwright/test";

import { installPerchBridge } from "../helpers/perchBridge";

/**
 * `/handoff` — what this watch did, and what the next one inherits.
 */

async function openHandoff(page: Page): Promise<void> {
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId("perch-nav-handoff").click();
  await expect(page.getByTestId("perch-handoff")).toBeVisible();
}

test("the block declares its timezone", async ({ page }) => {
  // A handoff is read by whoever comes on next, who may not share the
  // outgoing operator's timezone.
  await openHandoff(page);
  await expect(page.getByTestId("perch-end-watch-block")).toContainText(
    "times in UTC",
  );
});

test("every heading is present even for a shift that touched nothing", async ({
  page,
}) => {
  // An empty shift is a claim about coverage: the reader must see WHICH
  // things were zero, not a block that omits them.
  await openHandoff(page);
  const block = page.getByTestId("perch-end-watch-block");
  for (const heading of [
    "CASES TOUCHED",
    "FINDINGS REVIEWED",
    "HOLDS EXPIRED UNDECIDED",
    "OPEN CONTAINMENTS",
    "VERDICTS RECORDED",
  ]) {
    await expect(block).toContainText(heading);
  }
});

test("the claim panel says taking the watch does not narrow paging", async ({
  page,
}) => {
  // The dangerous misreading is that claiming the watch removes other people
  // from the page. Both standing sentences deny it.
  await openHandoff(page);
  const panel = page.getByTestId("perch-watch-claim");
  await expect(panel).toContainText("does not change who is p-tagged");
});

test("with no claim, the panel says everyone is paged", async ({ page }) => {
  await openHandoff(page);
  await expect(page.getByTestId("perch-watch-claim")).toHaveAttribute(
    "data-claim-state",
    "none",
  );
});

test("no take control exists while the claim's home is undecided", async ({
  page,
}) => {
  // A disabled button asserts the action exists.
  await openHandoff(page);
  await expect(page.getByTestId("perch-take-watch")).toHaveCount(0);
  await expect(page.getByTestId("perch-watch-claim-undecided")).toBeVisible();
});

test("the handoff promises no daemon-side record", async ({ page }) => {
  // W3-36: there is no shift record to promise, so the copy names the case
  // channels rather than a session id that was never minted.
  await openHandoff(page);
  await expect(page.getByTestId("perch-end-watch")).toContainText(
    "daemon keeps no shift record",
  );
});
