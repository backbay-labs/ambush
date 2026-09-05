import { expect, test, type Page } from "@playwright/test";

import { installPerchBridge } from "../helpers/perchBridge";

/**
 * `/watch-floor` — the room's screen.
 *
 * Read from across a room by someone who did not open it and will not check a
 * tooltip, so every assertion here is about an absence rendering as an absence
 * rather than as a zero.
 */

async function openWall(page: Page): Promise<void> {
  // `page.goto("/watch-floor")` 404s: the preview server does not rewrite SPA
  // routes. Navigating from `/` is what works and what a person does.
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId("perch-nav-watchfloor").click();
  await expect(page.getByTestId("perch-watchfloor")).toBeVisible();
}

test("with no concentration frame the wall says it was not told, never zero", async ({
  page,
}) => {
  await openWall(page);
  const empty = page.getByTestId("perch-watchfloor-no-frame");
  await expect(empty).toBeVisible();
  await expect(empty).toContainText("not a concentration of zero");
});

test("with no health frame the colony band says the same", async ({ page }) => {
  await openWall(page);
  await expect(page.getByTestId("perch-watchfloor-colony")).toContainText(
    "not zero agents",
  );
});

test("an unknown mode is unknown, never normal", async ({ page }) => {
  // Rendering "normal" for a mode nobody reported is the reassurance this
  // screen exists to refuse.
  await openWall(page);
  await expect(page.getByTestId("perch-watchfloor-mode")).toContainText(
    "unknown, not normal",
  );
});

test("the wall states that it changes nothing", async ({ page }) => {
  await openWall(page);
  await expect(page.getByTestId("perch-watchfloor")).toContainText(
    "changes nothing",
  );
});

test("the governance strip survives the wall", async ({ page }) => {
  // The state it reports is the state in which every other number on this
  // screen becomes untrustworthy.
  await openWall(page);
  await expect(page.getByTestId("perch-governance-strip")).toBeVisible();
});

test("the decay band names the curve as an interpolation", async ({ page }) => {
  await openWall(page);
  await expect(page.getByTestId("perch-watchfloor-decay")).toContainText(
    "curve is an interpolation",
  );
});

test("liveness is attributed to the health stream and not to presence", async ({
  page,
}) => {
  // A dead agent reads online for up to 180s on Nostr presence, so the band
  // says where its answer comes from.
  await openWall(page);
  await expect(page.getByTestId("perch-watchfloor-colony")).toContainText(
    "never Nostr presence",
  );
});
