import { expect, test, type Page } from "@playwright/test";

import { installPerchBridge } from "../helpers/perchBridge";

/**
 * The ⌘K omnibox.
 *
 * Every assertion is about the same rule: it emits an intent and never
 * performs a write. A destructive verb one keystroke from every surface is
 * what the render laws forbid.
 */

async function openOmnibox(page: Page): Promise<void> {
  await installPerchBridge(page);
  await page.goto("/");
  // Move focus off any composer first. The composer owns ⌘K for its link
  // dialog and calls preventDefault, and the shell's handler returns early on
  // `defaultPrevented` — by design, so a more specific surface wins.
  await page.getByTestId("perch-nav").click();
  await page.keyboard.press("ControlOrMeta+k");
  await expect(page.getByTestId("perch-omnibox")).toBeVisible();
}

test("plain text is a search, not a command", async ({ page }) => {
  await openOmnibox(page);
  await page.getByTestId("perch-omnibox-input").fill("strength > 2");
  // `>` switches modes only as the FIRST character: `strength > 2` is a query
  // an operator will type, and swallowing it as a command loses the search.
  await expect(page.getByTestId("perch-omnibox-mode")).toHaveAttribute(
    "data-mode",
    "query",
  );
});

test("a leading angle bracket switches to command mode", async ({ page }) => {
  await openOmnibox(page);
  await page.getByTestId("perch-omnibox-input").fill(">open leases");
  await expect(page.getByTestId("perch-omnibox-mode")).toHaveAttribute(
    "data-mode",
    "command",
  );
});

test("a matched command states its consequence before enter", async ({
  page,
}) => {
  // A palette whose entries do not say what they do is one people learn by
  // pressing things.
  await openOmnibox(page);
  await page.getByTestId("perch-omnibox-input").fill(">open watchfloor");
  await expect(page.getByTestId("perch-omnibox-consequence")).toContainText(
    "changes nothing",
  );
});

test("release containment navigates and releases nothing", async ({ page }) => {
  await openOmnibox(page);
  await page
    .getByTestId("perch-omnibox-input")
    .fill(">release containment cl_9b3645fc");
  await expect(page.getByTestId("perch-omnibox-consequence")).toContainText(
    "the daemon is asked only from that surface",
  );
  await page.getByTestId("perch-omnibox-input").press("Enter");

  // It lands on Containments. It does not open a confirmation, and it
  // certainly does not release: a deep link that pre-confirmed a destructive
  // action would be a write path around the board's own gate.
  await expect(page.getByTestId("perch-containments")).toBeVisible();
  await expect(page.getByTestId("perch-release-dialog")).toHaveCount(0);
});

test("an unknown command matches nothing and says so", async ({ page }) => {
  await openOmnibox(page);
  await page.getByTestId("perch-omnibox-input").fill(">delete everything");
  await expect(page.getByTestId("perch-omnibox-no-match")).toBeVisible();
});

test("a capability lease id is not accepted where a containment lease is meant", async ({
  page,
}) => {
  // `cap-` names a different object with a different lifetime, and releasing
  // one because it looked like the other is not a mistake an operator can undo.
  await openOmnibox(page);
  await page
    .getByTestId("perch-omnibox-input")
    .fill(">release containment cap-9b3645fc");
  await expect(page.getByTestId("perch-omnibox-no-match")).toBeVisible();
});

test("a query navigates to the Ledger carrying the text", async ({ page }) => {
  await openOmnibox(page);
  await page.getByTestId("perch-omnibox-input").fill("isolate web-04");
  await page.getByTestId("perch-omnibox-input").press("Enter");
  await expect(page.getByTestId("perch-ledger")).toBeVisible();
  // The Ledger owns the search; the omnibox routes to it rather than adding a
  // second search path.
  await expect(page.getByTestId("perch-ledger-query")).toHaveValue(
    "isolate web-04",
  );
});
