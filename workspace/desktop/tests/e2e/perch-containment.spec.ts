import { expect, test, type Page } from "@playwright/test";

import { installPerchBridge } from "../helpers/perchBridge";

/**
 * `/leases` — the containments the daemon still holds open.
 *
 * The assertions here are all about the same thing: this board must never
 * render a host as free when it is not. Every state that could be mistaken for
 * "released" gets its own check.
 */

const OPEN_LEASE = {
  lease_id: "cl_open",
  action_kind: "isolate_host",
  scope_value: "web-04",
  origin_receipt_id: "r1",
  governance_receipt_id: "g1",
  issued_at_ms: 1_000,
  expires_at_ms: 9_999_999_999_999,
  remaining_ms: 600_000,
  expired: false,
};

/**
 * `remaining_ms` saturates at zero, so `0/false` and `0/true` are two
 * different facts and this is the second one: the sweep tried and failed.
 */
const EXPIRED_LEASE = {
  ...OPEN_LEASE,
  lease_id: "cl_expired",
  scope_value: "db-01",
  remaining_ms: 0,
  expired: true,
};

/**
 * Reach the board the way an operator does.
 *
 * `page.goto("/leases")` 404s: the preview server serves static files and does
 * not rewrite SPA routes, so a deep link never reaches the router. Navigating
 * from `/` through the nav is both what works and what a person does.
 */
async function gotoPerch(page: Page, surface: string): Promise<void> {
  await page.getByTestId(`perch-nav-${surface}`).click();
}

async function openBoard(
  page: Page,
  containments: readonly Record<string, unknown>[],
): Promise<void> {
  await installPerchBridge(page, { containments });
  await page.goto("/");
  await gotoPerch(page, "containments");
  await expect(page.getByTestId("perch-containments")).toBeVisible();
}

test("an open containment lists the host it is holding", async ({ page }) => {
  await openBoard(page, [OPEN_LEASE]);
  await expect(page.getByTestId("perch-containments")).toContainText("web-04");
});

test("an expired lease still says the host may be contained", async ({
  page,
}) => {
  // The one reading this board must not produce: a lease past its expiry and
  // still listed means the sweep failed, not that the host is free.
  await openBoard(page, [EXPIRED_LEASE]);
  const board = page.getByTestId("perch-containments");
  await expect(board).toContainText("db-01");
  await expect(board).toContainText(/EXPIRED/);
});

test("no open containment is stated as such, and never as an error", async ({
  page,
}) => {
  await openBoard(page, []);
  await expect(page.getByTestId("perch-containments")).toContainText(
    /No open containments/i,
  );
});

test("release asks first, and the dialog names the inverse and the target", async ({
  page,
}) => {
  await openBoard(page, [OPEN_LEASE]);
  await page.getByTestId("perch-containment-release-cl_open").click();
  const dialog = page.getByTestId("perch-release-dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("web-04");
  await expect(dialog).toContainText("isolate_host");
});

test("a 200 with lease_closed false renders in the error register, not as success", async ({
  page,
}) => {
  // The daemon answered. The inverse failed. The host is still contained.
  await installPerchBridge(page, {
    containments: [OPEN_LEASE],
    release: {
      lease_closed: false,
      fully_reversed: false,
      attestation_verified: true,
      attestation_error: null,
      steps: [],
    },
  });
  await page.goto("/");
  await gotoPerch(page, "containments");
  await expect(page.getByTestId("perch-containments")).toBeVisible();

  await page.getByTestId("perch-containment-release-cl_open").click();
  await page.getByTestId("perch-release-confirm").click();

  const notClosed = page.getByTestId("perch-release-not-closed");
  await expect(notClosed).toBeVisible();
  await expect(notClosed).toHaveAttribute("data-perch-register", "error");
  await expect(notClosed).toHaveAttribute("role", "alert");
  await expect(notClosed).toContainText("still in effect");
  // And the dialog stays open: closing on confirm would hide exactly this.
  await expect(page.getByTestId("perch-release-dialog")).toBeVisible();
});

test("the partition section is absent while governance is healthy", async ({
  page,
}) => {
  // Always present with zeroes would train an operator to skip the one place
  // the console reports actions taken without authorization.
  await openBoard(page, [OPEN_LEASE]);
  await expect(page.getByTestId("perch-partition-section")).toHaveCount(0);
});

test("no extend control exists anywhere on the board", async ({ page }) => {
  // A containment lease cannot be extended; a disabled control would assert
  // the action exists.
  await openBoard(page, [OPEN_LEASE]);
  await expect(page.getByRole("button", { name: /extend/i })).toHaveCount(0);
});
