import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  PERCH_HOLD_A,
  perchHold,
  perchRecordedVerdicts,
  readBlastRadius,
  installPerchWatchBridge,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * The two-stroke grant, and the gate in front of its second stroke.
 *
 * The tests that matter here are the NEGATIVE CONTROLS: each one performs the
 * complete recording sequence with the gate's precondition missing, and each
 * one must record nothing. A suite that only drove the sequence that works
 * would pass identically against a control with no gate at all.
 */
async function openHold(page: Page, viewport = { width: 1280, height: 300 }) {
  await page.setViewportSize(viewport);
  await installPerchWatchBridge(page, {
    holds: [perchHold({ hold_id: PERCH_HOLD_A })],
  });
  await page.goto("/");
  await waitForPerchQueue(page);
  await page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`).click();
  await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();
}

test("the full two-stroke records NOTHING while the blast radius has not been read", async ({
  page,
}) => {
  // The negative control. A short viewport keeps the BLAST RADIUS block out of
  // view; the operator arms, waits well past the dwell, and presses Enter.
  await openHold(page);
  await page.getByTestId("perch-queue-holds").scrollIntoViewIfNeeded();

  await page.keyboard.press("g");
  await expect(page.getByTestId("perch-grant-armed")).toBeVisible();

  await page.waitForTimeout(2_500);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(300);

  expect(await perchRecordedVerdicts(page)).toEqual([]);
  await expect(page.getByTestId("perch-grant-record")).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  await expect(page.getByTestId("perch-grant-dwell")).toContainText(
    /read the blast radius first|keep the blast radius in view/,
  );
  // No write state exists, because no write started.
  await expect(page.locator("[data-perch-decision-state]")).toHaveCount(0);
});

test("clicking the control while the gate is shut records nothing either", async ({
  page,
}) => {
  // The same negative control through the pointer, because a keyboard-only
  // gate is a gate with a mouse-shaped hole in it.
  await openHold(page);
  await page.getByTestId("perch-queue-holds").scrollIntoViewIfNeeded();
  await page.getByTestId("perch-grant-record").click({ force: true });
  await page.waitForTimeout(300);
  expect(await perchRecordedVerdicts(page)).toEqual([]);
});

test("a held G does not arm: a held key is one intention, not forty", async ({
  page,
}) => {
  await openHold(page);
  await page.evaluate(() => {
    window.dispatchEvent(
      new KeyboardEvent("keydown", { key: "g", repeat: true, bubbles: true }),
    );
  });
  await expect(page.getByTestId("perch-grant-armed")).toHaveCount(0);
});

test("Enter without arming records nothing, even with the gate open", async ({
  page,
}) => {
  await openHold(page, { width: 1280, height: 1400 });
  await readBlastRadius(page);
  await expect(page.getByTestId("perch-grant-record")).toHaveAttribute(
    "aria-disabled",
    "false",
  );
  await expect(page.getByTestId("perch-grant-armed")).toHaveCount(0);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(300);
  expect(await perchRecordedVerdicts(page)).toEqual([]);
});

test("with the blast radius read, arming plus Enter records exactly one decision", async ({
  page,
}) => {
  // The positive control. It is only meaningful beside the three above.
  await openHold(page, { width: 1280, height: 1400 });
  await readBlastRadius(page);
  await page.keyboard.press("g");
  await expect(page.getByTestId("perch-grant-armed")).toBeVisible();
  await page.keyboard.press("Enter");

  await expect(
    page.locator('[data-perch-decision-state="acknowledged"]'),
  ).toBeVisible();
  const recorded = await perchRecordedVerdicts(page);
  expect(recorded).toHaveLength(1);
  expect(recorded[0].decision).toBe("grant");
  expect(recorded[0].holdId).toBe(PERCH_HOLD_A);
});

test("refuse takes one keypress, no dialog, and no dwell at all", async ({
  page,
}) => {
  // The asymmetry is the design: refusing dispatches nothing, so nothing needs
  // to be understood before it is safe. The short viewport is deliberate —
  // the blast radius is NOT read here and the refusal still lands.
  await openHold(page);
  await page.getByTestId("perch-queue-holds").scrollIntoViewIfNeeded();
  await page.keyboard.press("r");

  await expect(
    page.locator('[data-perch-decision-state="acknowledged"]'),
  ).toBeVisible();
  const recorded = await perchRecordedVerdicts(page);
  expect(recorded).toHaveLength(1);
  expect(recorded[0].decision).toBe("refuse");
  // One keypress: no dialog appeared between the key and the record.
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
});

test("the grant control is not the app's default button variant", async ({
  page,
}) => {
  // INV-10. A grant styled as the happy-path action is a grant an operator can
  // press without reading, which is what the dwell exists to prevent.
  await openHold(page, { width: 1280, height: 1400 });
  const control = page.getByTestId("perch-grant-record");
  await expect(control).toHaveAttribute("data-perch-role", "grant");
  const className = await control.getAttribute("class");
  expect(className ?? "").not.toContain("bg-primary");
});
