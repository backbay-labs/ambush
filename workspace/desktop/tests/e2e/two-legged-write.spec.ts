import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  PERCH_HOLD_A,
  perchHold,
  perchRecordedVerdicts,
  installPerchWatchBridge,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * The two-legged write, through every terminal state.
 *
 * Refuse is the driver rather than grant: it reaches the same machine in one
 * keypress with no dwell, so these tests are about the WRITE and not about the
 * gate, which `grant-two-stroke.spec.ts` owns.
 */
async function openHold(
  page: Page,
  seed: Parameters<typeof installPerchWatchBridge>[1] = {},
) {
  await installPerchWatchBridge(page, {
    holds: [perchHold({ hold_id: PERCH_HOLD_A })],
    ...seed,
  });
  await page.goto("/");
  await waitForPerchQueue(page);
  await page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`).click();
  await expect(page.getByTestId("perch-verdict-pane")).toBeVisible();
}

test("a decision passes through recorded before it is ever acknowledged", async ({
  page,
}) => {
  // The delay makes the ordering observable. `recorded` means the relay took
  // the signed intent; `acknowledged` means the daemon acted. A console that
  // showed the second without the first would be reporting an outcome for a
  // decision it had not written down.
  await openHold(page, { decideDelayMs: 1_200 });
  await page.keyboard.press("r");

  await expect(
    page.locator('[data-perch-decision-state="recorded"]'),
  ).toBeVisible();
  await expect(page.getByTestId("perch-write-state-recorded")).toContainText(
    "The decision exists whatever the daemon answers next",
  );
  await expect(
    page.locator('[data-perch-decision-state="acknowledged"]'),
  ).toBeVisible({ timeout: 10_000 });
  // No undo, at any point in the sequence.
  await expect(page.getByTestId("perch-decision-undo")).toHaveCount(0);
});

test("a late refusal is an outcome, not an error, and names its rule", async ({
  page,
}) => {
  await openHold(page, {
    decide: {
      outcome: "refused_late",
      rule: "runtime.containment_refused",
      reason: "no containment lease store is configured",
    },
  });
  await page.keyboard.press("r");

  const row = page.locator('[data-perch-decision-state="refused_late"]');
  await expect(row).toBeVisible();
  await expect(row).toContainText("after your decision was recorded");
  await expect(row).toContainText("The action was never taken");
  await expect(
    page.getByTestId("perch-write-state-refusal-rule"),
  ).toContainText("runtime.containment_refused");
  // Announced, because a refusal is the one state the operator must not miss.
  await expect(row).toHaveAttribute("role", "alert");
});

test("an unreachable daemon leaves the decision recorded and says it cannot tell", async ({
  page,
}) => {
  await openHold(page);
  await page.evaluate(() => {
    window.__AMBUSH_E2E_PERCH_CONTROL__?.setDaemonError(
      "daemon unreachable: connection refused",
    );
  });
  await page.keyboard.press("r");

  const row = page.locator('[data-perch-decision-state="unreachable"]');
  await expect(row).toBeVisible();
  await expect(row).toContainText("recorded on the case");
  await expect(row).toContainText("cannot say whether it ran");
  // Leg 1 happened. The console does not pretend otherwise.
  expect(await perchRecordedVerdicts(page)).toHaveLength(1);
});

test("leg 1 failing means no leg 2 was ever attempted", async ({ page }) => {
  // The ordering, from the other side. A machine that POSTed the daemon call
  // regardless would have acted on a decision with no signed record of who
  // asked for it.
  await openHold(page, {
    legOneError: "relay refused the verdict card: rate limited",
  });
  await page.keyboard.press("r");

  await expect(
    page.locator('[data-perch-decision-state="unreachable"]'),
  ).toContainText("intent card could not be published");
  expect(await perchRecordedVerdicts(page)).toEqual([]);
});

test("losing the compare-and-set is superseded, and the losing card says so on the case", async ({
  page,
}) => {
  // The two-console rule. Both cards are genuine and both stay in the case
  // channel forever, so the loser publishes an update naming the winner —
  // otherwise a reader next month cannot tell which of two signed verdicts ran.
  const winner = "cc".repeat(32);
  await openHold(page, {
    decide: {
      outcome: "superseded",
      rule: "hold_already_decided",
      reason: "another operator's decision was recorded first",
      superseded_by: winner,
      winning_decision: "grant",
    },
  });
  await page.keyboard.press("r");

  const row = page.locator('[data-perch-decision-state="superseded"]');
  await expect(row).toBeVisible();
  await expect(row).toContainText("did not run");
  await expect(row).toContainText("grant");
  await expect(
    page.getByTestId("perch-write-state-superseded-winner"),
  ).toContainText(winner);

  const recorded = await perchRecordedVerdicts(page);
  expect(recorded).toHaveLength(1);
  expect(
    recorded[0].supersededBy,
    "the losing leg-1 card was updated to name the winner",
  ).toBe(winner);
});

test("the winning decision is never guessed from the daemon's prose", async ({
  page,
}) => {
  // W3-17: the 409 body carries `{error, message}` and nothing else, so the
  // winner comes from a re-read. A console that searched the free-text reason
  // for a verb would read this one exactly backwards.
  await openHold(page, {
    decide: {
      outcome: "superseded",
      rule: "hold_already_decided",
      reason: "the other operator did not refuse; they granted it",
      superseded_by: "cc".repeat(32),
      winning_decision: null,
    },
  });
  await page.keyboard.press("r");

  const row = page.locator('[data-perch-decision-state="superseded"]');
  await expect(row).toBeVisible();
  await expect(row).toContainText("Another operator's decision was the one");
  await expect(row).not.toContainText("ran: refuse");
});

test("an expired hold refuses with the expiry rather than a transport error", async ({
  page,
}) => {
  await openHold(page, { decide: { outcome: "expired" } });
  await page.keyboard.press("r");
  const row = page.locator('[data-perch-decision-state="refused_late"]');
  await expect(row).toBeVisible();
  await expect(
    page.getByTestId("perch-write-state-refusal-rule"),
  ).toContainText("hold_expired");
});
