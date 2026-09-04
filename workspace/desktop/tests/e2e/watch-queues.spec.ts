import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import { waitForAnimations } from "../helpers/animations";
import { installMockBridge } from "../helpers/bridge";
import {
  installPerchWatchBridge,
  PERCH_HOLD_A,
  PERCH_HOLD_B,
  perchHold,
  waitForPerchQueue,
} from "../helpers/perchBridge";

/**
 * The Watch, on a mock daemon.
 *
 * Order matters and is the reason for one helper rather than three inline
 * calls: the fixture and the `perch` opt-in both have to be in place before
 * `page.goto`, because the console's first daemon read is on mount.
 * `installPerchWatchBridge` does both in that order.
 */
async function openTheWatch(
  page: Page,
  seed: Parameters<typeof installPerchWatchBridge>[1] = {},
) {
  await installPerchWatchBridge(page, seed);
  await page.goto("/");
  await waitForPerchQueue(page);
}

test("the four queues render with their ratified labels and holds sort oldest first", async ({
  page,
}) => {
  await openTheWatch(page, {
    holds: [
      perchHold({ hold_id: PERCH_HOLD_B, ageMs: 30_000 }),
      perchHold({ hold_id: PERCH_HOLD_A, ageMs: 300_000 }),
    ],
  });
  await waitForAnimations(page);

  for (const label of ["Holds", "Findings to review", "Case activity"]) {
    await expect(page.getByRole("heading", { name: label })).toBeVisible();
  }
  // NAMED YOU is the one queue that disappears rather than reading zero, and
  // the mock relay feed carries a mention for this identity — so here it is
  // present WITH its count. The absent-when-empty half is the unit contract
  // (`watchQueues.test.mjs`), because this bridge has no seam for an empty
  // relay feed.
  await expect(page.getByRole("heading", { name: "Named you" })).toBeVisible();
  await expect(page.getByTestId("perch-queue-count-named-you")).toHaveAttribute(
    "data-perch-count-known",
    "true",
  );

  const rows = page.locator('[data-testid^="perch-queue-row-"]');
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toHaveAttribute(
    "data-testid",
    `perch-queue-row-${PERCH_HOLD_A}`,
  );
  await expect(page.getByTestId("perch-queue-count-holds")).toHaveText("2");
  await expect(page.getByTestId("perch-watch")).toHaveAttribute(
    "data-perch-queue-reconciled",
    "true",
  );
});

test("with the daemon unreachable the count is unavailable, never zero, and nothing reassures", async ({
  page,
}) => {
  await openTheWatch(page, {
    holds: [perchHold()],
    daemonError: "daemon unreachable: connection refused",
  });

  const count = page.getByTestId("perch-queue-count-holds");
  await expect(count).toContainText("count unavailable");
  await expect(count).toHaveAttribute("data-perch-count-known", "false");
  await expect(page.getByTestId("perch-queue-holds")).not.toContainText(
    /all clear|no data|caught up|everything looks good/i,
  );
  await expect(page.getByTestId("perch-watch")).toHaveAttribute(
    "data-perch-queue-reconciled",
    "false",
  );
  // The refusal names what failed rather than showing an empty list.
  await expect(
    page.locator('[data-perch-role="unavailable-note"]').first(),
  ).toContainText("cannot say what is held");
});

test("an expired hold stays in the queue and says no action was taken", async ({
  page,
}) => {
  await openTheWatch(page, {
    holds: [
      perchHold({
        hold_id: PERCH_HOLD_A,
        state: "expired",
        expired: true,
        remaining_ms: 0,
      }),
    ],
  });

  const row = page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`);
  await expect(row).toHaveAttribute("data-perch-row-kind", "expired");
  await expect(row.getByTestId("perch-hold-ttl")).toHaveAttribute(
    "data-perch-ttl-state",
    "expired",
  );
  await expect(row.getByTestId("perch-hold-ttl-expired")).toContainText(
    "no action was taken",
  );
});

test("twelve open holds trip the queue-depth alarm and a non-durable store says so", async ({
  page,
}) => {
  await openTheWatch(page, {
    holds: [perchHold({ hold_id: PERCH_HOLD_A })],
    openCount: 12,
    storeDurable: false,
  });

  await expect(page.getByTestId("perch-counter-strip")).toHaveAttribute(
    "data-perch-queue-depth-alarm",
    "true",
  );
  await expect(
    page.locator('[data-perch-counter="perch_queue_open_count"]'),
  ).toHaveAttribute("data-perch-counter-value", "12");
  await expect(page.getByTestId("perch-store-not-durable")).toContainText(
    "a restart forgets every open hold",
  );
});

test("a decided hold leaves the queue rather than asking the same question twice", async ({
  page,
}) => {
  await openTheWatch(page, {
    holds: [
      perchHold({ hold_id: PERCH_HOLD_A, state: "executed" }),
      perchHold({ hold_id: PERCH_HOLD_B, state: "notified" }),
    ],
  });

  await expect(page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`)).toHaveCount(
    0,
  );
  await expect(
    page.getByTestId(`perch-queue-row-${PERCH_HOLD_B}`),
  ).toBeVisible();
  await expect(page.getByTestId("perch-queue-count-holds")).toHaveText("1");
});

test("an empty holds queue states a governing number rather than reassuring", async ({
  page,
}) => {
  await openTheWatch(page, { holds: [] });

  await expect(page.getByTestId("perch-queue-count-holds")).toHaveText("0");
  const empty = page.locator('[data-perch-role="empty-state"]').first();
  await expect(empty).toHaveAttribute(
    "data-perch-empty-kind",
    "governing-number",
  );
  await expect(empty).toContainText("ran without one");
  await expect(page.getByTestId("perch-queue-holds")).not.toContainText(
    /all clear|caught up|everything looks good/i,
  );
});

test("the relay's failure does not empty the holds queue, and its own queues say so", async ({
  page,
}) => {
  // The two backends fail independently, which is the whole reason HOLDS has
  // an authority and the other three do not. A relay that cannot answer must
  // not be able to make the daemon's holds disappear.
  await installPerchWatchBridge(
    page,
    { holds: [perchHold({ hold_id: PERCH_HOLD_A })] },
    { feedReadError: "relay unreachable: connection refused" },
  );
  await page.goto("/");
  await waitForPerchQueue(page);

  await expect(
    page.getByTestId(`perch-queue-row-${PERCH_HOLD_A}`),
  ).toBeVisible();
  await expect(page.getByTestId("perch-queue-count-holds")).toHaveText("1");
  for (const queue of ["named-you", "findings", "case-activity"]) {
    await expect(page.getByTestId(`perch-queue-count-${queue}`)).toContainText(
      "count unavailable",
    );
  }
  // Neither side answered completely, so the screen does not claim it did.
  await expect(page.getByTestId("perch-watch")).toHaveAttribute(
    "data-perch-queue-reconciled",
    "false",
  );
});

test("the perch flag is off by default, so Home still renders without opting in", async ({
  page,
}) => {
  // The seam's other half. `perch` is excluded from the bridge's blanket
  // preview-feature seeding, so a spec that does not opt in sees Home.
  await installMockBridge(page);
  await page.goto("/");
  await expect(page.getByTestId("perch-watch")).toHaveCount(0);
});
