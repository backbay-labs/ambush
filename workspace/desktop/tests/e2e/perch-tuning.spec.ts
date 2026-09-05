import { expect, test, type Page } from "@playwright/test";
import {
  installPerchBridge,
  type PerchMockFixture,
} from "../helpers/perchBridge";

/**
 * `/tuning` — every field of a recommendation with its denominators, the
 * empty state naming the minimums, and no way to apply anything.
 */
async function openTuning(
  page: Page,
  fixture?: PerchMockFixture,
): Promise<void> {
  await installPerchBridge(page, fixture);
  await page.goto("/");
  await page.getByTestId("perch-nav-tuning").click();
  await expect(page.getByTestId("perch-tuning-screen")).toBeVisible();
}

test("a recommendation renders every field the daemon carries, numbers with denominators", async ({
  page,
}) => {
  await openTuning(page);
  const card = page.getByTestId("perch-tuning-card-0");
  await expect(card).toBeVisible();
  await expect(card).toContainText("Detector rule review");
  await expect(page.getByTestId("perch-tuning-priority-0")).toHaveText("high");
  await expect(card).toContainText("suspicious_process_tree");
  await expect(card).toContainText("host-ops-1");
  await expect(card).toContainText("dismissed more often than it is confirmed");
  await expect(card).toContainText("parent-process allowlist");
  await expect(page.getByTestId("perch-tuning-basis-0")).toContainText(
    "2 of 3 · 0.67",
  );
  await expect(
    page.getByTestId("perch-tuning-signals-0").locator("li"),
  ).toHaveCount(1);
  await expect(card).toContainText("not verdict timestamps");
  await expect(page.getByTestId("perch-tuning-ledger-0")).toHaveAttribute(
    "href",
    /\/ledger\?q=agent%3Asuspicious_process_tree/,
  );
});

test("an empty report names the three minimums and links to the watch", async ({
  page,
}) => {
  await openTuning(page, {
    operatorStatus: {
      captured_at_ms: 1,
      alert_tuning: {
        reviewed_findings: 1,
        false_positive_findings: 0,
        recommendation_count: 0,
        recommendations: [],
      },
    },
  });
  const empty = page.getByTestId("perch-tuning-empty");
  await expect(empty).toContainText("No recommendations yet");
  await expect(empty).toContainText(
    "3 reviewed findings and 2 false positives",
  );
  await expect(empty).toContainText("needs 4 and 2");
  await expect(empty).toContainText("needs 2 and 2");
  await expect(empty).toContainText("1 reviewed, 0 false positive");
  await expect(page.getByTestId("gap-link")).toHaveCount(0);
  // Hash history in the E2E build renders `/#/`; the path is what matters.
  await expect(page.getByTestId("perch-tuning-open-watch")).toHaveAttribute(
    "href",
    /\/$/,
  );
});

test("nothing on the bench applies anything", async ({ page }) => {
  await openTuning(page);
  const screen = page.getByTestId("perch-tuning-screen");
  await expect(screen.getByText(/apply/i)).toHaveCount(0);
  await expect(screen.locator("button")).toHaveCount(0);
});
