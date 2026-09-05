import { expect, type Page, test } from "@playwright/test";
import { installMockBridge } from "../helpers/bridge";
import { installPerchBridge } from "../helpers/perchBridge";

/**
 * Settings → Detector: this console's decision key, and the sidecar panel
 * that existed before it was mounted anywhere.
 */

/** `open-settings` opens the profile popover; its Settings item opens the view. */
async function openSettings(page: Page): Promise<void> {
  await page.getByTestId("open-settings").click();
  await page.getByTestId("profile-popover-settings").click();
  await expect(page.getByTestId("settings-view")).toBeVisible();
}
test("the detector section shows the decision key the daemon must pin", async ({
  page,
}) => {
  await installPerchBridge(page);
  await page.goto("/");
  await openSettings(page);
  await page.getByTestId("settings-nav-detector").click();
  await expect(page.getByTestId("perch-operator-key")).toHaveText(
    "dd".repeat(32),
  );
  await expect(page.getByTestId("perch-operator-key-id")).toContainText(
    "key id",
  );
  await expect(page.getByTestId("perch-sidecar-status")).toHaveAttribute(
    "data-healthz",
    "never-started",
  );
});

test("without the perch feature the section is not offered", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/");
  await openSettings(page);
  await expect(page.getByTestId("settings-nav-profile")).toBeVisible();
  await expect(page.getByTestId("settings-nav-detector")).toHaveCount(0);
});
