import { expect, test, type Page } from "@playwright/test";
import { installPerchBridge } from "../helpers/perchBridge";

/**
 * `/policy` — rules in file order, shadowing evaluated per triple by the
 * daemon (the mock evaluates the way the daemon does), read-only.
 */
async function openPolicy(page: Page): Promise<void> {
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId("perch-nav-policy").click();
  await expect(page.getByTestId("perch-policy")).toBeVisible();
  await expect(page.getByTestId("perch-policy-decider")).toHaveAttribute(
    "data-source",
    "daemon",
  );
}

test("the default triple is decided by the C2 rule, which outranks the human gate", async ({
  page,
}) => {
  await openPolicy(page);
  await expect(page.getByTestId("perch-policy-rule-0")).toHaveAttribute(
    "data-verdict",
    "not_matched",
  );
  await expect(page.getByTestId("perch-policy-rule-1")).toHaveAttribute(
    "data-verdict",
    "decides",
  );
  await expect(page.getByTestId("perch-policy-rule-2")).toHaveAttribute(
    "data-verdict",
    "not_reached",
  );
  await expect(page.getByTestId("perch-policy-decider")).toContainText(
    "Rule 1 (command-and-control-emergency-block) decides this triple.",
  );
  await expect(page.getByTestId("perch-policy-outranks")).toContainText(
    "OUTRANKS THE HUMAN GATE",
  );
  await expect(page.getByTestId("perch-policy-source")).toContainText(
    "Read-only",
  );
});

test("dropping the severity to HIGH un-matches the C2 rule and falls through to the static hold", async ({
  page,
}) => {
  await openPolicy(page);
  await page.getByTestId("perch-policy-severity").selectOption("HIGH");
  await expect(page.getByTestId("perch-policy-rule-1")).toHaveAttribute(
    "data-verdict",
    "not_matched",
  );
  await expect(page.getByTestId("perch-policy-decider")).toContainText(
    "require_human",
  );
  await expect(page.getByTestId("perch-policy-outranks")).toHaveCount(0);
});

test("a deny rule renders its word as the wire value and never as a control", async ({
  page,
}) => {
  await openPolicy(page);
  await page
    .getByTestId("perch-policy-threat-class")
    .selectOption("credential_access");
  await page.getByTestId("perch-policy-severity").selectOption("HIGH");
  await page
    .getByTestId("perch-policy-action")
    .selectOption("revoke_credential");
  await expect(page.getByTestId("perch-policy-rule-2")).toHaveAttribute(
    "data-verdict",
    "decides",
  );
  await expect(
    page.getByTestId("perch-policy-rule-2").locator("code"),
  ).toHaveText("deny");
  await expect(page.getByTestId("perch-policy-outranks")).toHaveCount(0);
});
