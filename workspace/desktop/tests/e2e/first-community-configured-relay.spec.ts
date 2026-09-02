import { expect, test, type Page } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";
import { seedActiveIdentity } from "../helpers/onboarding";

// The first-run screen offers the relay this instance is configured to use.
// The offer is resolved from that relay's live NIP-11 document — the mock
// bridge does not intercept `fetch` — so these tests need the relay actually
// running, which is what the integration project provides.
const RELAY_HTTP_URL =
  process.env.AMBUSH_E2E_RELAY_URL ?? "http://localhost:3000";
const RELAY_WS_URL = RELAY_HTTP_URL.replace(/^http/, "ws");

const FIRST_RUN_TYLER = { ...TEST_IDENTITIES.tyler, username: "" };

test.beforeAll(async () => {
  const response = await fetch(RELAY_HTTP_URL, {
    headers: { Accept: "application/nostr+json" },
  }).catch(() => null);
  if (!response?.ok) {
    throw new Error(
      `No relay answering at ${RELAY_HTTP_URL}. Start one (\`just relay\`) before running this spec.`,
    );
  }
});

/** Land on the first-run community screen with no community configured yet. */
async function openFirstRunScreen(page: Page) {
  await seedActiveIdentity(page, FIRST_RUN_TYLER);
  await page.addInitScript((pubkey) => {
    window.localStorage.setItem(
      `ambush-machine-onboarding-complete.v2:${pubkey}`,
      "true",
    );
  }, FIRST_RUN_TYLER.pubkey);
  await installMockBridge(page, undefined, {
    relayWsUrl: RELAY_WS_URL,
    skipOnboardingSeed: true,
    skipCommunitySeed: true,
  });
  await page.goto("/");
  await expect(page.getByTestId("welcome-setup")).toBeVisible();
}

function storedCommunities(page: Page) {
  return page.evaluate(
    () =>
      JSON.parse(window.localStorage.getItem("ambush-communities") ?? "[]") as
        | Array<{ id: string; name: string; relayUrl: string }>
        | [],
  );
}

test("the configured relay is offered on the first-run screen and joins in one click", async ({
  page,
}) => {
  await openFirstRunScreen(page);

  const configuredChoice = page.getByTestId("community-choice-configured");
  await expect(configuredChoice).toBeVisible();
  await expect(configuredChoice).toContainText(/^Reconnect to \S/);
  await expect(configuredChoice).toContainText(RELAY_WS_URL);

  await configuredChoice.click();

  await expect(
    page.getByRole("heading", { name: "Build your profile" }),
  ).toBeVisible();
  await page.getByTestId("community-profile-name-key").fill("Tyler");
  await page.getByTestId("community-profile-next").click();
  await page.getByTestId("community-team-intro-enter").click();

  await expect(page.getByTestId("community-onboarding-flow")).toHaveCount(0, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("app-sidebar")).toBeVisible();

  const communities = await storedCommunities(page);
  expect(communities).toHaveLength(1);
  expect(communities[0]?.relayUrl).toBe(RELAY_WS_URL);
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.localStorage.getItem("ambush-active-community-id"),
      ),
    )
    .toBe(communities[0]?.id);
});

test("the member path opens pre-filled with the configured relay", async ({
  page,
}) => {
  await openFirstRunScreen(page);

  // The offer resolving is what pre-fills the form; wait for it before
  // navigating so the assertion cannot race the probe.
  await expect(page.getByTestId("community-choice-configured")).toBeVisible();
  await page.getByTestId("community-choice-existing").click();
  await page.getByTestId("existing-choice-member").click();

  await expect(page.getByTestId("invite-redeem-input")).toHaveValue(
    RELAY_WS_URL,
  );
  await expect(page.getByTestId("invite-redeem-submit")).toBeEnabled();

  await page.getByTestId("invite-redeem-submit").click();
  await expect(
    page.getByRole("heading", { name: "Build your profile" }),
  ).toBeVisible();
});
