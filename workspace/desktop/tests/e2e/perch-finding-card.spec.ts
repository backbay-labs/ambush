import { expect, test, type Locator, type Page } from "@playwright/test";

import {
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_LANE_CHANNEL_NAME,
} from "../helpers/perchBridge";

/**
 * The `swarm:finding:v1` card as an operator sees it: the facts it carries,
 * the rails around the two adversary-controlled strings, and the one
 * verification claim a tier-0 card is allowed to make.
 */

/** Right-to-left override and a zero-width space, planted in the host. */
const RLO = "‮";
const ZWSP = "​";
const ADVERSARY_HOST = `web-${RLO}04${ZWSP}`;

const TIER_0_BADGE =
  "secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record";

/** Copy this card may never render (D1, and the plan's Copy constraint). */
const BANNED_COPY = ["Perch", "Approve", "verified", "signed"];

async function openLaneWithFinding(
  page: Page,
  locator?: Record<string, unknown>,
): Promise<Locator> {
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(
    PERCH_LANE_CHANNEL_NAME,
  );
  const eventId = await emitPerchMessage(page, {
    channelName: PERCH_LANE_CHANNEL_NAME,
    content: findingCardBody(locator),
    pubkey: PERCH_ADMITTED_ISSUER,
    id: PERCH_FINDING_CARD_EVENT_ID,
  });
  const card = page
    .locator(`[data-message-id="${eventId}"]`)
    .getByTestId("perch-evidence-finding");
  await expect(card).toBeVisible();
  return card;
}

test.describe("the finding card", () => {
  test("renders the golden finding's human facts", async ({ page }) => {
    const card = await openLaneWithFinding(page);

    for (const fact of [
      "whisker-7a3f",
      "data_exfiltration",
      "HIGH",
      "confidence 0.82",
      "f2c9a1b4",
      "dns_exfil_beaconing",
      "tel-8831",
    ]) {
      await expect(card).toContainText(fact);
    }

    // The provenance footer names the event and the signer, so a reader can
    // go and find the record rather than trusting the card.
    await expect(card.getByTestId("perch-evidence-frame")).toContainText(
      PERCH_FINDING_CARD_EVENT_ID.slice(0, 8),
    );
    await expect(card).toHaveAttribute("data-testid", "perch-evidence-finding");
    await expect(card.locator('[data-perch-pillar="substrate"]')).toHaveCount(
      1,
    );
  });

  test("makes the one verification claim it is entitled to, and no other", async ({
    page,
  }) => {
    const card = await openLaneWithFinding(page);

    await expect(card.getByTestId("perch-tier-badge")).toHaveText(TIER_0_BADGE);

    // The badge is the ONE sanctioned use of the word "signed" on this card,
    // and it is a fixed literal: it names the chain that was checked and says
    // what was not. Remove it, and none of the banned words may remain.
    //
    // `textContent`, not `innerText`: the badge is styled `uppercase`, so
    // `innerText` returns what CSS drew rather than what the component wrote,
    // and the contract is the written literal.
    const rendered = ((await card.textContent()) ?? "")
      .replace(TIER_0_BADGE, "")
      .toLowerCase();
    for (const banned of BANNED_COPY) {
      expect(
        rendered.includes(banned.toLowerCase()),
        `the finding card must not render "${banned}" outside the tier badge`,
      ).toBe(false);
    }
    // No check mark: a tier-0 card has nothing to tick.
    expect(rendered.includes("✓")).toBe(false);
    expect(rendered.includes("✔")).toBe(false);
  });

  test("rails both adversary-controlled strings and names the codepoints", async ({
    page,
  }) => {
    const card = await openLaneWithFinding(page, { host_id: ADVERSARY_HOST });

    const host = card.locator(
      '[aria-label="host, adversary-controlled value"]',
    );
    const evidence = card.locator(
      '[aria-label="evidence, adversary-controlled value"]',
    );
    await expect(host).toHaveCount(1);
    await expect(evidence).toHaveCount(1);
    // The rail says so out loud once the value carries escaped code points.
    await expect(host).toContainText(
      "ADVERSARY-CONTROLLED · CONTAINS ESCAPED CHARACTERS",
    );

    const escaped = host.getByTestId("perch-escaped-codepoint");
    await expect(escaped).toHaveCount(2);
    await expect(escaped.nth(0)).toHaveAttribute(
      "title",
      "U+202E RIGHT-TO-LEFT OVERRIDE",
    );
    await expect(escaped.nth(1)).toHaveAttribute(
      "title",
      "U+200B ZERO WIDTH SPACE",
    );
    // The raw code points never reach the document text.
    const hostText = await host.innerText();
    expect(hostText.includes(RLO)).toBe(false);
    expect(hostText.includes(ZWSP)).toBe(false);
    expect(hostText).toContain("web-");

    // The evidence rail carries the finding's own evidence object verbatim.
    await expect(evidence).toContainText("entropy");
    await expect(evidence).toContainText("411");
  });

  test("offers nothing to act on until the verdict workflow lands", async ({
    page,
  }) => {
    const card = await openLaneWithFinding(page);
    await expect(
      card.locator('[data-testid^="perch-finding-action"]'),
    ).toHaveCount(0);
    // The expand control on a capped adversary string is the only button a
    // read-only card may own, and this card's values are under the cap.
    await expect(card.locator("button")).toHaveCount(0);
  });
});
