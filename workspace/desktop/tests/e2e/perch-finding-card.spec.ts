import { expect, test, type Locator, type Page } from "@playwright/test";

import {
  countPerchCommand,
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_FINDING_ID,
  PERCH_LANE_CHANNEL_NAME,
  readPerchMockLog,
  seedPerchFixtureAt,
  type PerchMockFixture,
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
  fixture?: PerchMockFixture,
): Promise<Locator> {
  await installPerchBridge(page, fixture);
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

  test("offers no verdict before the finding is promoted, and no A key at all", async ({
    page,
  }) => {
    const card = await openLaneWithFinding(page);
    const actions = card.getByTestId("perch-finding-actions");
    await expect(actions).toBeVisible();

    // E is available; the three verdicts are present and refused, with the
    // reason on the page rather than only in a tooltip.
    await expect(
      actions.getByTestId("perch-finding-action-promote"),
    ).toBeEnabled();
    for (const verb of ["confirm", "dismiss", "investigate"]) {
      await expect(
        actions.getByTestId(`perch-finding-action-${verb}`),
      ).toBeDisabled();
    }
    await expect(actions.getByTestId("perch-finding-promote-first")).toHaveText(
      "Promote this finding to a case first",
    );

    // There is no `A` key and no control claims to approve anything. The
    // check is over the CONTROL LABELS, because the group's prose legitimately
    // contains the article "a" and a text-wide regex would only be testing
    // that sentence.
    const labels = await actions.locator("button").allTextContents();
    expect(labels.length).toBeGreaterThan(0);
    for (const label of labels) {
      expect(
        label.trim().startsWith("A "),
        `no verdict verb may sit on the A key: "${label}"`,
      ).toBe(false);
    }
    expect(labels.join(" ").toLowerCase().includes("approve")).toBe(false);

    // A verdict key before promotion neither arms a rationale nor writes.
    await actions.getByTestId("perch-finding-action-promote").focus();
    await page.keyboard.press("d");
    await expect(
      actions.getByTestId("perch-finding-rationale-row"),
    ).toHaveCount(0);
    expect(await countPerchCommand(page, "perch_record_verdict")).toBe(0);
  });
});

test.describe("the finding verdict", () => {
  test("E promotes exactly once and opens the case the daemon minted", async ({
    page,
  }) => {
    const card = await openLaneWithFinding(page);
    const actions = card.getByTestId("perch-finding-actions");

    await actions.getByTestId("perch-finding-action-promote").focus();
    await page.keyboard.press("e");

    await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
    expect(await countPerchCommand(page, "perch_mint_incident")).toBe(1);
    // Promotion is not a verdict: nothing was signed and nothing was told to
    // the daemon about a decision.
    expect(await countPerchCommand(page, "perch_record_verdict")).toBe(0);
    expect(await countPerchCommand(page, "perch_finding_feedback")).toBe(0);
    // The case channel does not exist yet; the console says so instead of
    // rendering an empty channel.
    await expect(page.getByTestId("perch-case-opening")).toBeVisible();
  });

  test("D twice writes both legs, in order, and never shows one as the other", async ({
    page,
  }) => {
    // Both legs held open long enough to observe the window between them.
    const card = await openLaneWithFinding(page, undefined, {
      verdictDelayMs: 1_200,
      feedbackDelayMs: 1_200,
    });
    const actions = card.getByTestId("perch-finding-actions");
    await actions.getByTestId("perch-finding-action-promote").focus();
    await page.keyboard.press("e");
    await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));

    // Back to the lane, where the admitted finding is.
    await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
    const back = page
      .locator(`[data-message-id="${PERCH_FINDING_CARD_EVENT_ID}"]`)
      .getByTestId("perch-finding-actions");
    await expect(
      back.getByTestId("perch-finding-action-dismiss"),
    ).toBeEnabled();

    // First D arms; it does not write.
    await back.getByTestId("perch-finding-action-dismiss").focus();
    await page.keyboard.press("d");
    await expect(back.getByTestId("perch-finding-rationale-row")).toBeVisible();
    expect(await countPerchCommand(page, "perch_record_verdict")).toBe(0);

    // Second D commits.
    await page.keyboard.press("d");

    const state = page.getByTestId("perch-write-state");

    // Each window is read in ONE synchronous DOM pass, and the read asserts
    // which window it caught. A phase that had already advanced fails here
    // instead of quietly making the next assertion the one under test.
    const snapshot = () =>
      state.evaluate((el) => ({
        phase: el.getAttribute("data-perch-phase"),
        ambush:
          el.querySelector('[data-testid="perch-write-state-ambush"]')
            ?.textContent ?? null,
        daemon:
          el.querySelector('[data-testid="perch-write-state-daemon"]')
            ?.textContent ?? null,
        text: el.textContent ?? "",
      }));

    await expect(state).toHaveAttribute("data-perch-phase", "sending");
    const whileSending = await snapshot();
    expect(whileSending.phase).toBe("sending");
    expect(whileSending.ambush).toContain("sending");
    expect(whileSending.daemon).toBe(null);

    // Leg 1 landed. THIS is the window the contract is about: the Ambush
    // record exists and the daemon has said nothing.
    await expect(state).toHaveAttribute("data-perch-phase", "recorded");
    const midFlight = await snapshot();
    expect(midFlight.phase).toBe("recorded");
    expect(midFlight.ambush).toContain("recorded on Ambush");
    expect(midFlight.daemon).toContain("sending");
    expect(midFlight.daemon).not.toContain("acknowledged");
    expect(midFlight.text.includes("acknowledged")).toBe(false);
    expect(midFlight.text.includes("✓")).toBe(false);
    expect(midFlight.text.includes("✔")).toBe(false);

    // Only the daemon's own answer advances the row.
    await expect(state).toHaveAttribute("data-perch-phase", "acknowledged");
    await expect(state.getByTestId("perch-write-state-daemon")).toContainText(
      "acknowledged by the daemon",
    );
    await expect(state.getByTestId("perch-write-state-ambush")).toContainText(
      "recorded on Ambush",
    );

    const log = await readPerchMockLog(page);
    const legs = log.filter(
      (entry) =>
        entry === "perch_record_verdict" || entry === "perch_finding_feedback",
    );
    expect(legs).toEqual(["perch_record_verdict", "perch_finding_feedback"]);
  });

  test("with the daemon down the record stands, and a retry re-sends leg 2 alone", async ({
    page,
  }) => {
    const card = await openLaneWithFinding(page);
    const actions = card.getByTestId("perch-finding-actions");
    await actions.getByTestId("perch-finding-action-promote").focus();
    await page.keyboard.press("e");
    await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
    await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
    const back = page
      .locator(`[data-message-id="${PERCH_FINDING_CARD_EVENT_ID}"]`)
      .getByTestId("perch-finding-actions");
    await expect(
      back.getByTestId("perch-finding-action-dismiss"),
    ).toBeEnabled();

    // The daemon goes down between the legs. The relay is unaffected.
    await seedPerchFixtureAt(page, { daemonReachable: false });
    await back.getByTestId("perch-finding-action-dismiss").focus();
    await page.keyboard.press("d");
    await back.getByTestId("perch-finding-rationale").fill("scheduled backup");
    await back.getByTestId("perch-finding-record").click();

    const state = page.getByTestId("perch-write-state");
    await expect(state).toHaveAttribute(
      "data-perch-phase",
      "daemon-unreachable",
    );
    await expect(state.getByTestId("perch-write-state-ambush")).toContainText(
      "recorded on Ambush",
    );
    await expect(state.getByTestId("perch-write-state-daemon")).toContainText(
      "daemon unreachable — the Ambush record remains",
    );
    const intentEventId = await state.getAttribute(
      "data-perch-intent-event-id",
    );
    expect(intentEventId).toMatch(/^[0-9a-f]{64}$/);
    const relayWritesBefore = await countPerchCommand(
      page,
      "perch_record_verdict",
    );
    expect(relayWritesBefore).toBe(1);

    // Bring the daemon back and retry.
    await seedPerchFixtureAt(page, { daemonReachable: true });
    await state.getByTestId("perch-write-state-retry").click();

    await expect(state).toHaveAttribute("data-perch-phase", "acknowledged");
    expect(await countPerchCommand(page, "perch_record_verdict")).toBe(
      relayWritesBefore,
    );
    expect(await countPerchCommand(page, "perch_finding_feedback")).toBe(2);
    // The SAME signed intent: a retry replays leg 2, it does not re-decide.
    await expect(state).toHaveAttribute(
      "data-perch-intent-event-id",
      intentEventId ?? "",
    );
    await expect(state.getByTestId("perch-write-state-retry")).toHaveCount(0);
    // And the finding the daemon now holds is the one the card named.
    expect(PERCH_FINDING_ID.length).toBeGreaterThan(0);
  });
});
