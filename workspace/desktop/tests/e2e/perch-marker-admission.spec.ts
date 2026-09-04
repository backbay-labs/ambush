import { expect, test, type Locator, type Page } from "@playwright/test";

import {
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  malformedFindingCardBody,
  PERCH_ADMITTED_ISSUER,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_FINDING_HUMAN_LINE,
  PERCH_LANE_CHANNEL_NAME,
  PERCH_UNADMITTED_ISSUER,
  readPerchCounterAt,
  waveMessageBody,
} from "../helpers/perchBridge";

/**
 * INV-15, end to end: a card renders only when its RAW SIGNER
 * (`TimelineMessage.signerPubkey`) resolves to an admitted bridge identity.
 *
 * Four messages, one lane channel, identical card bytes in two of them. Every
 * assertion is scoped to its own `data-message-id`, because the whole point is
 * that four bodies which look alike to a content sniff take four different
 * paths through the seam.
 */

const CARD = findingCardBody();

async function openLane(page: Page) {
  await page.goto("/");
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(
    PERCH_LANE_CHANNEL_NAME,
  );
}

function row(page: Page, eventId: string): Locator {
  return page.locator(`[data-message-id="${eventId}"]`);
}

test.describe("perch marker admission", () => {
  test("admits on the raw signer and refuses every other shape", async ({
    page,
  }) => {
    await installPerchBridge(page);
    await openLane(page);
    expect(
      await readPerchCounterAt(page, "perch_marker_unadmitted_total"),
    ).toBe(0);

    // 1. The admitted bridge, the golden body, and a delegated-authorship
    //    claim naming somebody this console does NOT admit. Admission reads
    //    the signer, so the claim changes nothing.
    const admittedId = await emitPerchMessage(page, {
      channelName: PERCH_LANE_CHANNEL_NAME,
      content: CARD,
      pubkey: PERCH_ADMITTED_ISSUER,
      id: PERCH_FINDING_CARD_EVENT_ID,
      extraTags: [
        ["actor", PERCH_UNADMITTED_ISSUER],
        ["p", PERCH_UNADMITTED_ISSUER],
      ],
    });

    // 2. THE SAME BYTES from a signer the console does not admit, with the
    //    delegated-authorship tags reversed: the tags now name the admitted
    //    bridge. A renderer that trusted `pubkey` would render a card here.
    const unadmittedId = await emitPerchMessage(page, {
      channelName: PERCH_LANE_CHANNEL_NAME,
      content: CARD,
      pubkey: PERCH_UNADMITTED_ISSUER,
      extraTags: [
        ["actor", PERCH_ADMITTED_ISSUER],
        ["p", PERCH_ADMITTED_ISSUER],
      ],
    });

    // 3. The admitted bridge, a body whose fenced envelope is not a finding.
    const malformedId = await emitPerchMessage(page, {
      channelName: PERCH_LANE_CHANNEL_NAME,
      content: malformedFindingCardBody(),
      pubkey: PERCH_ADMITTED_ISSUER,
    });

    // 4. The chat app's own marker. Two namespaces, no collision.
    const waveId = await emitPerchMessage(page, {
      channelName: PERCH_LANE_CHANNEL_NAME,
      content: waveMessageBody(),
      pubkey: PERCH_ADMITTED_ISSUER,
    });

    // ---- 1: one card, and no prose copy of the same body ------------------
    const admitted = row(page, admittedId);
    await expect(admitted.getByTestId("perch-evidence-finding")).toHaveCount(1);
    await expect(admitted).not.toContainText(PERCH_FINDING_HUMAN_LINE);
    await expect(admitted.locator("pre")).toHaveCount(0);
    await expect(
      admitted.getByTestId("perch-unadmitted-marker-notice"),
    ).toHaveCount(0);

    // ---- 2: prose plus the notice, never a card ---------------------------
    const unadmitted = row(page, unadmittedId);
    await expect(unadmitted.getByTestId("perch-evidence-finding")).toHaveCount(
      0,
    );
    await expect(
      unadmitted.getByTestId("perch-unadmitted-marker-notice"),
    ).toHaveCount(1);
    await expect(unadmitted).toContainText(PERCH_FINDING_HUMAN_LINE);
    await expect(unadmitted.locator("pre")).toHaveCount(1);
    // A refusal card is a signal an adversary could plant at will, so the
    // unadmitted path renders no card of any kind.
    await expect(
      unadmitted.locator('[data-perch-role="evidence-card"]'),
    ).toHaveCount(0);

    // ---- 3: a refusal, with nothing to act on -----------------------------
    const malformed = row(page, malformedId);
    await expect(
      malformed.getByTestId("perch-evidence-undecodable"),
    ).toHaveCount(1);
    await expect(malformed.getByTestId("perch-evidence-finding")).toHaveCount(
      0,
    );
    await expect(
      malformed.locator('[data-testid^="perch-finding-action"]'),
    ).toHaveCount(0);

    // ---- 4: the inherited wave renderer -----------------------------------
    const wave = row(page, waveId);
    await expect(wave.getByTestId("message-wave-attachment")).toHaveCount(1);
    await expect(wave.locator('[data-perch-role="evidence-card"]')).toHaveCount(
      0,
    );

    // ---- the counter -------------------------------------------------------
    // Exactly one of the four is an unadmitted marker, and a re-render is not
    // a second marker: the counter is keyed by event id.
    await expect
      .poll(() => readPerchCounterAt(page, "perch_marker_unadmitted_total"))
      .toBe(1);
    await page.getByTestId("channel-general").click();
    await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
    await expect(
      row(page, unadmittedId).getByTestId("perch-unadmitted-marker-notice"),
    ).toHaveCount(1);
    expect(
      await readPerchCounterAt(page, "perch_marker_unadmitted_total"),
    ).toBe(1);
  });

  test("admitting nobody turns every card back into prose", async ({
    page,
  }) => {
    // The fixture seam, not a renderer hook: the daemon serves the admitted
    // set (D-FC-2), so "admit nobody" is a daemon answer.
    await installPerchBridge(page, { issuers: [] });
    await openLane(page);

    const eventId = await emitPerchMessage(page, {
      channelName: PERCH_LANE_CHANNEL_NAME,
      content: CARD,
      pubkey: PERCH_ADMITTED_ISSUER,
      id: PERCH_FINDING_CARD_EVENT_ID,
    });

    const only = row(page, eventId);
    await expect(
      only.getByTestId("perch-unadmitted-marker-notice"),
    ).toHaveCount(1);
    await expect(only.getByTestId("perch-evidence-finding")).toHaveCount(0);
    await expect(only).toContainText(PERCH_FINDING_HUMAN_LINE);
  });
});
