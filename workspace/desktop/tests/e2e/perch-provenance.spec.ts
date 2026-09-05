import { expect, test, type Page } from "@playwright/test";
import goldenRollback from "../../src/features/perch/wire/golden/card-swarm-rollback-v1.json" with {
  type: "json",
};
import { buildCardContent } from "../../src/features/perch/wire/marker";
import {
  emitPerchMessage,
  findingCardBody,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_CASE_CHANNEL,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_LANE_CHANNEL_NAME,
} from "../helpers/perchBridge";

/**
 * B2g-p on the rollback card: a receipt with no governance attestation is
 * UNATTESTED, and the partition state at execution says whether that was by
 * design. `null` is a third answer, never healthy.
 */

type JsonObject = Record<string, unknown>;

function rollbackBody(
  partitionState: string | null,
  attested: boolean,
): string {
  const envelope = JSON.parse(JSON.stringify(goldenRollback)) as JsonObject;
  const fact = envelope.fact as JsonObject;
  fact.partition_state_at_execution = partitionState;
  const receipt = fact.rollback_receipt as JsonObject;
  if (attested) receipt.governance_attestation = { present: true };
  else delete receipt.governance_attestation;
  return buildCardContent(
    "rollback",
    "rollback rb-1 · lease cl-1 · manual · completed",
    JSON.stringify(envelope, null, 2),
  );
}

/** `E` on the lane's finding card mints the case and lands on its timeline. */
async function openCase(page: Page): Promise<string> {
  await installPerchBridge(page);
  await page.goto("/");
  await page.getByTestId(`channel-${PERCH_LANE_CHANNEL_NAME}`).click();
  await expect(page.getByTestId("chat-title")).toHaveText(
    PERCH_LANE_CHANNEL_NAME,
  );
  const eventId = await emitPerchMessage(page, {
    channelName: PERCH_LANE_CHANNEL_NAME,
    content: findingCardBody(),
    pubkey: PERCH_ADMITTED_ISSUER,
    id: PERCH_FINDING_CARD_EVENT_ID,
  });
  const card = page
    .locator(`[data-message-id="${eventId}"]`)
    .getByTestId("perch-evidence-finding");
  await expect(card).toBeVisible();
  await card
    .getByTestId("perch-finding-actions")
    .getByTestId("perch-finding-action-promote")
    .focus();
  await page.keyboard.press("e");
  await expect(page).toHaveURL(new RegExp(`/cases/${PERCH_CASE_CHANNEL}$`));
  // The timeline wrapper is `display: contents` (no box, so never "visible");
  // the case root is what has a box.
  await expect(page.getByTestId("perch-case")).toBeVisible();
  return `case-${PERCH_CASE_CHANNEL.slice(0, 8)}`;
}

const STATES: [string | null, string, string][] = [
  ["healthy", "perch-attestation-badge-rollback-healthy", "UNATTESTED"],
  ["degraded", "perch-attestation-badge-rollback-degraded", "UNATTESTED"],
  [
    "partitioned",
    "perch-attestation-badge-rollback-partitioned",
    "UNATTESTED — BY DESIGN",
  ],
  [
    "healing",
    "perch-attestation-badge-rollback-healing",
    "UNATTESTED — BY DESIGN",
  ],
  [
    null,
    "perch-attestation-badge-rollback-unknown",
    "UNATTESTED · the console could not establish the partition state",
  ],
];

// One card per test: the timeline is virtualized, and five tall cards in one
// case put the later ones below the fold where nothing is rendered to find.
for (const [state, testid, text] of STATES) {
  test(`a rollback receipt without an attestation, executed while ${state ?? "the partition state was unknown"}, reads "${text}"`, async ({
    page,
  }) => {
    const caseChannelName = await openCase(page);
    const eventId = await emitPerchMessage(page, {
      channelName: caseChannelName,
      content: rollbackBody(state, false),
      pubkey: PERCH_ADMITTED_ISSUER,
    });
    const card = page
      .locator(`[data-message-id="${eventId}"]`)
      .getByTestId("perch-evidence-rollback");
    await expect(card).toBeVisible();
    await expect(card.getByTestId(testid)).toHaveText(text);
  });
}

test("a receipt that carries an attestation is not called UNATTESTED, and is not called checked either", async ({
  page,
}) => {
  const caseChannelName = await openCase(page);
  const eventId = await emitPerchMessage(page, {
    channelName: caseChannelName,
    content: rollbackBody("healthy", true),
    pubkey: PERCH_ADMITTED_ISSUER,
  });
  const card = page
    .locator(`[data-message-id="${eventId}"]`)
    .getByTestId("perch-evidence-rollback");
  await expect(card).toBeVisible();
  await expect(
    card.getByTestId("perch-attestation-badge-rollback-present"),
  ).toContainText("not checked by this console");
  await expect(card).not.toContainText("UNATTESTED");
});
