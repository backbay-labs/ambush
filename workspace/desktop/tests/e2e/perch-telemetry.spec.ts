import { expect, test, type Locator, type Page } from "@playwright/test";

import {
  emitPerchFrame,
  installPerchBridge,
  PERCH_ADMITTED_ISSUER,
  PERCH_UNADMITTED_ISSUER,
  waitForPerchTelemetrySubscription,
} from "../helpers/perchBridge";

/**
 * The telemetry REQ, end to end: the console opens it, a 26004 arrives on it,
 * and the governance strip says what the frame said.
 *
 * This is the path `evidence/window-walk.md` found-2 recorded as absent. The
 * subscription manager hard-coded `telemetryWanted: false` and its sink handled
 * `lane-movement` alone, so `applyPerchEphemeralFrame` had no caller anywhere in
 * `src`: on a real window the strip read `bridge: down` forever while an
 * authenticated subscriber on the same relay received the frames fine. Every
 * assertion here is about the whole path — the REQ is really open on the mock
 * socket, the frame really rides it, and the strip really re-reads the store —
 * because each half of it worked on its own before and the seam is what did not.
 *
 * The strip goes stale three seconds after the last frame
 * (`GOVERNANCE_STALE_AFTER_MS`), which is correct and is why the mode
 * assertions carry a shorter timeout than Playwright's default: a `healthy` that
 * takes longer than the frame's own lifetime to appear is not a pass.
 */

const HEALTHY_GOVERNANCE = {
  partition_state: "healthy",
  total_governors: 1,
  healthy_governors: 1,
};

/** Past this a `healthy` frame has aged into `stale` and proves nothing. */
const BEFORE_STALE_MS = 2_000;

function strip(page: Page): Locator {
  return page.getByTestId("perch-governance-strip");
}

function counter(page: Page, metric: string): Locator {
  return page.locator(`[data-perch-counter="${metric}"]`);
}

/**
 * Open the console on The Watch and wait for the telemetry REQ.
 *
 * The Watch renders no message timeline, which is the point: before this change
 * the REQ set was mounted only by a rendered swarm card surface, so this screen
 * — and the Watchfloor, and the strip on every route — opened nothing at all.
 */
async function openWatch(page: Page): Promise<void> {
  await installPerchBridge(page);
  await page.goto("/");
  await expect(strip(page)).toBeVisible();
  await waitForPerchTelemetrySubscription(page);
}

test("with no frame the strip says the bridge is down, never healthy", async ({
  page,
}) => {
  // Governance liveness is not restart-safe: an absent frame is the one thing
  // that must never read as an all-clear.
  await openWatch(page);
  await expect(strip(page)).toHaveAttribute(
    "data-governance-mode",
    "bridge-down",
  );
  // found-1: the line renders its own values, so `{lastSeen}` is filled — here
  // `never`, because no envelope has landed — never shipped as a raw template.
  await expect(strip(page)).toHaveText(
    "bridge: down (last envelope never) · holds may not be reaching the console",
  );
});

test("a 26004 from the admitted bridge reaches the strip", async ({ page }) => {
  await openWatch(page);
  await emitPerchFrame(page, {
    kind: 26004,
    pubkey: PERCH_ADMITTED_ISSUER,
    body: HEALTHY_GOVERNANCE,
  });
  await expect(strip(page)).toHaveAttribute("data-governance-mode", "healthy", {
    timeout: BEFORE_STALE_MS,
  });
  await expect(counter(page, "perch_frame_unadmitted_total")).toHaveAttribute(
    "data-perch-counter-value",
    "0",
  );
});

test("the same frame from a signer the console does not admit is counted and refused", async ({
  page,
}) => {
  // INV-15 on the ephemeral path. The bytes are identical to the test above;
  // the raw signer is the only difference, and it is the only thing consulted.
  await openWatch(page);
  await emitPerchFrame(page, {
    kind: 26004,
    pubkey: PERCH_UNADMITTED_ISSUER,
    body: HEALTHY_GOVERNANCE,
  });
  await expect(counter(page, "perch_frame_unadmitted_total")).toHaveAttribute(
    "data-perch-counter-value",
    "1",
  );
  await expect(strip(page)).toHaveAttribute(
    "data-governance-mode",
    "bridge-down",
  );
});

test("a frame nobody can decode is counted as undecodable, not read as healthy", async ({
  page,
}) => {
  // A 26004 stored with an empty body would paint the strip `healthy` off bytes
  // the console could not read — the worst available failure on this surface.
  await openWatch(page);
  await emitPerchFrame(page, {
    kind: 26004,
    pubkey: PERCH_ADMITTED_ISSUER,
    content: "{not json",
  });
  await expect(counter(page, "perch_frame_undecodable_total")).toHaveAttribute(
    "data-perch-counter-value",
    "1",
  );
  await expect(counter(page, "perch_frame_unadmitted_total")).toHaveAttribute(
    "data-perch-counter-value",
    "0",
    // Two different numbers: one is an accusation about a signer, the other
    // says only that the bridge sent bytes this console could not read.
  );
  await expect(strip(page)).toHaveAttribute(
    "data-governance-mode",
    "bridge-down",
  );
});
